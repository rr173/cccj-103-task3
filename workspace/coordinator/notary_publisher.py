"""第三方审计公证事实的编码与后台投递（落盘待发箱 -> 公证哈希树）。

事实类型（主流程在产出这些事实的同一本地事务内登记待发箱）：
- CERTIFICATE      签发凭据（证书某版本）
- GLOBAL_TOMBSTONE 全域阻断标记（全局墓碑）
- RULE_BATCH       规则生效批次（一次完成的策略迁移）

投递保证：
- 稳定事实编号：fact_id 由业务主键确定性派生，跨进程/跨重放不变。
- 落盘待发箱：主流程只负责本地落库，投递由后台线程异步完成，
  公证端失联/超时/503 不阻塞主流程，待发箱积压、连通后断点补齐。
- 幂等 exactly-once 入树：相同编号重投只返回原位置（公证端按 fact_id 去重）；
  相同编号不同正文 -> 公证端 409，本地置 CONFLICT 并给诊断，绝不重投。
- 回执逆序可收敛：投递可有多个工作线程并发，确认按 HTTP 返回顺序到达，
  待发箱按 fact_id 独立标记 SENT，顺序无关；每项最终恰好入树一次。
- 崩溃可续：SENT/PENDING 均已落盘；进程重启后只重投仍 PENDING 的行。
- 崩溃注入：crash_before_ack 武装后，指定 fact 在"公证端已入树、确认未落盘"
  的窗口内杀死进程，重启重放必须幂等收敛到同一位置（不产生第二片叶子）。
"""
from __future__ import annotations

import json
import os
import threading
import time

from . import notary_client
from .store import Store
from common import canonical, now_ms

DRAIN_INTERVAL_S = float(os.environ.get("NOTARY_DRAIN_INTERVAL_S", "0.3"))
DRAIN_WORKERS = int(os.environ.get("NOTARY_DRAIN_WORKERS", "4"))
SUBMIT_TIMEOUT_S = float(os.environ.get("NOTARY_SUBMIT_TIMEOUT_S", "4"))


# -- 确定性事实编号 --------------------------------------------------------
def cert_fact_id(rid: str, version: int) -> str:
    return f"cert:{rid}:v{version}"


def tombstone_fact_id(rid: str, version: int) -> str:
    return f"tomb:{rid}:v{version}"


def rule_batch_fact_id(migration_id: str) -> str:
    return f"rules:{migration_id}"


# -- 确定性事实正文（叶子唯一输入；审计方据此独立复算叶子哈希） ------------
def encode_certificate_fact(rid: str, cert: dict) -> bytes:
    """cert 为 certificates 表落库行（含 merkle_root/版本/计数/时间）。"""
    body = {
        "fact_type": "CERTIFICATE",
        "request_id": rid,
        "subject_id": cert["subject_id"],
        "version": cert["version"],
        "merkle_root": cert["merkle_root"],
        "item_count": cert["item_count"],
        "sealed_count": cert["sealed_count"],
        "issued_at": cert["issued_at"],
        "certificate_signature": cert["signature"],
    }
    return canonical(body)


def encode_tombstone_fact(rid: str, subject_id: str, version: int,
                          token: str, issued_at: int) -> bytes:
    body = {
        "fact_type": "GLOBAL_TOMBSTONE",
        "request_id": rid,
        "subject_id": subject_id,
        "version": version,
        "tombstone_token": token,
        "issued_at": issued_at,
    }
    return canonical(body)


def encode_rule_batch_fact(migration: dict, affected_requests: list[str],
                           item_results: list[dict]) -> bytes:
    body = {
        "fact_type": "RULE_BATCH",
        "migration_id": migration["id"],
        "revision": migration["revision"],
        "mode": migration["mode"],
        "state": migration["state"],
        "total": migration["total"],
        "done": migration["done"],
        "affected_requests": sorted(affected_requests),
        "items": sorted(item_results, key=lambda x: x["item_id"]),
        "completed_at": migration["updated_at"],
    }
    return canonical(body)


def decode_fact(encoded_hex: str) -> dict:
    return json.loads(bytes.fromhex(encoded_hex).decode())


class NotaryPublisher:
    """后台把落盘待发箱投递到公证节点（不阻塞、可崩溃恢复）。"""

    def __init__(self, store: Store):
        self.store = store
        self._stop = threading.Event()
        self._inflight: set[str] = set()
        self._inflight_lock = threading.Lock()
        # 崩溃注入（仅进程内存，重启不携带）：
        #   crash_before_ack: fact_id -> True 时，在该 fact 的公证端确认到达后、
        #   本地落 SENT 之前杀死进程；用于证明"确认前崩溃"重放恰好入树一次。
        self._crash_before_ack: set[str] = set()
        self.thread: threading.Thread | None = None

    def start(self):
        self.thread = threading.Thread(target=self._run,
                                       name="notary-drain", daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()

    def arm_crash_before_ack(self, fact_id: str | None):
        if fact_id:
            self._crash_before_ack.add(fact_id)
        else:
            self._crash_before_ack.clear()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.drain_once()
            except Exception as e:
                print(f"[notary-pub] drain error: {e!r}")
            time.sleep(DRAIN_INTERVAL_S)

    def drain_once(self):
        """投递一批 PENDING 行（有界并发）；每行独立成败，互不阻塞。"""
        with self.store.lock:
            pending = self.store.pending_facts(limit=DRAIN_WORKERS * 2)
        jobs = []
        with self._inflight_lock:
            for row in pending:
                if row["fact_id"] not in self._inflight:
                    self._inflight.add(row["fact_id"])
                    jobs.append(row)
                if len(jobs) >= DRAIN_WORKERS:
                    break
        if not jobs:
            return
        threads = []
        for row in jobs:
            t = threading.Thread(target=self._deliver, args=(row,),
                                 name=f"notary-send-{row['fact_id'][:24]}",
                                 daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=SUBMIT_TIMEOUT_S + 3)

    def _release(self, fact_id: str):
        with self._inflight_lock:
            self._inflight.discard(fact_id)

    def _deliver(self, row: dict):
        fid = row["fact_id"]
        try:
            self._deliver_inner(row)
        finally:
            self._release(fid)

    def _deliver_inner(self, row: dict):
        fid = row["fact_id"]
        try:
            res = notary_client.submit(
                fid, row["fact_type"], row["encoded"],
                timeout=SUBMIT_TIMEOUT_S)
        except notary_client.NotaryConflict as c:
            # 同编号异正文：诊断性冲突，落盘并停止重试（根摘要不变）
            with self.store.lock:
                self.store.mark_fact_conflict(fid, c.detail)
                self.store.event(row["ref_id"], "NOTARY_FACT_CONFLICT", {
                    "fact_id": fid, "detail": c.detail})
                self.store.commit()
            print(f"[notary-pub] FACT CONFLICT {fid}: {c.detail.get('error')}")
            return
        except notary_client.NotaryUnavailable as e:
            with self.store.lock:
                self.store.mark_fact_attempt(fid, str(e))
                self.store.commit()
            return
        except Exception as e:  # 任何意外都不得终止投递循环
            with self.store.lock:
                self.store.mark_fact_attempt(fid, repr(e))
                self.store.commit()
            return
        # 公证端已确认入树。崩溃注入点：确认已到达、SENT 未落盘之前。
        if fid in self._crash_before_ack:
            print(f"[notary-pub] crash-before-ack injected for {fid};"
                  f" notary has seq={res.get('seq')}; exiting", flush=True)
            os._exit(1)
        head = res.get("tree_head") or {}
        with self.store.lock:
            self.store.mark_fact_sent(
                fid, res.get("leaf_hash", ""), int(res["seq"]),
                int(res["tree_size"]), {
                    "tree_size": head.get("tree_size", res["tree_size"]),
                    "sha256_root_hash": head.get("sha256_root_hash"),
                    "timestamp": head.get("timestamp"),
                    "signer_key_ids": head.get("signer_key_ids"),
                })
            self.store.event(row["ref_id"], "NOTARY_FACT_PUBLISHED", {
                "fact_id": fid, "fact_type": row["fact_type"],
                "tree_seq": res["seq"], "tree_size": res["tree_size"],
                "idempotent": bool(res.get("idempotent"))})
            self.store.commit()
