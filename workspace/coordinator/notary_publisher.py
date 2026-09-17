"""协调端 -> 公证节点的事实发布器：稳定编号 + 落盘待发箱。

设计目标（见需求）：
- 主流程产出签发凭据 / 全域阻断标记 / 规则生效批次时，先在本地事务内把
  确定性编码事实写入待发箱，再异步投递；公证故障绝不阻塞主流程。
- **稳定事实编号**：同一事实的编号由其业务身份确定性派生；相同编号再次
  投递只能返回原位置（公证端幂等），相同编号携带不同正文被判为冲突。
- **落盘待发箱**：尚未拿到公证确认的事实留在 PENDING；确认带回固定叶子
  位置后标记 CONFIRMED。尚未入树的凭据对外只显示"等待公开"。
- **从断点补齐**：公证端失联、确认逆序（并发投递下先投的事实后确认）、
  或任一进程重启后，发布器都从待发箱断点重投，每项恰好入树一次。

为什么"恰好一次"成立：
1. 投递的幂等键是 fact_id；公证端以叶子位置（index）幂等去重，
   网络重试/进程重启重复投递只会拿回同一个 index，树不增长。
2. 协调端在 PENDING->CONFIRMED 前不对外宣称已公开；确认落库与读取在
   Store 的同一把串行锁内，并发投递只会有一次成功写入确认。
3. 确认逆序不影响正确性：每个 fact_id 的确认独立回填，未确认者继续 PENDING。
"""
from __future__ import annotations

import json
import os
import threading
import time

from common import canonical, now_ms, sha256_hex
from . import notary_client
from .notary_client import FactConflict, NotaryError

# 投递节奏（秒）。失联时后台线程按固定间隔重试待发箱，避免忙等；
# 主流程不被阻塞（事实停在 PENDING，对外显示"等待公开"）。
PUBLISH_INTERVAL_MS = float(os.environ.get(
    "NOTARY_PUBLISH_INTERVAL_MS", "200"))
# 单轮最多并发投递的待发事实数（用于制造/容忍"确认逆序"）。
MAX_INFLIGHT = int(os.environ.get("NOTARY_MAX_INFLIGHT", "4"))


class NotaryPublisher:
    def __init__(self, store):
        self.store = store
        self._stop = threading.Event()
        self.thread: threading.Thread | None = None
        # 崩溃注入：发送后、落确认前杀死进程（仅进程内存，重启不携带）。
        # 经 POST /admin/notary/crash-after 武装，参数为待确认 fact 下标。
        self._crash_after_pending = 0

    def set_crash_after(self, n: int):
        self._crash_after_pending = max(0, int(n))

    # -- 事实落盘（由主流程在业务事务内调用；绝不触网） ------------------
    def enqueue(self, fact_id: str, kind: str, body: dict,
                ref_type: str, ref_id: str) -> dict:
        """把事实写入待发箱（幂等）。已存在则返回既有行，不改写正文。"""
        body_bytes = canonical(body)
        with self.store.lock:
            existing = self.store.conn.execute(
                "SELECT fact_id,status FROM notary_outbox WHERE fact_id=?",
                (fact_id,)).fetchone()
            if existing:
                return {"fact_id": fact_id, "status": existing["status"],
                        "idempotent": True}
            ts = now_ms()
            self.store.conn.execute(
                "INSERT INTO notary_outbox(fact_id,kind,body,body_hash,"
                " ref_type,ref_id,status,attempts,created_at)"
                " VALUES(?,?,?,?,?,?, 'PENDING',0,?)",
                (fact_id, kind, json.dumps(body, ensure_ascii=False,
                                           sort_keys=True),
                 sha256_hex(body_bytes), ref_type, ref_id, ts))
            self.store.commit()
        return {"fact_id": fact_id, "status": "PENDING", "idempotent": False}

    def is_confirmed(self, fact_id: str) -> bool:
        with self.store.lock:
            r = self.store.conn.execute(
                "SELECT status FROM notary_outbox WHERE fact_id=?",
                (fact_id,)).fetchone()
        return bool(r and r["status"] == "CONFIRMED")

    # -- 生命周期 ----------------------------------------------------------
    def start(self):
        self.thread = threading.Thread(target=self._run,
                                       name="notary-publisher", daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.drain_once()
            except Exception as e:
                print(f"[notary-pub] drain error: {e!r}")
            time.sleep(PUBLISH_INTERVAL_MS / 1000.0)

    # -- 一轮投递 ----------------------------------------------------------
    def drain_once(self) -> dict:
        """把待发箱中所有 PENDING 事实推向公证端；返回本轮统计。"""
        with self.store.lock:
            rows = self.store.conn.execute(
                "SELECT fact_id,kind,body,attempts FROM notary_outbox"
                " WHERE status='PENDING' ORDER BY created_at, fact_id"
            ).fetchall()
        pending = [dict(r) for r in rows]
        if not pending:
            return {"sent": 0, "confirmed": 0, "conflict": 0, "unreachable": 0}

        # 到点才发（简单退避：next_attempt 存 attempts 推导；全部到期即发）
        batch = pending[:MAX_INFLIGHT]
        confirmed = conflict = unreachable = 0

        # 并发投递（确认可能逆序返回）。每项独立幂等，结果按 fact_id 回收。
        results: dict[str, dict] = {}
        errors: dict[str, Exception] = {}

        def deliver(row: dict):
            fid = row["fact_id"]
            body = json.loads(row["body"])
            try:
                results[fid] = notary_client.append(fid, row["kind"], body)
            except FactConflict as e:
                errors[fid] = e
            except NotaryError as e:
                errors[fid] = e

        threads = []
        for row in batch:
            t = threading.Thread(target=deliver, args=(row,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=8.0)

        for row in batch:
            fid = row["fact_id"]
            if fid in results:
                # 崩溃注入：在“已发出、确认未落盘”窗口杀死进程。
                # 仅在确实收到新投递确认时触发（不被无待发的空轮询消耗）；
                # 重启后待发箱仍为 PENDING，重投拿回同一 index（恰好一次）。
                if self._crash_after_pending:
                    self._crash_after_pending -= 1
                    print(f"[notary-pub] crash injection before ack of {fid};"
                          f" exiting", flush=True)
                    import os
                    os._exit(1)
                self._record_ack(fid, results[fid])
                confirmed += 1
                continue
            err = errors.get(fid)
            if isinstance(err, FactConflict):
                self._record_conflict(fid, err)
                conflict += 1
            else:
                self._record_retry(fid)
                unreachable += 1

        return {"sent": len(batch), "confirmed": confirmed,
                "conflict": conflict, "unreachable": unreachable,
                "remaining": len(pending) - len(batch)}

    def _record_ack(self, fact_id: str, ack: dict):
        with self.store.lock:
            self.store.conn.execute(
                "UPDATE notary_outbox SET status='CONFIRMED', leaf_index=?,"
                " tree_size=?, tree_head=?, confirmed_at=?,"
                " attempts=attempts+1 WHERE fact_id=?",
                (int(ack["index"]), int(ack["tree_size"]),
                 json.dumps(ack.get("tree_head"), ensure_ascii=False,
                            sort_keys=True),
                 now_ms(), fact_id))
            self.store.conn.execute(
                "INSERT INTO events(request_id,ts,type,detail) VALUES(?,?,?,?)",
                ("", now_ms(), "NOTARY_FACT_PUBLISHED", json.dumps({
                    "fact_id": fact_id, "leaf_index": ack["index"],
                    "tree_size": ack["tree_size"],
                    "idempotent": ack.get("idempotent", False)},
                    ensure_ascii=False, sort_keys=True)))
            self.store.commit()

    def _record_conflict(self, fact_id: str, err: FactConflict):
        with self.store.lock:
            self.store.conn.execute(
                "UPDATE notary_outbox SET status='CONFLICT', conflict=?,"
                " attempts=attempts+1 WHERE fact_id=?",
                (json.dumps(err.body, ensure_ascii=False), fact_id))
            self.store.conn.execute(
                "INSERT INTO events(request_id,ts,type,detail) VALUES(?,?,?,?)",
                ("", now_ms(), "NOTARY_FACT_CONFLICT", json.dumps({
                    "fact_id": fact_id, "detail": err.body},
                    ensure_ascii=False, sort_keys=True)))
            self.store.commit()

    def _record_retry(self, fact_id: str):
        with self.store.lock:
            self.store.conn.execute(
                "UPDATE notary_outbox SET attempts=attempts+1 WHERE fact_id=?",
                (fact_id,))
            self.store.commit()
