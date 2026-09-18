"""第三方审计公证节点（notary service）。

独立于协调端与业务服务的第三方角色：
- 维护一棵**仅可追加（append-only）**的哈希树账簿。发送方（协调端）每当
  产出签发凭据（certificate）、全域阻断标记（global tombstone）或规则生效
  批次（policy migration batch），就把确定性编码后的事实提交到这里。
- 为当前树头（STH, Signed Tree Head）签名，向审计方提供：
    * 叶片包含路径（inclusion proof）：某事实确已公开（在某树头中）；
    * 前缀一致性路径（consistency proof）：任意两个树头没有分叉，
      旧树头的叶子是新树头的严格前缀。
- 提交按**稳定事实编号（fact_id）**幂等：同一编号重放只返回原位置；
  同一编号携带不同正文 -> 409 诊断冲突，树头/根摘要不变。
- 支持**可追溯的签名密钥换代**：换代声明自身作为一片叶子入树；
  新旧公钥仅在配置的交叠窗口共同受信（树头双签）；窗口结束后新树头
  只带新密钥标识，旧树头与旧包含路径永久可凭旧公钥验证。

审计方（tests/notary_scenarios.py 的离线审计器）只需要 genesis 公钥，
通过公开（无需令牌）的 HTTP 取证端点即可完成全部验证，不接触任何内部存储。

仅使用 Python 标准库（RSA PKCS#1 v1.5 / SHA-256 由 common 实现）。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from common import (
    canonical,
    iso,
    now_ms,
    rsa_generate_keypair,
    rsa_public_key,
    rsa_sign,
    tree_inclusion_path,
    tree_leaf_hash,
    tree_mth,
    tree_consistency_path,
    tree_verify_consistency,
    tree_verify_inclusion,
)

SERVICE_NAME = "notary"
PORT = int(os.environ.get("NOTARY_PORT", "9105"))
DB_PATH = os.environ.get("NOTARY_DB", "/data/notary.db")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
# 密钥交叠窗口（毫秒）：窗口内树头由新旧密钥共同签名；窗口结束后只用新密钥。
OVERLAP_MS = int(os.environ.get("NOTARY_OVERLAP_SECONDS", "300")) * 1000
# 开发/测试可经环境变量使用更短的 RSA 模数（生产固定 2048）。
KEY_BITS = int(os.environ.get("NOTARY_KEY_BITS", "2048"))
GENESIS_KEY_ID = "notary-key-genesis"

SCHEMA = """
CREATE TABLE IF NOT EXISTS leaves(
  seq INTEGER PRIMARY KEY,          -- 0-based 入树顺序（只增不改不删）
  fact_id TEXT NOT NULL UNIQUE,     -- 发送侧稳定事实编号
  fact_type TEXT NOT NULL,
  encoded TEXT NOT NULL,            -- 确定性编码字节（hex），叶子唯一输入
  leaf_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS keys(
  key_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,              -- GENESIS/ACTIVE/RETIRED
  keypair TEXT NOT NULL,            -- 含私钥（仅公证进程；演示持久化）
  public_key TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rotations(
  seq INTEGER PRIMARY KEY,          -- 换代声明所在叶子序号
  old_key_id TEXT NOT NULL,
  new_key_id TEXT NOT NULL,
  overlap_end_ms INTEGER NOT NULL,
  body TEXT NOT NULL,               -- 入树的确定性换代声明正文
  old_signature TEXT,               -- 旧密钥对声明的签名（信任链引导）
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
-- 每追加一片叶子就固化一份签名树头（STH）：历史树头永久可取、永久可验。
-- 交叠窗口语义按"规模"执行：换代声明之后到窗口结束之间增长的规模双签；
-- 窗口结束后新规模只由新密钥签；旧规模沿用其固化时的签名（旧公钥永久有效）。
CREATE TABLE IF NOT EXISTS heads(
  tree_size INTEGER PRIMARY KEY,
  sha256_root_hash TEXT NOT NULL,
  ts INTEGER NOT NULL,
  signers TEXT NOT NULL,               -- JSON: [key_id,...]
  signed_bytes TEXT NOT NULL,
  signatures TEXT NOT NULL             -- JSON: {key_id: hex signature}
);
"""

_lock = threading.RLock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript(SCHEMA)
_conn.commit()


def db():
    return _conn


# -- 故障注入（仅演示/启动验证用；生产应在管理面鉴权后关闭） --------------
def get_fault(key: str) -> str | None:
    r = db().execute("SELECT v FROM kv WHERE k=?", (f"fault:{key}",)).fetchone()
    return r["v"] if r else None


def set_fault(key: str, value: str | None):
    with _lock:
        if value is None:
            db().execute("DELETE FROM kv WHERE k=?", (f"fault:{key}",))
        else:
            db().execute(
                "INSERT INTO kv(k,v) VALUES(?,?)"
                " ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (f"fault:{key}", value))
        db().commit()


def _fault_submit_blocked(fact_id: str) -> str | None:
    """返回非空字符串表示本次提交被故障注入阻断（返回该故障类型）。

    - submit_503：所有提交一律 503（公证端失联/断网）；
    - stall_first：首个提交（按 fact_id）阻塞到放行，制造"回执逆序"：
      被阻塞的低序号提交必须不被重复入树，且最终与并发提交各自只入树一次。
    """
    if get_fault("submit_503"):
        return "submit_503"
    stall = get_fault("stall_first")
    if stall and stall != "released":
        with _lock:
            r = db().execute(
                "SELECT v FROM kv WHERE k='stall:fid'").fetchone()
            if not r:
                db().execute("INSERT INTO kv(k,v) VALUES('stall:fid',?)",
                             (fact_id,))
                db().commit()
                blocked = True
            else:
                blocked = r["v"] == fact_id
        if blocked:
            return "stall_first"
    return None


# -- 叶子状态（缓存于进程；树只追加，重启后由表全量重建） ------------------
_hashes: list[str] = []
_index: dict[str, int] = {}


def _rebuild_cache():
    global _hashes, _index
    _hashes = [r["leaf_hash"] for r in db().execute(
        "SELECT leaf_hash FROM leaves ORDER BY seq").fetchall()]
    _index = {r["fact_id"]: r["seq"] for r in db().execute(
        "SELECT fact_id, seq FROM leaves").fetchall()}


_rebuild_cache()


def _signers_for_historical_size(size: int) -> tuple[list[str], int]:
    """某历史规模在其成立时刻应使用的签名者（用于崩溃后的树头自愈）。

    规则与 append 路径一致：
    - 无换代：genesis；
    - 换代声明叶子（size == rot.seq+1）及其后且处于交叠窗口：旧/新双签；
    - 交叠窗口结束之后：仅新密钥。
    时间戳取该规模最后一片叶子的入树时刻。
    """
    row = db().execute(
        "SELECT created_at FROM leaves WHERE seq=?", (size - 1,)).fetchone()
    ts = int(row["created_at"]) if row else now_ms()
    rot = _latest_rotation()
    if not rot:
        return [GENESIS_KEY_ID], ts
    decl_size = int(rot["seq"]) + 1
    if size < decl_size:
        return [rot["old_key_id"]], ts
    if ts < int(rot["overlap_end_ms"]):
        return [rot["old_key_id"], rot["new_key_id"]], ts
    return [rot["new_key_id"]], ts


def heal_heads():
    """启动自愈：为任何"有叶子但缺固化树头"的规模补签树头。

    正常路径下叶子与树头在同一事务内提交，此函数只防御异常退出/历史数据。
    """
    with _lock:
        n = len(_hashes)
        existing = {r["tree_size"] for r in db().execute(
            "SELECT tree_size FROM heads").fetchall()}
        missing = [s for s in range(1, n + 1) if s not in existing]
        if not missing:
            return
        for size in missing:
            signers, ts = _signers_for_historical_size(size)
            head = _build_head(size, tree_mth(_hashes[:size]), ts, signers)
            _insert_head(head)
        db().commit()
        print(f"[notary] self-healed {len(missing)} missing signed tree heads")


# -- 密钥管理 --------------------------------------------------------------
def ensure_genesis_key():
    """首启动生成 genesis 签名密钥（幂等）。"""
    with _lock:
        if db().execute("SELECT COUNT(*) c FROM keys").fetchone()["c"]:
            return
        kp = rsa_generate_keypair(KEY_BITS)
        ts = now_ms()
        db().execute(
            "INSERT INTO keys(key_id, state, keypair, public_key, created_at)"
            " VALUES(?, 'GENESIS', ?, ?, ?)",
            (GENESIS_KEY_ID, json.dumps(kp, sort_keys=True),
             json.dumps(rsa_public_key(kp), sort_keys=True), ts))
        db().commit()
        print(f"[notary] genesis key created id={GENESIS_KEY_ID} bits={KEY_BITS}")


def _key(key_id: str) -> dict | None:
    r = db().execute("SELECT * FROM keys WHERE key_id=?",
                     (key_id,)).fetchone()
    return dict(r) if r else None


def _latest_rotation() -> dict | None:
    r = db().execute(
        "SELECT * FROM rotations ORDER BY seq DESC LIMIT 1").fetchone()
    return dict(r) if r else None


def signing_schedule(ts: int | None = None) -> dict:
    """某时刻的"新树头"签名安排（只影响之后新固化的 STH）。

    返回 {"signers": [key_id,...], "rotation": <row|None>,
          "overlap": bool, "overlap_end_ms": int|None}
    - 从未换代：仅 genesis 单签；
    - 换代声明已入树且未到 overlap_end：旧/新双签（交叠窗口共同受信）；
    - 交叠窗口结束：只允许新密钥签新树头（旧树头历史仍永久可验）。
    """
    ts = now_ms() if ts is None else ts
    rot = _latest_rotation()
    if not rot:
        return {"signers": [GENESIS_KEY_ID], "rotation": None,
                "overlap": False, "overlap_end_ms": None}
    if ts < int(rot["overlap_end_ms"]):
        return {"signers": [rot["old_key_id"], rot["new_key_id"]],
                "rotation": rot, "overlap": True,
                "overlap_end_ms": int(rot["overlap_end_ms"])}
    return {"signers": [rot["new_key_id"]], "rotation": rot,
            "overlap": False, "overlap_end_ms": int(rot["overlap_end_ms"])}


def _build_head(tree_size: int, root: str, ts: int, signers: list[str]) -> dict:
    tbs = {
        "tree_size": tree_size,
        "sha256_root_hash": root,
        "timestamp": ts,
        "signer_key_ids": signers,
        "notary_key_id": signers[-1],  # 当前主签名密钥（窗口后即新密钥）
    }
    encoded = canonical(tbs)
    signatures = {}
    for kid in signers:
        row = _key(kid)
        signatures[kid] = rsa_sign(encoded, json.loads(row["keypair"]))
    return {
        "tree_size": tree_size,
        "sha256_root_hash": root,
        "timestamp": ts,
        "timestamp_iso": iso(ts),
        "signer_key_ids": signers,
        "notary_key_id": signers[-1],
        "signatures": signatures,
        "signed_bytes": encoded.decode(),
    }


def _insert_head(head: dict):
    """写入一份签名树头（不提交；由调用方与其叶子放在同一事务）。"""
    db().execute(
        "INSERT OR REPLACE INTO heads(tree_size, sha256_root_hash, ts,"
        " signers, signed_bytes, signatures) VALUES(?,?,?,?,?,?)",
        (head["tree_size"], head["sha256_root_hash"], head["timestamp"],
         json.dumps(head["signer_key_ids"]), head["signed_bytes"],
         json.dumps(head["signatures"], sort_keys=True)))


def _persist_head(head: dict):
    with _lock:
        _insert_head(head)
        db().commit()


def _head_view(tree_size: int) -> dict | None:
    r = db().execute("SELECT * FROM heads WHERE tree_size=?",
                     (tree_size,)).fetchone()
    if not r:
        return None
    head = {
        "tree_size": r["tree_size"],
        "sha256_root_hash": r["sha256_root_hash"],
        "timestamp": r["ts"],
        "timestamp_iso": iso(r["ts"]),
        "signer_key_ids": json.loads(r["signers"]),
        "signatures": json.loads(r["signatures"]),
        "signed_bytes": r["signed_bytes"],
    }
    head["notary_key_id"] = head["signer_key_ids"][-1]
    sched = signing_schedule()
    head["overlap"] = (sched["overlap"]
                       and tree_size > _rotation_decl_size())
    return head


def _rotation_decl_size() -> int:
    rot = _latest_rotation()
    return int(rot["seq"]) + 1 if rot else 0


def current_head() -> dict | None:
    with _lock:
        size = len(_hashes)
        if size == 0:
            return None
        return _head_view(size)


def head_at(tree_size: int) -> dict | None:
    """取某个历史规模固化的签名树头（永久可验）。"""
    with _lock:
        return _head_view(tree_size)


# -- 追加 -----------------------------------------------------------------
class FactConflict(Exception):
    """同一稳定事实编号携带不同正文：诊断性冲突（树头不变）。"""

    def __init__(self, detail: dict):
        self.detail = detail
        super().__init__(detail.get("error", "fact conflict"))


def append_fact(fact_id: str, fact_type: str, encoded: bytes,
                signers: list[str] | None = None) -> dict:
    """幂等追加一片事实叶子。

    - fact_id 已存在且正文一致：返回原位置（idempotent），树不增长；
    - fact_id 已存在但正文不同：抛 FactConflict，根摘要不变；
    - 否则按到达顺序分配 seq（稳定编号 -> 确定位置），返回新位置。
    signers 仅在追加换代声明叶子时由 rotate_keys 显式给定（交叠双签），
    此时 rotations 行尚未落库，常规时刻的签名安排无法识别新换代。
    """
    if not fact_id or not isinstance(fact_id, str):
        raise FactConflict({"error": "fact_id required"})
    if not isinstance(encoded, (bytes, bytearray)) or not encoded:
        raise FactConflict({"error": "encoded body required"})
    encoded_hex = bytes(encoded).hex()
    lh = tree_leaf_hash(bytes(encoded))
    with _lock:
        existing = db().execute(
            "SELECT * FROM leaves WHERE fact_id=?", (fact_id,)).fetchone()
        if existing:
            if existing["encoded"] == encoded_hex:
                return {"seq": existing["seq"], "fact_id": fact_id,
                        "leaf_hash": existing["leaf_hash"],
                        "tree_size": len(_hashes), "idempotent": True,
                        "conflict": False}
            raise FactConflict({
                "error": "fact_id conflict: same stable id carries a different"
                         " body; original position retained, tree unchanged",
                "fact_id": fact_id,
                "existing_seq": existing["seq"],
                "existing_leaf_hash": existing["leaf_hash"],
                "incoming_leaf_hash": lh,
                "tree_size": len(_hashes),
                "sha256_root_hash": tree_mth(_hashes),
            })
        ts = now_ms()
        cur = db().execute(
            "INSERT INTO leaves(seq, fact_id, fact_type, encoded, leaf_hash,"
            " created_at) VALUES((SELECT COALESCE(MAX(seq)+1,0) FROM leaves),"
            " ?,?,?,?,?)",
            (fact_id, fact_type, encoded_hex, lh, ts))
        seq = cur.lastrowid
        _hashes.append(lh)
        _index[fact_id] = seq
        # 叶子与该规模的签名树头在同一事务内固化：
        # 任何崩溃点之后重启，要么两者都在，要么都不在（树头永不缺口）。
        size = len(_hashes)
        head_signers = signers if signers is not None else \
            signing_schedule(ts)["signers"]
        head = _build_head(size, tree_mth(_hashes), ts, head_signers)
        _insert_head(head)
        db().commit()
        return {"seq": seq, "fact_id": fact_id, "leaf_hash": lh,
                "tree_size": size, "idempotent": False,
                "conflict": False,
                "tree_head": {"tree_size": head["tree_size"],
                              "sha256_root_hash": head["sha256_root_hash"],
                              "timestamp": head["timestamp"],
                              "signer_key_ids": head["signer_key_ids"]}}


# -- 取证（审计器只走公开只读端点） ---------------------------------------
def get_entry(seq: int) -> dict | None:
    r = db().execute("SELECT * FROM leaves WHERE seq=?", (seq,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["encoded_bytes"] = bytes.fromhex(d.pop("encoded")).decode()
    return d


def entries(a: int, b: int) -> list[dict]:
    rows = db().execute(
        "SELECT seq, fact_id, fact_type, encoded, leaf_hash, created_at"
        " FROM leaves WHERE seq>=? AND seq<? ORDER BY seq", (a, b)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["encoded_bytes"] = bytes.fromhex(d.pop("encoded")).decode()
        out.append(d)
    return out


def proof_for(fact_id: str, tree_size: int | None = None) -> dict | None:
    with _lock:
        if fact_id not in _index:
            return None
        seq = _index[fact_id]
        size = len(_hashes) if tree_size is None else int(tree_size)
        if size <= seq or size > len(_hashes):
            return None
        path = tree_inclusion_path(_hashes[:size], seq)
        return {
            "fact_id": fact_id, "leaf_index": seq, "tree_size": size,
            "leaf_hash": _hashes[seq],
            "inclusion_path": path,
            "sha256_root_hash": tree_mth(_hashes[:size]),
        }


def consistency_for(first: int, second: int) -> dict | None:
    with _lock:
        n = len(_hashes)
        if not 1 <= first <= second <= n:
            return None
        path = tree_consistency_path(_hashes[:second], first)
        return {
            "first": first, "second": second,
            "consistency_path": path,
            "first_root": tree_mth(_hashes[:first]),
            "second_root": tree_mth(_hashes[:second]),
        }


def all_public_keys() -> list[dict]:
    rows = db().execute(
        "SELECT key_id, state, public_key, created_at FROM keys"
        " ORDER BY rowid").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["public_key"] = json.loads(d["public_key"])
        out.append(d)
    return out


def rotations_list() -> list[dict]:
    rows = db().execute(
        "SELECT seq, old_key_id, new_key_id, overlap_end_ms, body,"
        " old_signature, created_at FROM rotations ORDER BY seq").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["body_obj"] = json.loads(d.pop("body"))
        out.append(d)
    return out


# -- 密钥换代（声明自身入树；窗口双签；窗口后新签） -----------------------
def rotate_keys(overlap_seconds: int | None = None) -> dict:
    with _lock:
        sched = signing_schedule()
        if sched["overlap"]:
            raise FactConflict({
                "error": "previous key rotation overlap window still open",
                "overlap_end_ms": sched["overlap_end_ms"]})
        old_id = sched["signers"][-1]
        old_row = _key(old_id)
        overlap_ms = (int(overlap_seconds) * 1000
                      if overlap_seconds is not None else OVERLAP_MS)
        ts = now_ms()
        new_kp = rsa_generate_keypair(KEY_BITS)
        n = len(_hashes) + 1  # 声明将成为第 n 个叶子（seq = n-1）
        new_id = f"notary-key-{n}"
        body = {
            "type": "NOTARY_KEY_ROTATION",
            "seq": n - 1,
            "old_key_id": old_id,
            "new_key_id": new_id,
            "new_public_key": rsa_public_key(new_kp),
            "overlap_end_ms": ts + overlap_ms,
            "declared_at": ts,
            "tree_size_at_declaration": n,
        }
        encoded = canonical(body)
        fact_id = f"notary:key-rotation:{n - 1}"
        # 旧密钥对声明正文签名：审计方凭旧信任锚即可验证新公钥的真实性。
        old_signature = rsa_sign(encoded, json.loads(old_row["keypair"]))
        # 先登记新密钥，再追加声明叶子：该叶子固化的 STH 立即处于交叠窗口，
        # 由旧/新双钥共同签名，信任链从声明树头连续。
        db().execute("INSERT INTO keys(key_id, state, keypair, public_key,"
                     " created_at) VALUES(?, 'ACTIVE', ?, ?, ?)",
                     (new_id, json.dumps(new_kp, sort_keys=True),
                      json.dumps(rsa_public_key(new_kp), sort_keys=True), ts))
        db().execute("UPDATE keys SET state='RETIRED' WHERE key_id=?",
                     (old_id,))
        res = append_fact(fact_id, "KEY_ROTATION", encoded,
                          signers=[old_id, new_id])
        db().execute(
            "INSERT INTO rotations(seq, old_key_id, new_key_id,"
            " overlap_end_ms, body, old_signature, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (res["seq"], old_id, new_id, ts + overlap_ms,
             json.dumps(body, ensure_ascii=False, sort_keys=True),
             old_signature, ts))
        db().commit()
        return {
            "fact_id": fact_id, "seq": res["seq"],
            "old_key_id": old_id, "new_key_id": new_id,
            "new_public_key": rsa_public_key(new_kp),
            "overlap_end_ms": ts + overlap_ms,
            "overlap_seconds": overlap_ms // 1000,
            "leaf_hash": res["leaf_hash"],
            "tree_size": len(_hashes),
            "old_signature": old_signature,
            "declaration": body,
            "tree_head": res["tree_head"],
        }


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = "Notary/1.0"

    def log_message(self, fmt, *args):
        print(f"[notary] {fmt % args}")

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n).decode()) if n else {}

    def _auth(self, expected):
        return self.headers.get("Authorization", "") == f"Bearer {expected}"

    # -- GET：全部为公开取证端点（审计器无需任何内部令牌） ----------------
    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path.rstrip("/") or "/"
        q = parse_qs(parsed.query)
        try:
            if p == "/health":
                return self._json(200, {"ok": True, "role": "notary",
                                        "ts": iso(),
                                        "tree_size": len(_hashes)})
            if p == "/notary/v1/get-sth":
                return self._json(200, current_head())
            if p == "/notary/v1/get-entries":
                start = int(q.get("start", ["0"])[0])
                end = int(q.get("end", [str(len(_hashes))])[0])  # exclusive
                if start < 0 or end < start:
                    return self._json(400, {"error": "bad range"})
                es = entries(start, end)
                return self._json(200, {"entries": es,
                                        "start": start, "end": start + len(es)})
            if p == "/notary/v1/get-entry-by-fact":
                fid = (q.get("fact_id") or [""])[0]
                if fid not in _index:
                    return self._json(404, {"error": "fact not found"})
                e = get_entry(_index[fid])
                return self._json(200, e)
            if p == "/notary/v1/get-proof-by-fact":
                fid = (q.get("fact_id") or [""])[0]
                tree_size = q.get("tree_size", [None])[0]
                tree_size = int(tree_size) if tree_size else None
                pr = proof_for(fid, tree_size)
                if pr is None:
                    return self._json(404, {"error": "proof unavailable",
                                            "fact_id": fid})
                return self._json(200, pr)
            if p == "/notary/v1/get-consistency":
                first = int(q.get("first", ["0"])[0])
                second = int(q.get("second", [str(len(_hashes))])[0])
                cp = consistency_for(first, second)
                if cp is None:
                    return self._json(400, {"error": "bad size range",
                                            "first": first, "second": second,
                                            "tree_size": len(_hashes)})
                return self._json(200, cp)
            if p == "/notary/v1/keys":
                return self._json(200, {"keys": all_public_keys(),
                                        "genesis_key_id": GENESIS_KEY_ID,
                                        "schedule": {
                                            "signers": signing_schedule()["signers"],
                                            "overlap":
                                                signing_schedule()["overlap"],
                                            "overlap_end_ms":
                                                signing_schedule()
                                                ["overlap_end_ms"]}})
            if p == "/notary/v1/rotations":
                return self._json(200, {"rotations": rotations_list()})
            if p == "/notary/v1/head-at":
                size = int(q.get("tree_size", ["0"])[0])
                h = head_at(size)
                if h is None:
                    return self._json(404, {"error": "no such tree size"})
                return self._json(200, h)
            if p == "/admin/fault":
                # 故障注入状态查看（管理面）
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {
                    "submit_503": get_fault("submit_503"),
                    "stall_first": get_fault("stall_first"),
                    "stall_fid": (db().execute(
                        "SELECT v FROM kv WHERE k='stall:fid'").fetchone()
                                  or {"v": None})["v"]})
            return self._json(404, {"error": "not found", "path": p})
        except ValueError:
            return self._json(400, {"error": "bad integer parameter"})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    # -- POST：提交（内部令牌）/ 换代与故障注入（管理令牌） ----------------
    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if p == "/notary/v1/submit":
                if not self._auth(INTERNAL_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                fid = body.get("fact_id")
                ftype = body.get("fact_type", "FACT")
                encoded = body.get("encoded")
                if encoded is None:
                    return self._json(400, {"error": "encoded required"})
                blocked = _fault_submit_blocked(fid)
                if blocked == "submit_503":
                    return self._json(503, {"error": "injected: notary outage"})
                if blocked == "stall_first":
                    return self._json(503, {"error": "injected: stall",
                                            "fact_id": fid})
                try:
                    raw = bytes.fromhex(encoded) if isinstance(encoded, str) \
                        and all(c in "0123456789abcdefABCDEF" for c in encoded) \
                        else encoded.encode()
                except Exception:
                    return self._json(400, {"error": "bad encoded body"})
                try:
                    res = append_fact(fid, ftype, raw)
                except FactConflict as c:
                    return self._json(409, c.detail)
                return self._json(200, res)
            if p == "/admin/rotate-keys":
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                try:
                    res = rotate_keys(body.get("overlap_seconds"))
                except FactConflict as c:
                    return self._json(409, c.detail)
                return self._json(200, res)
            if p == "/admin/fault":
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                mode = body.get("mode")
                on = bool(body.get("on"))
                if mode == "submit_503":
                    set_fault("submit_503", "1" if on else None)
                elif mode == "stall_first":
                    # on=true 开始捕获首个 fact_id；on=false 放行
                    if on:
                        set_fault("stall_first", "armed")
                        with _lock:
                            db().execute("DELETE FROM kv WHERE k='stall:fid'")
                            db().commit()
                    else:
                        set_fault("stall_first", "released" if on is False
                                  else None)
                else:
                    return self._json(400, {"error": "unknown fault mode"})
                return self._json(200, {"ok": True, "mode": mode, "on": on})
            return self._json(404, {"error": "not found", "path": p})
        except Exception as e:
            return self._json(500, {"error": repr(e)})


def main():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    ensure_genesis_key()
    heal_heads()
    httpd = _Server(("0.0.0.0", PORT), Handler)
    print(f"[notary] third-party audit notary listening on :{PORT}"
          f" db={DB_PATH} overlap={OVERLAP_MS // 1000}s")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
