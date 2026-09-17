"""第三方审计公证节点（notary）。

独立于协调端的透明日志（RFC 6962 风格 Merkle 账簿）+ 非对称签名树头：

- 协调端在产出三类事实——**签发凭据（credential）/ 全域阻断标记（block）/
  规则生效批次（rules）**——时，把确定性编码的事实追加到本节点的
  仅可追加（append-only）哈希树账簿；密钥换代声明（key_rotation）自身
  也作为一片叶子写入账簿。
- 公证节点为当前树头（tree_size + sha256 根 + 时间戳）用 Ed25519 私钥签名，
  审计方只凭公钥即可离线验签，无需接触本节点内部存储。
- 提供叶片包含路径（inclusion）与前缀一致性路径（consistency），
  让审计者确认"某项事实确已公开"以及"任意两个树头没有分叉"。

关键服务端不变量：
1. 追加幂等以 **fact_id** 为键：相同 fact_id 重放返回其原始固定位置，
   树规模不增长；相同 fact_id 携带不同规范正文返回 409 冲突诊断。
2. 账簿只追加：任何已写入的叶子/树头都不可改写或删除。
3. 签名密钥可换代：换代声明（含新旧公钥、交叠窗口、旧钥签名）先入树，
   此后新树头用新钥签名；旧树头与旧包含路径永久可由旧钥复验。
4. 交叠窗口内新旧公钥共同受信；窗口结束后新树头必须携带新密钥代号。

仅使用标准库（http.server / sqlite3 / 项目内 ed25519 + notary_tree）。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import ed25519
import notary_tree as nt
from common import canonical, iso, now_ms, sha256_hex

SERVICE_NAME = "notary"
PORT = int(os.environ.get("NOTARY_PORT", "9105"))
DB_PATH = os.environ.get("NOTARY_DB", "/data/notary.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
# 开发默认种子（与 docker-compose 一致）；生产由环境注入 32B hex。
DEFAULT_GENESIS_SEED = os.environ.get(
    "NOTARY_GENESIS_SEED",
    "notary-genesis-key-seed-000001"[:32].encode().hex())
# 换代交叠窗口默认秒数（窗口内新旧钥共同受信）。
DEFAULT_OVERLAP_SECONDS = int(os.environ.get("NOTARY_OVERLAP_SECONDS", "300"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS leaves(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,     -- 0 基叶子位置 = seq-1
  fact_id TEXT UNIQUE NOT NULL,
  kind TEXT NOT NULL,                        -- credential/block/rules/genesis/key_rotation/revocation
  body TEXT NOT NULL,                        -- 确定性规范事实 JSON（叶子即其哈希）
  body_hash TEXT NOT NULL,
  leaf_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS treeheads(
  tree_size INTEGER PRIMARY KEY,
  root TEXT NOT NULL,
  ts INTEGER NOT NULL,
  key_generation INTEGER NOT NULL,
  key_id TEXT NOT NULL,
  signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS keys(
  generation INTEGER PRIMARY KEY,
  key_id TEXT NOT NULL,
  seed TEXT NOT NULL,
  public_key TEXT NOT NULL,
  not_before INTEGER NOT NULL,              -- 该钥开始可签树头的时刻
  overlap_until INTEGER NOT NULL,           -- 与后继新钥共同受信的窗口结束
  rotated_at INTEGER,                       -- 实际换代（后继 not_before）时刻
  note TEXT
);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  detail TEXT
);
"""

_lock = threading.RLock()
os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript(SCHEMA)
_conn.commit()


def _fault() -> dict | None:
    r = db().execute("SELECT v FROM kv WHERE k='fault'").fetchone()
    if not r:
        return None
    try:
        return json.loads(r["v"])
    except Exception:
        return None


def _set_fault(mode: str | None, value: float = 0.0):
    with _lock:
        if mode:
            db().execute("INSERT INTO kv(k,v) VALUES('fault',?)"
                         " ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                         (json.dumps({"mode": mode, "value": value}),))
        else:
            db().execute("DELETE FROM kv WHERE k='fault'")
        db().commit()

# 内存叶子哈希序列（权威来源是 SQLite；启动时载入，追加时同步更新）。
_leaves: list[bytes] = []
_leaf_meta: dict[str, dict] = {}  # fact_id -> {seq/index,kind,body,leaf_hash}


def db():
    return _conn


def _event(etype: str, detail: dict):
    db().execute("INSERT INTO events(ts,type,detail) VALUES(?,?,?)",
                 (now_ms(), etype,
                  json.dumps(detail, ensure_ascii=False, sort_keys=True)))


def _reload():
    global _leaves, _leaf_meta
    rows = db().execute(
        "SELECT fact_id, kind, body, leaf_hash, seq FROM leaves ORDER BY seq"
    ).fetchall()
    _leaves = []
    _leaf_meta = {}
    for r in rows:
        lh = bytes.fromhex(r["leaf_hash"])
        idx = r["seq"] - 1
        _leaves.append(lh)
        _leaf_meta[r["fact_id"]] = {
            "index": idx, "kind": r["kind"], "body": json.loads(r["body"]),
            "leaf_hash": r["leaf_hash"]}


_reload()


def db():
    return _conn


# -- 密钥管理 -------------------------------------------------------------
def _get_key(gen: int) -> dict | None:
    r = db().execute("SELECT * FROM keys WHERE generation=?", (gen,)).fetchone()
    return dict(r) if r else None


def _latest_key() -> dict:
    r = db().execute("SELECT * FROM keys ORDER BY generation DESC LIMIT 1"
                     ).fetchone()
    return dict(r)


def _all_keys() -> list[dict]:
    rows = db().execute(
        "SELECT generation,key_id,public_key,not_before,overlap_until,"
        "rotated_at,note FROM keys ORDER BY generation").fetchall()
    return [dict(r) for r in rows]


def ensure_genesis():
    """植入创世密钥（generation 1）与创世叶子（幂等）。"""
    with _lock:
        if db().execute("SELECT COUNT(*) c FROM keys").fetchone()["c"]:
            return
        ts = now_ms()
        seed = bytes.fromhex(DEFAULT_GENESIS_SEED).ljust(32, b"0")[:32]
        if len(seed) != 32:
            seed = seed[:32].ljust(32, b"0")
        pub = ed25519.public_key(seed)
        key_id = "key-gen1-" + sha256_hex(pub)[:12]
        db().execute(
            "INSERT INTO keys(generation,key_id,seed,public_key,not_before,"
            " overlap_until,rotated_at,note) VALUES(1,?,?,?,0,0,NULL,?)",
            (key_id, seed.hex(), pub.hex(), "notary genesis signing key"))
        genesis = {
            "kind": "genesis",
            "genesis": True,
            "key_generation": 1,
            "key_id": key_id,
            "public_key": pub.hex(),
            "created_at": ts,
        }
        _append_leaf_locked("fact-notary-genesis", "genesis", genesis, ts)
        _event("NOTARY_GENESIS", {"key_id": key_id,
                                  "public_key": pub.hex()})
        db().commit()


def rotate_key(note: str | None, overlap_seconds: int | None) -> dict:
    """生成下一代签名密钥：换代声明先入树，再切换签名钥。

    返回换代声明（含旧钥对声明的签名，构成可离线验证的信任链）。
    """
    overlap_ms = int((overlap_seconds if overlap_seconds is not None
                      else DEFAULT_OVERLAP_SECONDS)) * 1000
    with _lock:
        cur = _latest_key()
        if cur.get("rotated_at"):
            raise Conflict("latest key already rotated; rotate the newest key",
                           generation=cur["generation"])
        ts = now_ms()
        new_seed = os.urandom(32)
        new_pub = ed25519.public_key(new_seed)
        new_gen = int(cur["generation"]) + 1
        new_id = f"key-gen{new_gen}-" + sha256_hex(new_pub)[:12]
        # 旧钥签名换代声明（授权新钥）：审计方据此验证信任链连续性。
        declaration = {
            "kind": "key_rotation",
            "old_key_generation": int(cur["generation"]),
            "old_key_id": cur["key_id"],
            "old_public_key": cur["public_key"],
            "new_key_generation": new_gen,
            "new_key_id": new_id,
            "new_public_key": new_pub.hex(),
            "not_before": ts,
            "overlap_until": ts + overlap_ms,
            "note": note or "",
            "declared_at": ts,
        }
        declaration["declaration_signature"] = ed25519.sign(
            bytes.fromhex(cur["seed"]), canonical(declaration)).hex()
        fact_id = f"fact-keyrotation-gen{new_gen}"
        meta = _append_leaf_locked(fact_id, "key_rotation", declaration, ts)
        # 登记新钥；旧钥标记 rotated_at（窗口内仍可验证旧头）。
        db().execute(
            "INSERT INTO keys(generation,key_id,seed,public_key,not_before,"
            " overlap_until,rotated_at,note) VALUES(?,?,?,?,?,?,NULL,?)",
            (new_gen, new_id, new_seed.hex(), new_pub.hex(), ts,
             ts + overlap_ms, note or ""))
        db().execute("UPDATE keys SET rotated_at=? WHERE generation=?",
                     (ts, cur["generation"]))
        _event("NOTARY_KEY_ROTATED", {
            "old_generation": cur["generation"], "new_generation": new_gen,
            "overlap_until": iso(ts + overlap_ms),
            "leaf_index": meta["index"]})
        db().commit()
        return {"fact_id": fact_id, **declaration, "leaf_index": meta["index"],
                "tree_size": len(_leaves)}


class Conflict(Exception):
    def __init__(self, error: str, **extra):
        self.error = error
        self.extra = extra
        super().__init__(error)


# -- 账簿追加 -------------------------------------------------------------
def _leaf_for(body: dict) -> bytes:
    return nt.leaf_hash(canonical(body))


def _append_leaf_locked(fact_id: str, kind: str, body: dict,
                        ts: int | None = None) -> dict:
    """调用方必须持有 _lock。返回叶子元信息。"""
    ts = ts or now_ms()
    body_bytes = canonical(body)
    lh = nt.leaf_hash(body_bytes)
    cur = db().execute("SELECT seq FROM leaves WHERE fact_id=?",
                       (fact_id,)).fetchone()
    if cur:
        idx = cur["seq"] - 1
        return _leaf_meta[fact_id]
    db().execute(
        "INSERT INTO leaves(fact_id,kind,body,body_hash,leaf_hash,created_at)"
        " VALUES(?,?,?,?,?,?)",
        (fact_id, kind, json.dumps(body, ensure_ascii=False, sort_keys=True),
         sha256_hex(body_bytes), lh.hex(), ts))
    idx = db().execute("SELECT seq FROM leaves WHERE fact_id=?",
                       (fact_id,)).fetchone()["seq"] - 1
    _leaves.append(lh)
    meta = {"index": idx, "kind": kind, "body": body, "leaf_hash": lh.hex()}
    _leaf_meta[fact_id] = meta
    return meta


def append_fact(fact_id: str, kind: str, body: dict) -> dict:
    """幂等追加。

    - 新 fact_id：写入新叶子，返回 index、tree_size、树头回执。
    - 相同 fact_id + 相同正文：返回原始位置（idempotent=true），树不增长。
    - 相同 fact_id + 不同正文：409 冲突诊断（existing_index/body_hash）。
    """
    with _lock:
        existing = db().execute(
            "SELECT body,body_hash,seq,kind FROM leaves WHERE fact_id=?",
            (fact_id,)).fetchone()
        new_canon = canonical(body)
        new_bhash = sha256_hex(new_canon)
        if existing:
            if existing["body_hash"] != new_bhash:
                raise Conflict(
                    f"fact_id {fact_id!r} already published with a different"
                    " body",
                    fact_id=fact_id, existing_index=existing["seq"] - 1,
                    existing_body_hash=existing["body_hash"],
                    submitted_body_hash=new_bhash,
                    code="fact_body_conflict")
            return {"fact_id": fact_id, "index": existing["seq"] - 1,
                    "idempotent": True, "kind": existing["kind"],
                    "tree_size": len(_leaves),
                    "leaf_hash": _leaf_meta[fact_id]["leaf_hash"],
                    "tree_head": current_head_signed()}
        meta = _append_leaf_locked(fact_id, kind, body)
        _event("NOTARY_FACT_APPENDED", {
            "fact_id": fact_id, "kind": kind, "index": meta["index"]})
        db().commit()
        return {"fact_id": fact_id, "index": meta["index"],
                "idempotent": False, "kind": kind,
                "tree_size": len(_leaves),
                "leaf_hash": meta["leaf_hash"],
                "tree_head": current_head_signed()}


# -- 树头签名 -------------------------------------------------------------
def _signing_key_for_ts(ts: int) -> dict:
    """选择在 ts 时刻合法的签名钥：not_before<=ts 的最新一代。"""
    rows = db().execute(
        "SELECT * FROM keys WHERE not_before<=? ORDER BY generation DESC",
        (ts,)).fetchall()
    if not rows:
        raise Conflict("no usable signing key")
    return dict(rows[0])


def current_head_signed(ts: int | None = None) -> dict:
    """构造并签名当前树头（按需签发；同 size 同规范内容在同毫秒下可复现）。

    签名钥选择规则（密钥换代交叠窗口）：
    - 换代声明的 not_before 起，新钥即成为"当前活跃钥"——窗口的意义是
      让审计者在窗口内仍可同时信任旧钥（验证尚未刷新到新树头的持有方）；
    - 因此 not_before <= ts 的最新一代对新树头签名；窗口结束后由于不存在
      比它更新的一代，新树头必然继续且只能使用该新密钥标识。
    """
    with _lock:
        ts = ts or now_ms()
        size = len(_leaves)
        root = nt.tree_root(_leaves)
        key = _signing_key_for_ts(ts)
        head = {"tree_size": size,
                "sha256_root_hash": root.hex(),
                "timestamp": ts,
                "key_generation": int(key["generation"]),
                "key_id": key["key_id"]}
        signed_input = canonical(head)
        head["signature"] = ed25519.sign(
            bytes.fromhex(key["seed"]), signed_input).hex()
        head["signed_input"] = json.loads(signed_input)
        # 活跃钥的受信窗口（供审计器独立核对换代时序；非签名负载的一部分）
        head["active_key"] = {
            "generation": int(key["generation"]),
            "key_id": key["key_id"],
            "public_key": key["public_key"],
            "not_before": key["not_before"],
            "overlap_until": key["overlap_until"]}
        return head


def inclusion_for(fact_id: str, tree_size: int | None = None) -> dict:
    with _lock:
        meta = _leaf_meta.get(fact_id)
        if not meta:
            raise Conflict("unknown fact_id", fact_id=fact_id,
                           code="unknown_fact")
        cur_size = len(_leaves)
        size = tree_size or cur_size
        if not (meta["index"] < size <= cur_size):
            raise Conflict(
                "tree_size out of range for this leaf",
                leaf_index=meta["index"], requested=size,
                current=cur_size, code="bad_tree_size")
        leaves_at = _leaves[:size]
        root = nt.tree_root(leaves_at)
        proof = nt.inclusion_proof(leaves_at, meta["index"])
        key = _signing_key_for_ts(now_ms())
        head = {"tree_size": size, "sha256_root_hash": root.hex(),
                "timestamp": now_ms(), "key_generation": int(key["generation"]),
                "key_id": key["key_id"]}
        head["signature"] = ed25519.sign(
            bytes.fromhex(key["seed"]), canonical(head)).hex()
        return {"fact_id": fact_id, "leaf_index": meta["index"],
                "leaf_hash": meta["leaf_hash"], "kind": meta["kind"],
                "body": meta["body"], "tree_size": size,
                "inclusion_path": proof, "tree_head": head}


def consistency_between(first: int, second: int) -> dict:
    with _lock:
        cur = len(_leaves)
        if not (0 < first <= second <= cur):
            raise Conflict("bad sizes", first=first, second=second,
                           current=cur, code="bad_tree_size")
        r1 = nt.tree_root(_leaves[:first])
        r2 = nt.tree_root(_leaves[:second])
        proof = nt.consistency_proof(first, second, _leaves)
        return {"first_tree_size": first, "second_tree_size": second,
                "first_root": r1.hex(), "second_root": r2.hex(),
                "consistency_path": proof}


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

    def _admin(self):
        return self.headers.get("Authorization", "") == f"Bearer {ADMIN_TOKEN}"

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path.rstrip("/") or "/"
        try:
            if p == "/health":
                return self._json(200, {"ok": True, "role": "notary",
                                        "tree_size": len(_leaves), "ts": iso()})
            if p == "/notary/tree-head":
                return self._json(200, current_head_signed())
            if p == "/notary/keys":
                return self._json(200, {"keys": _all_keys()})
            if p == "/notary/consistency":
                q = parse_qs(parsed.query)
                try:
                    first = int(q["first"][0]); second = int(q["second"][0])
                    return self._json(200, consistency_between(first, second))
                except (KeyError, ValueError):
                    return self._json(400, {"error": "first/second required"})
                except Conflict as c:
                    return self._json(400, {"error": c.error, **c.extra})
            if p.startswith("/notary/inclusion/"):
                # /notary/inclusion/<fact_id>?tree_size=
                fact_id = p.split("/", 3)[3]
                q = parse_qs(parsed.query)
                size = int(q["tree_size"][0]) if q.get("tree_size") else None
                try:
                    return self._json(200, inclusion_for(fact_id, size))
                except Conflict as c:
                    code = 404 if c.extra.get("code") == "unknown_fact" else 400
                    return self._json(code, {"error": c.error, **c.extra})
            return self._json(404, {"error": "not found", "path": p})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if p == "/notary/append":
                fault = _fault()
                if fault and fault.get("mode") == "offline":
                    # 模拟公证端整体失联：连接被直接重置（非业务响应）
                    import http.client
                    self.close_connection = True
                    self._json(503, {"error": "injected: notary offline"})
                    return
                body = self._body()
                if fault and fault.get("mode") == "slow":
                    time.sleep(float(fault.get("value", 1.0)))
                fact_id = body.get("fact_id")
                kind = body.get("kind")
                payload = body.get("body")
                if not fact_id or not kind or not isinstance(payload, dict):
                    return self._json(400, {"error":
                                            "fact_id, kind, body(object) required"})
                if kind not in ("credential", "block", "rules", "revocation"):
                    return self._json(400, {"error": f"unknown kind {kind!r}"})
                try:
                    return self._json(200, append_fact(fact_id, kind, payload))
                except Conflict as c:
                    if c.extra.get("code") == "fact_body_conflict":
                        return self._json(409, {"error": c.error, **c.extra})
                    return self._json(400, {"error": c.error, **c.extra})
            if p == "/notary/rotate":
                if not self._admin():
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                try:
                    out = rotate_key(body.get("note"),
                                     body.get("overlap_seconds"))
                    return self._json(200, out)
                except Conflict as c:
                    return self._json(409, {"error": c.error, **c.extra})
            if p == "/admin/fault":
                if not self._admin():
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                mode = body.get("mode") if body.get("on", True) else None
                _set_fault(mode, float(body.get("seconds", 0)))
                return self._json(200, {"ok": True, "fault": _fault()})
            return self._json(404, {"error": "not found", "path": p})
        except Exception as e:
            return self._json(500, {"error": repr(e)})


def main():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    ensure_genesis()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[notary] third-party audit notary listening on :{PORT}"
          f" db={DB_PATH} tree_size={len(_leaves)}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
