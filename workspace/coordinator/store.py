"""协调端 SQLite 存储。

单连接 + 进程锁：协调端本身是单实例编排器，所有写入在锁内串行，
消除"重复/乱序回报"造成的竞态。WAL 模式保证健康检查等读不阻塞写。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

from common import now_ms

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests(
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  display_name TEXT,
  status TEXT NOT NULL,              -- RESOLVING/IN_PROGRESS/CONFIRMED/ABORTED
  deadline_ms INTEGER NOT NULL,
  cert_version INTEGER NOT NULL DEFAULT 0,
  engine_paused INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS items(
  id TEXT PRIMARY KEY,              -- request_id:service[:record_id]
  request_id TEXT NOT NULL,
  service TEXT NOT NULL,
  subject_id TEXT,
  record_id TEXT,
  status TEXT NOT NULL,             -- 见 STATUS_RANK
  attempts INTEGER NOT NULL DEFAULT 0,
  command_id_restrict TEXT,
  command_id_purge TEXT,
  active_command_id TEXT,           -- 当前阶段期望的命令（幂等/陈旧判定）
  hold_code TEXT,
  hold_reason TEXT,
  hold_releases_at INTEGER,
  result_hash TEXT,
  evidence TEXT,                    -- 服务回报的完整证据 JSON
  overdue INTEGER NOT NULL DEFAULT 0,
  overdue_event INTEGER NOT NULL DEFAULT 0,
  fatal INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  purge_due_ms INTEGER NOT NULL DEFAULT 0,
  holds_checked_at INTEGER NOT NULL DEFAULT 0,
  report_seq INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  service TEXT NOT NULL,
  command_id TEXT,
  attempt INTEGER,
  reported_status TEXT,
  result_hash TEXT,
  hold_code TEXT,
  accepted INTEGER NOT NULL,        -- 0=被判定为重复/乱序/伪造而忽略
  reason TEXT,
  received_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS tombstones(
  request_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  service TEXT NOT NULL,            -- '*' 表示全局墓碑
  token TEXT NOT NULL,
  version INTEGER NOT NULL,
  pushed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(request_id, subject_id, service, version)
);
CREATE TABLE IF NOT EXISTS certificates(
  request_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  merkle_root TEXT NOT NULL,
  signature TEXT NOT NULL,
  leaves TEXT NOT NULL,
  item_count INTEGER NOT NULL,
  sealed_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(request_id, version)
);
-- 合规策略控制平面：每个工作流绑定一个不可变的策略修订快照（revision+rules）。
CREATE TABLE IF NOT EXISTS policy_bindings(
  request_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  content_hash TEXT,
  rules TEXT NOT NULL,                  -- 绑定时刻的规则快照，永不随策略变更改写
  canary INTEGER NOT NULL DEFAULT 0,
  bound_at INTEGER NOT NULL
);
-- 策略迁移（应用一个候选修订到既有工作流）：幂等、可恢复的迁移登记。
CREATE TABLE IF NOT EXISTS policy_migrations(
  id TEXT PRIMARY KEY,                  -- deterministic: rev:scope[:subjects]
  revision INTEGER NOT NULL,            -- 目标修订
  mode TEXT NOT NULL,                   -- canary / activate / rollback
  expected_version INTEGER,
  state TEXT NOT NULL,                  -- CONFLICT/IN_PROGRESS/COMPLETED
  total INTEGER NOT NULL DEFAULT 0,
  done INTEGER NOT NULL DEFAULT 0,
  last_item_id TEXT,                   -- 持久检查点：崩溃后从其后恢复
  detail TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_migration_items(
  migration_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  service TEXT NOT NULL,
  record_id TEXT,
  action TEXT NOT NULL,                 -- SEAL/RELEASE/REBIND/SKIP
  state TEXT NOT NULL DEFAULT 'PENDING', -- PENDING/DONE/SKIPPED/FAILED
  detail TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(migration_id, item_id)
);
CREATE TABLE IF NOT EXISTS policy_migration_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  migration_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  detail TEXT
);
-- 第三方审计公证的落盘待发箱（durable outbox）。
-- 主流程在同一本地事务内把"已发生的事实"写入待发箱即视为完成；
-- 后台投递线程以稳定事实编号幂等发往公证节点，公证故障绝不阻塞主流程。
-- PENDING -> SENT（已入树，附位置/树头）；CONFLICT（同编号异正文，诊断保留）。
CREATE TABLE IF NOT EXISTS notary_outbox(
  fact_id TEXT PRIMARY KEY,           -- 稳定事实编号（确定性、跨重放不变）
  fact_type TEXT NOT NULL,            -- CERTIFICATE/GLOBAL_TOMBSTONE/RULE_BATCH/...
  ref_id TEXT NOT NULL,               -- 关联对象（request_id / migration_id）
  encoded TEXT NOT NULL,              -- 确定性编码字节（hex）；叶子唯一输入
  leaf_hash TEXT,                     -- 公证端返回的叶子哈希
  tree_seq INTEGER,                   -- 入树位置（0-based）
  tree_size INTEGER,                  -- 入树后的树规模
  tree_head TEXT,                     -- 入树时树头摘要 JSON
  state TEXT NOT NULL DEFAULT 'PENDING', -- PENDING/SENT/CONFLICT
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notary_outbox_state
  ON notary_outbox(state);
-- 计划项当前绑定的修订号（不可变快照见 policy_bindings；项级版本用于乐观并发）。
"""

# 既有数据库的增量列迁移（镜像首次构建即含这些列）。
_COLUMN_MIGRATIONS = {
    "requests": [
        ("policy_revision", "INTEGER NOT NULL DEFAULT 1"),
    ],
    "items": [
        ("policy_revision", "INTEGER NOT NULL DEFAULT 1"),
        ("policy_version", "INTEGER NOT NULL DEFAULT 1"),  # 乐观并发版本
        ("hold_origin", "TEXT"),  # LOCAL（服务侧既存保留）/POLICY/EXTERNAL
    ],
}


def _migrate_columns(conn):
    for table, cols in _COLUMN_MIGRATIONS.items():
        have = {r["name"] for r in conn.execute(
            f"PRAGMA table_info({table})").fetchall()}
        for name, decl in cols:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

# 计划项状态序：只允许"同命令幂等重放"或"向前推进"，倒序回报一律拒绝。
STATUS_RANK = {
    "PENDING": 0,
    "DISPATCHED": 1,
    "ERROR": 1,        # 瞬态失败，与 DISPATCHED 同级，允许迟到成功回调把它推进
    "RESTRICTED": 2,
    "SEALED": 2,       # 受限变体：受法律/财务保留，只能封存
    "PURGING": 3,
    "PURGED": 4,       # 终态：已擦除
    "FAILED": 5,       # 终态：永久失败（saga 中止）
    "CANCELLED": 5,    # 终态：被补偿撤销
}
TERMINAL = {"PURGED", "FAILED", "CANCELLED"}
SEALED_LIKE = {"RESTRICTED", "SEALED"}


class Store:
    def __init__(self, path: str):
        first_init = not os.path.exists(path)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        _migrate_columns(self.conn)
        self.conn.commit()
        self.lock = threading.RLock()
        self._first_init = first_init

    # -- 基础辅助 ----------------------------------------------------------
    def tx(self):
        return self.conn  # 所有写操作在 self.lock 内进行，末尾显式 commit

    def commit(self):
        self.conn.commit()

    def event(self, request_id: str, etype: str, detail: Any = None):
        with self.lock:
            self.conn.execute(
                "INSERT INTO events(request_id, ts, type, detail) VALUES(?,?,?,?)",
                (request_id, int(time.time() * 1000), etype,
                 json.dumps(detail, ensure_ascii=False, sort_keys=True)),
            )
            self.conn.commit()

    # -- 读模型 ------------------------------------------------------------
    def get_request(self, rid: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        return dict(r) if r else None

    def list_items(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM items WHERE request_id=? ORDER BY service, record_id", (rid,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_item(self, iid: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
        return dict(r) if r else None

    def list_reports(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM reports WHERE request_id=? ORDER BY id", (rid,)
        ).fetchall()
        return [dict(r) for r in rows]

    def list_events(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, type, detail FROM events WHERE request_id=? ORDER BY id", (rid,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
            out.append(d)
        return out

    def list_certificates(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM certificates WHERE request_id=? ORDER BY version", (rid,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["leaves"] = json.loads(d["leaves"])
            out.append(d)
        return out

    def list_tombstones(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT request_id, subject_id, service, token, version, pushed, created_at "
            "FROM tombstones WHERE request_id=? ORDER BY version, service", (rid,)
        ).fetchall()
        return [dict(r) for r in rows]

    def active_requests(self) -> list[dict]:
        # 注意必须包含 RESOLVING：身份解析常在单个 tick 内完成，
        # 若漏选 RESOLVING，请求会永久停滞在解析态。
        rows = self.conn.execute(
            "SELECT * FROM requests WHERE status IN ('RESOLVING','IN_PROGRESS','CONFIRMED')"
        ).fetchall()
        return [dict(r) for r in rows]

    def request_view(self, rid: str) -> dict | None:
        req = self.get_request(rid)
        if not req:
            return None
        req["items"] = self.list_items(rid)
        req["events"] = self.list_events(rid)
        req["reports"] = self.list_reports(rid)
        req["certificates"] = self.list_certificates(rid)
        return req

    # -- 合规策略：绑定 / 迁移登记 / 检查点 --------------------------------
    def get_binding(self, rid: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM policy_bindings WHERE request_id=?",
                              (rid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["rules"] = json.loads(d["rules"])
        return d

    def put_binding(self, rid: str, subject_id: str, revision: int,
                    rules: list[dict], content_hash: str | None, canary: bool):
        ts = now_ms()
        self.conn.execute(
            "INSERT INTO policy_bindings(request_id, subject_id, revision,"
            " content_hash, rules, canary, bound_at) VALUES(?,?,?,?,?,?,?)"
            " ON CONFLICT(request_id) DO UPDATE SET revision=excluded.revision,"
            " content_hash=excluded.content_hash, rules=excluded.rules,"
            " canary=excluded.canary, bound_at=excluded.bound_at",
            (rid, subject_id, revision, content_hash,
             json.dumps(rules, ensure_ascii=False, sort_keys=True),
             1 if canary else 0, ts))

    def get_migration(self, mid: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM policy_migrations WHERE id=?",
                              (mid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["detail"] = json.loads(d["detail"]) if d["detail"] else None
        return d

    def list_migration_items(self, mid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM policy_migration_items WHERE migration_id=?"
            " ORDER BY rowid", (mid,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"]) if d["detail"] else None
            out.append(d)
        return out

    def migration_view(self, mid: str) -> dict | None:
        m = self.get_migration(mid)
        if not m:
            return None
        m["items"] = self.list_migration_items(mid)
        rows = self.conn.execute(
            "SELECT id, ts, type, detail FROM policy_migration_events"
            " WHERE migration_id=? ORDER BY id", (mid,)).fetchall()
        ev = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
            ev.append(d)
        m["events"] = ev
        return m

    def migration_event(self, mid: str, etype: str, detail: Any = None):
        self.conn.execute(
            "INSERT INTO policy_migration_events(migration_id, ts, type, detail)"
            " VALUES(?,?,?,?)",
            (mid, now_ms(), etype,
             json.dumps(detail, ensure_ascii=False, sort_keys=True)))

    def list_migration_events_all(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, migration_id, ts, type, detail FROM policy_migration_events"
            " ORDER BY id").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
            out.append(d)
        return out

    # -- 第三方审计公证：落盘待发箱 ----------------------------------------
    def enqueue_fact(self, fact_id: str, fact_type: str, ref_id: str,
                     encoded_hex: str):
        """登记一条待公开事实（调用方须已在写事务/锁内，末尾统一提交）。

        幂等：同 fact_id 已存在则保留原行（不覆盖正文、不改状态）。
        """
        ts = now_ms()
        self.conn.execute(
            "INSERT INTO notary_outbox(fact_id, fact_type, ref_id, encoded,"
            " state, created_at, updated_at) VALUES(?,?,?,?, 'PENDING', ?, ?)"
            " ON CONFLICT(fact_id) DO NOTHING",
            (fact_id, fact_type, ref_id, encoded_hex, ts, ts))

    def fact_state(self, fact_id: str) -> dict | None:
        r = self.conn.execute(
            "SELECT * FROM notary_outbox WHERE fact_id=?",
            (fact_id,)).fetchone()
        return dict(r) if r else None

    def list_outbox(self, state: str | None = None,
                    ref_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM notary_outbox WHERE 1=1"
        args: list = []
        if state:
            sql += " AND state=?"; args.append(state)
        if ref_id:
            sql += " AND ref_id=?"; args.append(ref_id)
        sql += " ORDER BY rowid"
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def pending_facts(self, limit: int = 16) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM notary_outbox WHERE state='PENDING'"
            " ORDER BY rowid LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def mark_fact_sent(self, fact_id: str, leaf_hash: str, seq: int,
                       tree_size: int, tree_head: dict):
        ts = now_ms()
        self.conn.execute(
            "UPDATE notary_outbox SET state='SENT', leaf_hash=?, tree_seq=?,"
            " tree_size=?, tree_head=?, last_error=NULL, updated_at=?"
            " WHERE fact_id=?",
            (leaf_hash, seq, tree_size,
             json.dumps(tree_head, ensure_ascii=False, sort_keys=True),
             ts, fact_id))

    def mark_fact_attempt(self, fact_id: str, error: str):
        self.conn.execute(
            "UPDATE notary_outbox SET attempts=attempts+1, last_error=?,"
            " updated_at=? WHERE fact_id=?",
            (error, now_ms(), fact_id))

    def mark_fact_conflict(self, fact_id: str, detail: dict):
        self.conn.execute(
            "UPDATE notary_outbox SET state='CONFLICT', last_error=?,"
            " updated_at=? WHERE fact_id=?",
            (json.dumps(detail, ensure_ascii=False, sort_keys=True),
             now_ms(), fact_id))

    def count_outbox(self, state: str | None = None) -> int:
        if state:
            return self.conn.execute(
                "SELECT COUNT(*) c FROM notary_outbox WHERE state=?",
                (state,)).fetchone()["c"]
        return self.conn.execute(
            "SELECT COUNT(*) c FROM notary_outbox").fetchone()["c"]
