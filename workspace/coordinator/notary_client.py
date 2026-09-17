"""协调端 -> 第三方公证节点的 HTTP 客户端（仅 urllib）。"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

NOTARY_URL = os.environ.get("NOTARY_URL", "http://127.0.0.1:9105")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
# 公证节点失联不阻塞主流程：调用方据此把事实留在待发箱稍后重投。


class NotaryError(Exception):
    def __init__(self, status: int, body: dict | str):
        self.status = status
        self.body = body
        super().__init__(f"notary HTTP {status}: {body}")


class FactConflict(NotaryError):
    """相同 fact_id 携带不同正文：稳定事实编号冲突，必须人工诊断，不可重写。"""


def _request(method: str, path: str, payload=None, timeout: float = 5.0):
    url = f"{NOTARY_URL.rstrip('/')}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw)
        except Exception:
            body = raw
        if e.code == 409 and isinstance(body, dict) \
                and body.get("code") == "fact_body_conflict":
            raise FactConflict(e.code, body)
        raise NotaryError(e.code, body)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NotaryError(0, f"unreachable: {e}")


def append(fact_id: str, kind: str, body: dict, timeout: float = 6.0) -> dict:
    """投递一片事实。公证端按 fact_id 幂等：
    - 首次：{index, idempotent:false, tree_size, tree_head}
    - 重放：{index（原位置）, idempotent:true, ...}，树规模不增长
    - 同号异文：抛 FactConflict（409）。
    """
    return _request("POST", "/notary/append",
                    {"fact_id": fact_id, "kind": kind, "body": body},
                    timeout=timeout)[1]


def tree_head(timeout: float = 5.0) -> dict:
    return _request("GET", "/notary/tree-head", timeout=timeout)[1]


def inclusion(fact_id: str, tree_size: int | None = None,
              timeout: float = 5.0) -> dict:
    q = f"?tree_size={tree_size}" if tree_size else ""
    return _request("GET", f"/notary/inclusion/{fact_id}{q}",
                    timeout=timeout)[1]


def consistency(first: int, second: int, timeout: float = 5.0) -> dict:
    return _request("GET",
                    f"/notary/consistency?first={first}&second={second}",
                    timeout=timeout)[1]


def rotate(note: str | None = None, overlap_seconds: int | None = None,
           timeout: float = 6.0) -> dict:
    """运营侧签名密钥换代（需公证端管理令牌）。换代声明在公证端入树。"""
    url = f"{NOTARY_URL.rstrip('/')}/notary/rotate"
    payload = json.dumps({"note": note,
                          "overlap_seconds": overlap_seconds}).encode()
    r = urllib.request.Request(url, data=payload, method="POST")
    r.add_header("Content-Type", "application/json")
    r.add_header("Authorization", f"Bearer {ADMIN_TOKEN}")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw)
        except Exception:
            body = raw
        raise NotaryError(e.code, body)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NotaryError(0, f"unreachable: {e}")
