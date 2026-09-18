"""协调端 -> 第三方公证节点的 HTTP 客户端（仅用 urllib）。

语义：
- submit：以稳定事实编号幂等投递；正文必须是确定性编码字节（hex 传输）。
  * 同编号同正文 -> 200 + 原位置（idempotent=true/false 均可）；
  * 同编号异正文 -> 409 诊断冲突（NotaryConflict，由调用方落审计，不重投）；
  * 公证端失联/503 -> NotaryUnavailable（发送方待发箱保留，断点补齐）。
- 其余为公开取证读取（树头/包含路径/一致性路径/条目/公钥）。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

NOTARY_URL = os.environ.get("NOTARY_URL", "http://127.0.0.1:9105")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")


class NotaryUnavailable(Exception):
    """公证端失联/超时/5xx：待发箱保留待重试，绝不卡住主流程。"""


class NotaryConflict(Exception):
    """同一稳定事实编号携带不同正文：公证端诊断冲突（根不变）。"""
    def __init__(self, detail: dict):
        self.detail = detail
        super().__init__(detail.get("error", "fact conflict"))


class NotaryError(Exception):
    def __init__(self, status: int, body):
        self.status = status
        self.body = body
        super().__init__(f"notary HTTP {status}: {body}")


def _request(method: str, path: str, payload=None, token: str | None = None,
             timeout: float = 5.0):
    url = f"{NOTARY_URL.rstrip('/')}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
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
        raise NotaryError(e.code, body)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NotaryUnavailable(f"unreachable: {e}")


def submit(fact_id: str, fact_type: str, encoded_hex: str,
           timeout: float = 5.0) -> dict:
    """幂等投递一片事实。成功返回 {seq, tree_size, idempotent, tree_head,...}。"""
    try:
        _, body = _request("POST", "/notary/v1/submit", {
            "fact_id": fact_id, "fact_type": fact_type,
            "encoded": encoded_hex}, token=INTERNAL_TOKEN, timeout=timeout)
        return body
    except NotaryError as e:
        if e.status == 409:
            detail = e.body if isinstance(e.body, dict) else {"error": str(e.body)}
            raise NotaryConflict(detail)
        if e.status in (500, 502, 503, 504):
            raise NotaryUnavailable(f"http {e.status}: {e.body}")
        raise


def get_sth(timeout: float = 5.0) -> dict | None:
    try:
        s, body = _request("GET", "/notary/v1/get-sth", timeout=timeout)
    except NotaryError as e:
        if e.status == 404:
            return None
        raise
    return body if s == 200 else None


def proof_by_fact(fact_id: str, tree_size: int | None = None,
                  timeout: float = 5.0) -> dict | None:
    path = f"/notary/v1/get-proof-by-fact?fact_id={fact_id}"
    if tree_size:
        path += f"&tree_size={tree_size}"
    try:
        _, body = _request("GET", path, timeout=timeout)
    except NotaryError as e:
        if e.status == 404:
            return None
        raise
    return body


def consistency(first: int, second: int, timeout: float = 5.0) -> dict:
    _, body = _request(
        "GET", f"/notary/v1/get-consistency?first={first}&second={second}",
        timeout=timeout)
    return body


def entries(start: int, end: int, timeout: float = 10.0) -> list[dict]:
    _, body = _request(
        "GET", f"/notary/v1/get-entries?start={start}&end={end}",
        timeout=timeout)
    return body["entries"]


def entry_by_fact(fact_id: str, timeout: float = 5.0) -> dict | None:
    try:
        _, body = _request(
            "GET", f"/notary/v1/get-entry-by-fact?fact_id={fact_id}",
            timeout=timeout)
    except NotaryError as e:
        if e.status == 404:
            return None
        raise
    return body


def head_at(tree_size: int, timeout: float = 5.0) -> dict | None:
    try:
        _, body = _request(
            "GET", f"/notary/v1/head-at?tree_size={tree_size}", timeout=timeout)
    except NotaryError as e:
        if e.status == 404:
            return None
        raise
    return body


def keys(timeout: float = 5.0) -> dict:
    _, body = _request("GET", "/notary/v1/keys", timeout=timeout)
    return body


def rotations(timeout: float = 5.0) -> dict:
    _, body = _request("GET", "/notary/v1/rotations", timeout=timeout)
    return body


def rotate(overlap_seconds: int | None = None, timeout: float = 30.0) -> dict:
    _, body = _request("POST", "/admin/rotate-keys",
                       {"overlap_seconds": overlap_seconds},
                       token=ADMIN_TOKEN, timeout=timeout)
    return body
