"""删除协调方案的共享原语：证据哈希、Merkle 根、HMAC 签名、时间、策略规则匹配。

设计原则：
- 只使用 Python 标准库，保证容器内无需任何第三方依赖即可通过启动验证。
- 生产环境可将 HMAC 对称签名替换为非对称签名（Ed25519），验证算法保持不变。
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import time
from typing import Any, Iterable

# 生产环境通过环境变量注入；此处给出与 docker-compose 一致的开发默认值。
SIGNING_SECRET = os.environ.get("DELETION_SIGNING_SECRET", "dev-deletion-secret").encode()
GLOBAL_TOMBSTONE_SECRET = os.environ.get(
    "GLOBAL_TOMBSTONE_SECRET", "dev-tombstone-secret"
).encode()


def now_ms() -> int:
    return int(time.time() * 1000)


def iso(ms: int | None = None) -> str:
    if ms is None:
        ms = now_ms()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))


def canonical(obj: Any) -> bytes:
    """确定性 JSON 序列化：键排序、无空白，保证签名/哈希可复现。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def sign(payload: dict) -> str:
    """对一段可 JSON 序列化的证据负载签名，返回 hex HMAC-SHA256。"""
    return hmac_hex(SIGNING_SECRET, canonical(payload))


def verify_signature(payload: dict, signature: str) -> bool:
    return hmac.compare_digest(sign(payload), signature or "")


def evidence_leaf(item: dict) -> str:
    """单个计划项的证据叶子。

    item 需含：service, subject_id, record_id, status, result_hash,
               hold_code(可空), command_id, updated_at, policy_revision(可空)
    叶子绑定策略修订号：状态迁移所属的合规策略版本由此成为证据的一部分，
    回滚策略不会改写历史证书中的叶子哈希。
    验证方只需这些字段即可独立复算叶子，不依赖协调端数据库。
    """
    leaf_body = {
        "service": item["service"],
        "subject_id": item["subject_id"],
        "record_id": item.get("record_id"),
        "status": item["status"],
        "result_hash": item.get("result_hash"),
        "hold_code": item.get("hold_code"),
        "command_id": item.get("command_id"),
        "updated_at": item["updated_at"],
        "policy_revision": item.get("policy_revision"),
    }
    return sha256_hex(canonical(leaf_body))


# -- 合规策略规则匹配（策略组件/协调端/验证方共享同一份语义） ----------------
POLICY_ACTIONS = {"SEAL", "RELEASE"}


def normalize_rule(rule: dict) -> dict:
    """校验并规范化一条策略规则；非法规则抛 ValueError。"""
    action = rule.get("action")
    if action not in POLICY_ACTIONS:
        raise ValueError(f"invalid rule action: {action!r}")
    service = rule.get("service")
    record_glob = rule.get("record_glob", "*")
    subject_glob = rule.get("subject_glob", "*")
    hold_code = rule.get("hold_code")
    if not service or not isinstance(service, str):
        raise ValueError("rule requires non-empty service")
    if not isinstance(record_glob, str) or not isinstance(subject_glob, str):
        raise ValueError("record_glob/subject_glob must be strings")
    if action == "SEAL" and not hold_code:
        raise ValueError("SEAL rule requires hold_code")
    return {
        "action": action,
        "service": service,
        "record_glob": record_glob or "*",
        "subject_glob": subject_glob or "*",
        "hold_code": hold_code,
        "hold_reason": rule.get("hold_reason", ""),
        "retention_seconds": int(rule.get("retention_seconds", 0)),
    }


def normalize_rules(rules: list[dict] | None) -> list[dict]:
    return [normalize_rule(r) for r in (rules or [])]


def rule_matches(rule: dict, *, service: str, subject_id: str,
                 record_id: str | None) -> bool:
    """fnmatch glob 匹配：service 精确（大小写敏感），record/subject 支持通配。"""
    if rule.get("service") != service:
        return False
    if not fnmatch.fnmatchcase(subject_id or "", rule.get("subject_glob", "*")):
        return False
    return fnmatch.fnmatchcase(record_id or "", rule.get("record_glob", "*"))


def matching_rule(rules: list[dict], action: str, *, service: str,
                  subject_id: str, record_id: str | None) -> dict | None:
    for rule in rules:
        if rule.get("action") == action and rule_matches(
                rule, service=service, subject_id=subject_id,
                record_id=record_id):
            return rule
    return None


def seal_rule_for(rules: list[dict], *, service: str, subject_id: str,
                  record_id: str | None) -> dict | None:
    return matching_rule(rules, "SEAL", service=service,
                         subject_id=subject_id, record_id=record_id)


def merkle_root(leaves: Iterable[str]) -> str:
    """标准成对 Merkle 根；奇数节点复制最后一个。"""
    level = list(leaves)
    if not level:
        return sha256_hex(b"")
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            sha256_hex(level[i].encode() + level[i + 1].encode())
            for i in range(0, len(level), 2)
        ]
    return level[0]


def tombstone_token(request_id: str, subject_id: str) -> str:
    """全局墓碑令牌：任何服务/副本凭此即可判断"该主体已被删除，禁止复活"。"""
    body = {"request_id": request_id, "subject_id": subject_id}
    return f"tomb:{hmac_hex(GLOBAL_TOMBSTONE_SECRET, canonical(body))}"


def verify_tombstone_token(request_id: str, subject_id: str, token: str) -> bool:
    return hmac.compare_digest(tombstone_token(request_id, subject_id), token or "")


# =========================================================================
# 第三方审计公证：仅可追加哈希树（append-only Merkle tree）原语
#
# 域分隔（domain separation）：
#   叶子域 0x00：tree_leaf(确定性编码后的事实正文)
#   内部域 0x01：tree_node(左孩子 || 右孩子)
# 不平衡树不在奇数层复制末端，而按"严格小于 n 的最大 2 的幂"左右切分
# （RFC 6962 MTH 风格）；包含路径与前缀一致性路径的生产/验证算法已在
# tests/verifier.py 的离线审计器中从零独立重写并穷举交叉验证。
# =========================================================================
def tree_leaf_hash(encoded: bytes) -> str:
    """事实正文 -> 树叶子哈希（hex）。encoded 必须是确定性编码字节。"""
    return sha256_hex(b"\x00" + encoded)


def tree_node_hash(left: str, right: str) -> str:
    return sha256_hex(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def tree_largest_pow2_below(n: int) -> int:
    """严格小于 n 的最大 2 的幂（n >= 2）。"""
    return 1 << ((n - 1).bit_length() - 1)


def tree_mth(hashes: list[str]) -> str:
    """RFC6962 风格的不平衡 Merkle 树根；空树 = sha256(b"")。"""
    n = len(hashes)
    if n == 0:
        return sha256_hex(b"")
    if n == 1:
        return hashes[0]
    k = tree_largest_pow2_below(n)
    return tree_node_hash(tree_mth(hashes[:k]), tree_mth(hashes[k:]))


def tree_inclusion_path(hashes: list[str], index: int,
                        a: int = 0, b: int | None = None) -> list[str]:
    """叶子 index（全局）在 hashes[a:b] 子树中的包含路径（兄弟节点序列）。"""
    if b is None:
        b = len(hashes)
    n = b - a
    if n <= 1:
        return []
    k = tree_largest_pow2_below(n)
    if index - a < k:
        path = tree_inclusion_path(hashes, index, a, a + k)
        path.append(tree_mth(hashes[a + k:b]))
        return path
    path = tree_inclusion_path(hashes, index, a + k, b)
    path.append(tree_mth(hashes[a:a + k]))
    return path


def tree_verify_inclusion(index: int, size: int, leaf_hash: str,
                          path: list[str], root: str) -> bool:
    """仅用叶子哈希/路径/根独立验证包含关系（消费顺序与路径长度严格校验）。"""
    if size <= 0 or not 0 <= index < size:
        return False
    pos = [0]

    def fold(i: int, sub: int):
        if sub == 1:
            return leaf_hash
        k = tree_largest_pow2_below(sub)
        if i < k:
            left = fold(i, k)
            sib = path[pos[0]]; pos[0] += 1
            return tree_node_hash(left, sib)
        right = fold(i - k, sub - k)
        sib = path[pos[0]]; pos[0] += 1
        return tree_node_hash(sib, right)

    try:
        computed = fold(index, size)
    except IndexError:
        return False
    return pos[0] == len(path) and computed == root


def tree_consistency_path(hashes: list[str], first: int) -> list[str]:
    """first（旧树规模，1..n）到当前规模 n 的前缀一致性路径。"""
    n = len(hashes)
    path: list[str] = []

    def rec(m: int, a: int, b: int, flag: bool):
        s = b - a
        if m == s:
            if flag:
                path.append(tree_mth(hashes[a:b]))
            return
        k = tree_largest_pow2_below(s)
        if m <= k:
            rec(m, a, a + k, True)
            path.append(tree_mth(hashes[a + k:b]))
        else:
            rec(m - k, a + k, b, False)
            path.append(tree_mth(hashes[a:a + k]))

    if first != n:
        rec(first, 0, n, False)
    return path


def tree_verify_consistency(first: int, size: int, old_root: str,
                            new_root: str, path: list[str]) -> bool:
    """独立验证新旧两根前缀一致：旧树恰是新树前 first 个叶子。"""
    if first <= 0 or size <= 0 or first > size:
        return False
    if first == size:
        return path == [] and old_root == new_root
    pos = [0]

    def take() -> str | None:
        if pos[0] >= len(path):
            return None
        v = path[pos[0]]; pos[0] += 1
        return v

    def rec(m: int, s: int):
        """返回 (旧子树根, 新子树根)；m 为旧前缀在本子树内的叶子数。"""
        if m == s:
            h = take()
            return (None, None) if h is None else (h, h)
        k = tree_largest_pow2_below(s)
        if m <= k:
            old_l, new_l = rec(m, k)
            right = take()
            if old_l is None or right is None:
                return None, None
            return old_l, tree_node_hash(new_l, right)
        old_r, new_r = rec(m - k, s - k)
        left = take()
        if old_r is None or left is None:
            return None, None
        return tree_node_hash(left, old_r), tree_node_hash(left, new_r)

    old, new = rec(first, size)
    return pos[0] == len(path) and old == old_root and new == new_root


# =========================================================================
# 非对称签名原语（RSA PKCS#1 v1.5 + SHA-256，仅标准库实现）
#
# 公证节点为树头/换代声明签名，审计方只持有公钥即可离线验签，
# 无需与任何内部存储或共享密钥接触。私钥只出现在公证进程内。
# 私钥 JSON 仅用于本地开发/演示持久化；生产应替换为 KMS/HSM。
# =========================================================================
def _i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _is_prime_miller_rabin(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    import secrets
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa_generate_keypair(bits: int = 2048) -> dict:
    """生成 RSA 密钥对；e 固定为 65537；返回可 JSON 序列化的密钥字典。"""
    import secrets
    half = bits // 2
    e = 65537
    while True:
        while True:
            p = secrets.randbits(half) | (1 << (half - 1)) | 1
            if _is_prime_miller_rabin(p):
                break
        while True:
            q = secrets.randbits(half) | (1 << (half - 1)) | 1
            if q != p and _is_prime_miller_rabin(q):
                break
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            continue
        return {
            "n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1),
            "qinv": pow(q, -1, p), "bits": bits,
        }


def rsa_public_key(keypair: dict) -> dict:
    return {"n": keypair["n"], "e": keypair["e"], "bits": keypair.get("bits", 2048)}


# PKCS#1 v1.5 EMSA-PKCS1-V1_5 对 SHA-256 的 DER 摘要信息前缀
_SHA256_DIGESTINFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420")


def _rsa_encrypt_exp(msg_int: int, pub: dict) -> int:
    return pow(msg_int, int(pub["e"]), int(pub["n"]))


def _rsa_decrypt_crt(sig_int: int, priv: dict) -> int:
    p, q = int(priv["p"]), int(priv["q"])
    m1 = pow(sig_int, int(priv["dp"]), p)
    m2 = pow(sig_int, int(priv["dq"]), q)
    h = (int(priv["qinv"]) * (m1 - m2)) % p
    return m2 + h * q


def rsa_sign(message: bytes, priv: dict) -> str:
    """对字节消息生成 PKCS#1 v1.5 / SHA-256 签名（hex）。"""
    k = (int(priv["n"]).bit_length() + 7) // 8
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGESTINFO_PREFIX + digest
    ps = b"\xff" * (k - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t
    sig_int = _rsa_decrypt_crt(_os2ip(em), priv)
    return _i2osp(sig_int, k).hex()


def rsa_verify(message: bytes, signature_hex: str, pub: dict) -> bool:
    """用公钥验证 PKCS#1 v1.5 / SHA-256 签名；任何畸形一律返回 False。"""
    try:
        k = (int(pub["n"]).bit_length() + 7) // 8
        sig = bytes.fromhex(signature_hex or "")
        if len(sig) != k:
            return False
        em_int = _rsa_encrypt_exp(_os2ip(sig), pub)
        em = _i2osp(em_int, k)
        digest = hashlib.sha256(message).digest()
        t = _SHA256_DIGESTINFO_PREFIX + digest
        ps = b"\xff" * (k - len(t) - 3)
        expected = b"\x00\x01" + ps + b"\x00" + t
        return hmac.compare_digest(em, expected)
    except Exception:
        return False


def policy_content_hash(rules: list[dict]) -> str:
    """修订内容指纹：同一 revision 的规则内容不可变（immutable revision）。

    规则集合与其书写顺序无关（按规范化字节排序后再哈希），
    同语义规则集合无论提交顺序如何都得到同一指纹。
    """
    norm = normalize_rules(rules)
    ordered = sorted(norm, key=canonical)
    return sha256_hex(canonical({"rules": ordered}))
