"""纯标准库 Ed25519（RFC 8032）原语。

公证节点对树头做**非对称**签名：第三方审计器只持公钥即可离线验签，
这是"可追溯签名密钥换代"的前提（对称 HMAC 无法向第三方区分签署方）。

本实现仅依赖 hashlib（SHA-512）与整数运算，刻意不引入任何第三方依赖，
与项目"容器内零 pip install"的约束保持一致。生产环境可直接替换为
cryptography 库的 Ed25519，密钥/签名线格式（32B 公钥 / 64B 签名）完全相同。

线格式：
- 公钥：压缩椭圆曲线点，32 字节
- 种子（私钥）：32 字节随机种子
- 签名：R(32) || S(32)，64 字节
"""
from __future__ import annotations

import hashlib
import os

# 基域与群阶
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493

# 曲线常量（d = -121665/121666 mod q）
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _expmod(b: int, e: int, m: int) -> int:
    return pow(b, e, m)


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = _expmod(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q)


def _edwards(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    dxy = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + dxy)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - dxy)
    return x3 % _Q, y3 % _Q


def _scalarmult(P: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P: tuple[int, int]) -> bytes:
    x, y = P
    bits = y % (2 ** 255)
    if x & 1:
        bits |= 2 ** 255
    return bits.to_bytes(32, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    return int.from_bytes(_sha512(m), "little")


def _secret_scalar(seed: bytes) -> int:
    h = _sha512(seed)
    a = 2 ** 254
    for i in range(3, 254):
        if _bit(h, i):
            a += 2 ** i
    return a


def public_key(seed: bytes) -> bytes:
    """由 32 字节种子导出 32 字节压缩公钥。"""
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    A = _scalarmult(_B, _secret_scalar(seed))
    return _encodepoint(A)


def keygen(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """生成 (seed, public_key)；不给定种子则用 os.urandom。"""
    seed = seed or os.urandom(32)
    return seed, public_key(seed)


def sign(seed: bytes, msg: bytes) -> bytes:
    """对消息产出 64 字节确定性签名。"""
    h = _sha512(seed)
    a = 2 ** 254
    for i in range(3, 254):
        if _bit(h, i):
            a += 2 ** i
    A = _scalarmult(_B, a)
    r = _hint(h[32:] + msg) % _L
    R = _scalarmult(_B, r)
    S = (r + _hint(_encodepoint(R) + _encodepoint(A) + msg) * a) % _L
    return _encodepoint(R) + _encodeint(S)


def _decodepoint(s: bytes) -> tuple[int, int] | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (int.from_bytes(s, "little") >> 255):
        x = _Q - x
    P = (x, y)
    # 抵消 _xrecover 末尾的偶数偏好：选择与符号位一致的根
    if _encodepoint(P) != s:
        return None
    return P


def verify(public_key_bytes: bytes, msg: bytes, signature: bytes) -> bool:
    """验证 64 字节签名；任何格式/曲线/等式问题一律返回 False。"""
    try:
        if len(signature) != 64 or len(public_key_bytes) != 32:
            return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key_bytes)
        if R is None or A is None:
            return False
        S = int.from_bytes(signature[32:], "little")
        if S >= _L:
            return False
        rhs = _edwards(R, _scalarmult(
            A, _hint(signature[:32] + public_key_bytes + msg)))
        lhs = _scalarmult(_B, S)
        return lhs == rhs
    except Exception:
        return False
