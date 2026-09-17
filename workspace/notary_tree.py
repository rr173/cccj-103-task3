"""仅可追加哈希树账簿（RFC 6962 Merkle 透明日志）原语。

叶子/内部节点域分离（防第二原像）：
    leaf_hash  = SHA256(0x00 || canonical_fact)
    inner_hash = SHA256(0x01 || left || right)

树形态严格遵循 RFC 6962 §2.1：**不平衡二叉树**，奇数节点不自我复制，
而是以一棵较矮的子树直接挂到父节点。对 n 个输入，令 k 为严格小于 n
的最大 2 次幂，则

    MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))

空树根 MTH({}) = SHA256("")。

包含路径（inclusion / audit path, RFC §2.1.1）：重建某叶子到根所需的
兄弟节点序列，每项 {"side":"L"|"R","hash":hex}：
  side="L" 兄弟在左：node = H(0x01 || sibling || node)
  side="R" 兄弟在右：node = H(0x01 || node || sibling)

一致性路径（consistency, RFC §2.1.2）：证明旧树（m 叶）是新树（n 叶，
m<=n）的前缀——任意两个树头没有分叉。

所有函数都是确定性纯函数：同一叶子序列在任何进程都复算出相同根/路径；
离线审计器不接触公证节点内部存储即可独立验证。验证侧重放与生成侧相同
的递归切分（只依赖 index/tree_size，不依赖任何服务端状态），因此路径
的 side 仅为信息性标注，即便被篡改也无法让错误事实通过根比对。
"""
from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(canonical_fact: bytes) -> bytes:
    return sha256(LEAF_PREFIX + canonical_fact)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right)


def split_k(n: int) -> int:
    """RFC：严格小于 n 的最大 2 次幂（n>=2）。"""
    return 1 << ((n - 1).bit_length() - 1)


def tree_root(leaves: list[bytes]) -> bytes:
    """RFC MTH：不平衡二叉树根。空树 -> SHA256(b"")。"""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = split_k(n)
    return node_hash(tree_root(leaves[:k]), tree_root(leaves[k:]))


# 向后兼容别名（模块内历史命名）
_mth = tree_root


def inclusion_proof(leaves: list[bytes], index: int) -> list[dict]:
    """RFC §2.1.1 PATH(index, D[n])：叶子到根的兄弟序列（含 side 标注）。"""
    n = len(leaves)
    if not (0 <= index < n):
        raise IndexError(f"leaf index {index} out of range 0..{n - 1}")

    def build(m: int, lo: int, size: int) -> list[bytes]:
        if size == 1:
            return []
        k = split_k(size)
        if m < k:
            return build(m, lo, k) + [tree_root(leaves[lo + k:lo + size])]
        return build(m - k, lo + k, size - k) \
            + [tree_root(leaves[lo:lo + k])]

    raw = build(index, 0, n)

    # 重放同一递归以标注每个兄弟的左右位置（标注独立于哈希来源）。
    sides: list[str] = []

    def label(m: int, size: int):
        if size == 1:
            return
        k = split_k(size)
        if m < k:
            label(m, k)
            sides.append("R")
        else:
            label(m - k, size - k)
            sides.append("L")

    label(index, n)
    return [{"side": s, "hash": h.hex()} for s, h in zip(sides, raw)]


def verify_inclusion(leaf: bytes, index: int, tree_size: int,
                     proof: list[dict], root: bytes) -> bool:
    """离线复算包含路径（重放 RFC 递归，仅依赖 index/tree_size）。

    自顶向下推导叶子经过的每一层及其期望的兄弟左右位置（**不信任**
    证明里的 side，仅与推导出的期望值比对）；证明顺序为自叶子向上的
    后序，据此逐层折叠。校验：索引/规模合法；证明长度恰好等于树高；
    每个 side 与推导位置一致；重建根逐字节等于 root。
    换叶、错误索引、截短、加长、伪造旁支/兄弟均被拒绝。
    """
    if tree_size <= 0 or not (0 <= index < tree_size):
        return False
    try:
        nodes = [bytes.fromhex(p["hash"]) for p in proof]
        sides = [p.get("side") for p in proof]
    except (TypeError, ValueError, KeyError, AttributeError):
        return False
    if any(len(h) != 32 for h in nodes) \
            or any(s not in ("L", "R") for s in sides):
        return False

    # 自顶向下确定每层 (期望 side)；递归后追加 => 自叶子向上的后序。
    expected: list[str] = []

    def walk(m: int, size: int):
        if size == 1:
            return
        k = split_k(size)
        if m < k:
            walk(m, k)
            expected.append("R")
        else:
            walk(m - k, size - k)
            expected.append("L")

    walk(index, tree_size)
    if len(nodes) != len(expected) or sides != expected:
        return False

    node = leaf
    for want_side, sib in zip(expected, nodes):
        node = node_hash(node, sib) if want_side == "R" \
            else node_hash(sib, node)
    return node == root


# -- 一致性路径（RFC 6962 §2.1.2 构造 / 双根递归验证） --------------------
def _subproof(m: int, leaves: list[bytes], lo: int, size: int,
              b: bool) -> list[bytes]:
    """RFC SUBPROOF(m, D[size], b)，lo 为本子树在总序列的起点。"""
    if m == size:
        return [] if b else [tree_root(leaves[lo:lo + size])]
    k = split_k(size)
    if m <= k:
        return _subproof(m, leaves, lo, k, b) \
            + [tree_root(leaves[lo + k:lo + size])]
    return _subproof(m - k, leaves, lo + k, size - k, False) \
        + [tree_root(leaves[lo:lo + k])]


def consistency_proof(first_size: int, second_size: int,
                      leaves: list[bytes]) -> list[dict]:
    """RFC PROOF(m, D[n])：证明 first_size 叶是 second_size 叶的前缀。

    严格 RFC SUBPROOF，不预置旧根（旧根是验证者已持有的已签名树头；
    若由证明方再提供，分叉检测可被绕过）。side 恒为 "R" 占位：并入方向
    由 m,n 递归唯一决定，验证器不依赖它。
    """
    if not (0 < first_size <= second_size <= len(leaves)):
        raise ValueError("require 0 < first <= second <= len(leaves)")
    if first_size == second_size:
        return []
    nodes = _subproof(first_size, leaves, 0, second_size, True)
    return [{"side": "R", "hash": h.hex()} for h in nodes]


def verify_consistency(first_size: int, second_size: int,
                       proof: list[dict], first_root: bytes,
                       second_root: bytes) -> bool:
    """离线验证：旧树是新树的严格前缀（任意两个树头无分叉）。

    与 RFC SUBPROOF 同构的双根递归：消费证明的同时分别重建旧树 [0:m]
    与新树 [0:n] 的根，要求重建旧根==已签名 first_root、重建新根==
    已签名 second_root，且证明被恰好完全消费。

    旧根必须由证明独立重建并回验；若直接把 first_root 当左子树根而不
    回验，伪造的分叉证明会被误受。截断/加长/伪造旁支/非前缀（换叶、
    删叶）都导致重建失败或根不匹配。
    """
    if first_size <= 0 or second_size < first_size:
        return False
    if first_size == second_size:
        return len(proof) == 0 and first_root == second_root
    try:
        nodes = [bytes.fromhex(x["hash"]) for x in proof]
    except (TypeError, ValueError, KeyError, AttributeError):
        return False
    if any(len(h) != 32 for h in nodes):
        return False

    def rebuild(m: int, n: int, b: bool, i: int,
                known: bytes | None) -> tuple[bytes, bytes, int]:
        if m == n:
            if b:
                return known, known, i
            x = nodes[i]
            return x, x, i + 1
        k = split_k(n)
        if m <= k:
            old_l, new_l, i = rebuild(m, k, b, i, known)
            right = nodes[i]
            i += 1
            return old_l, node_hash(new_l, right), i
        old_r, new_r, i = rebuild(m - k, n - k, False, i, None)
        left = nodes[i]
        i += 1
        return node_hash(left, old_r), node_hash(left, new_r), i

    try:
        old_root, new_root, consumed = rebuild(
            first_size, second_size, True, 0, first_root)
    except IndexError:
        return False
    return (consumed == len(nodes) and old_root == first_root
            and new_root == second_root)
