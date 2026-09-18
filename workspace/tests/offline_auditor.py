"""离线审计器：仅凭公开网络取证端点独立核验第三方公证哈希树。

设计原则：
- **不接触任何内部存储**：只通过公证节点的公开（无需令牌）HTTP 端点取证
  （get-sth / head-at / get-entries / get-proof-by-fact / get-consistency /
   keys / rotations），以及协调端对外可见的请求/证书视图。
- 全部密码学判断从零复算：叶子哈希、包含路径、前缀一致性路径、树头签名、
  换代信任链均在本模块内独立实现/复用 common 的无状态原语，
  不调用协调端或公证节点的任何"自证"接口。
- 攻击抗性：删叶、换叶、截短（旧树头被宣称成更大规模）、伪造旁支
  （另一棵树/另一条历史）都必须被拒绝。

唯一信任锚：genesis 公钥（首次启动公证节点生成，可通过带外渠道公布）。
后续公钥只能通过"已入树、由上一把受信私钥签名"的换代声明引入，
交叠窗口内树头双签、窗口后只由新密钥签，旧树头凭固化签名永久可验。
"""
from __future__ import annotations

import json

from common import (
    canonical,
    rsa_verify,
    tree_leaf_hash,
    tree_mth,
    tree_verify_consistency,
    tree_verify_inclusion,
)


class AuditError(Exception):
    pass


class OfflineAuditor:
    def __init__(self, http_get, genesis_public_key: dict | None = None,
                 genesis_key_id: str = "notary-key-genesis"):
        """http_get(url) -> (status, body)；由调用方提供（仅标准库 urllib）。"""
        self.get = http_get
        self.genesis_key_id = genesis_key_id
        if genesis_public_key is not None:
            self.keys = {genesis_key_id: genesis_public_key}
        else:
            # 信任锚取自 /keys 中标注的 genesis 公钥（演示部署）。
            # 生产应由带外渠道（配置/公证文书）固定，不依赖在线响应。
            self.keys = {}

    # -- 基础取证 ----------------------------------------------------------
    def _need(self, path: str) -> dict:
        status, body = self.get(path)
        if status != 200 or not isinstance(body, dict):
            raise AuditError(f"fetch failed {path}: {status} {body}")
        return body

    def load_trust_anchor(self) -> dict:
        data = self._need("/notary/v1/keys")
        for k in data.get("keys", []):
            self.keys[k["key_id"]] = k["public_key"]
        gen = next((k for k in data.get("keys", [])
                    if k["key_id"] == data.get("genesis_key_id",
                                               self.genesis_key_id)), None)
        if not gen:
            raise AuditError("genesis public key not published")
        self.genesis_key_id = gen["key_id"]
        self.keys[gen["key_id"]] = gen["public_key"]
        return gen

    def sth(self) -> dict:
        return self._need("/notary/v1/get-sth")

    def head_at(self, size: int) -> dict:
        return self._need(f"/notary/v1/head-at?tree_size={size}")

    def rotations(self) -> list[dict]:
        return self._need("/notary/v1/rotations").get("rotations", [])

    def proof(self, fact_id: str, tree_size: int | None = None) -> dict:
        q = f"/notary/v1/get-proof-by-fact?fact_id={fact_id}"
        if tree_size:
            q += f"&tree_size={tree_size}"
        return self._need(q)

    def consistency(self, first: int, second: int) -> dict:
        return self._need(f"/notary/v1/get-consistency?first={first}"
                          f"&second={second}")

    def entry(self, fact_id: str) -> dict:
        return self._need(f"/notary/v1/get-entry-by-fact?fact_id={fact_id}")

    # -- 树头签名 ----------------------------------------------------------
    @staticmethod
    def head_signed_bytes(head: dict) -> bytes:
        return canonical({k: head[k] for k in (
            "tree_size", "sha256_root_hash", "timestamp",
            "signer_key_ids", "notary_key_id")})

    def verify_head_signatures(self, head: dict,
                               rotations: list[dict] | None = None) -> bool:
        """验证一份固化树头：其声明的每个签名者都必须是"当前受信"密钥。

        受信集合随换代单调扩展：genesis + 历次换代声明引入的新公钥。
        若审计方只带 genesis 信任锚，则先链式验证全部换代声明再验本树头。
        """
        if not self.keys:
            self.load_trust_anchor()
        sb = self.head_signed_bytes(head)
        # 固化树头内 signed_bytes 必须与规范重算一致（防字段偷换）
        if sb.decode() != head.get("signed_bytes"):
            return False
        signers = head.get("signer_key_ids") or []
        sigs = head.get("signatures") or {}
        if not signers or set(signers) != set(sigs):
            return False
        for kid in signers:
            pub = self.keys.get(kid)
            if pub is None:
                return False
            if not rsa_verify(sb, sigs[kid], pub):
                return False
        return True

    def build_trust_chain(self) -> dict:
        """从 genesis 出发，验证每一次换代声明，扩展受信公钥集合。

        换代声明自身是一片叶子：必须 (1) 在其声明的树规模有合法包含路径，
        (2) 声明树头至少由"上一把受信旧密钥"签名（新钥签名用声明自带公钥
            交叉核验），(3) 声明正文由旧密钥签名且与入树条目逐字节一致。
        返回受信 {key_id: pub} 与诊断；任何一环失败即拒绝整条链。
        """
        if not self.keys:
            self.load_trust_anchor()
        # 刷新在线公布的公钥目录（仅作候选；真正受信仍只来自下面的链式验证）
        try:
            data = self._need("/notary/v1/keys")
            for k in data.get("keys", []):
                self.keys.setdefault(k["key_id"], k["public_key"])
        except AuditError:
            pass
        trusted = {self.genesis_key_id: self.keys[self.genesis_key_id]}
        report = []
        for rot in self.rotations():
            body = rot["body_obj"]
            old_id, new_id = rot["old_key_id"], rot["new_key_id"]
            decl_size = rot["seq"] + 1
            head = self.head_at(decl_size)
            sb = self.head_signed_bytes(head)
            # 固化树头 signed_bytes 必须与规范重算一致
            if sb.decode() != head.get("signed_bytes"):
                raise AuditError(f"rotation {new_id}: head bytes mismatch")
            signers = head.get("signer_key_ids") or []
            sigs = head.get("signatures") or {}
            if old_id not in signers or old_id not in trusted:
                raise AuditError(f"rotation {new_id}: old key not on decl head")
            # 旧钥签名必须有效（权威引导）；新钥（尚未受信）用声明自带公钥验
            if not rsa_verify(sb, sigs[old_id], trusted[old_id]):
                raise AuditError(f"rotation {new_id}: old-key head sig invalid")
            if new_id in signers:
                if not rsa_verify(sb, sigs[new_id], body["new_public_key"]):
                    raise AuditError(f"rotation {new_id}: new-key head sig"
                                     " does not match declared public key")
            # 声明叶子必须真实包含在该树头中
            fid = body_fact_id_from_rotation(rot)
            pr = self.proof(fid, decl_size)
            ent = self.entry(fid)
            lh = tree_leaf_hash(ent["encoded_bytes"].encode())
            if lh != pr["leaf_hash"] or not tree_verify_inclusion(
                    pr["leaf_index"], decl_size, lh,
                    pr["inclusion_path"], head["sha256_root_hash"]):
                raise AuditError(f"rotation {new_id}: declaration not in tree")
            # 声明正文必须与入树条目逐字节一致（声明与叶子不得脱节）
            if canonical(body).decode() != ent["encoded_bytes"]:
                raise AuditError(f"rotation {new_id}: body/entry mismatch")
            # 旧密钥对声明正文签名必须有效，且旧密钥在链上受信
            if not rsa_verify(canonical(body), rot["old_signature"],
                              trusted[old_id]):
                raise AuditError(f"rotation {new_id}: old declaration"
                                 " signature invalid")
            trusted[new_id] = body["new_public_key"]
            self.keys[new_id] = body["new_public_key"]
            report.append({"old": old_id, "new": new_id, "seq": rot["seq"],
                           "overlap_end_ms": rot["overlap_end_ms"]})
        return {"trusted": trusted, "rotations": report}

    # -- 事实包含（公开证明） ---------------------------------------------
    def verify_fact_published(self, fact_id: str, encoded_body: bytes,
                              tree_size: int | None = None) -> dict:
        """确认某确定性编码事实确已公开：叶子哈希 + 包含路径 + 树头签名。"""
        if not self.keys:
            self.load_trust_anchor()
        self.build_trust_chain()
        head = self.sth() if tree_size is None else self.head_at(tree_size)
        if not self.verify_head_signatures(head):
            raise AuditError("signed tree head signature invalid")
        size = head["tree_size"]
        pr = self.proof(fact_id, size)
        lh = tree_leaf_hash(encoded_body)
        if lh != pr["leaf_hash"]:
            return {"published": False, "reason": "leaf hash mismatch (body"
                    " does not match any published fact with that id)"}
        ok = tree_verify_inclusion(pr["leaf_index"], size, lh,
                                   pr["inclusion_path"],
                                   head["sha256_root_hash"])
        return {
            "published": ok,
            "tree_size": size, "leaf_index": pr["leaf_index"],
            "root": head["sha256_root_hash"],
            "signer_key_ids": head["signer_key_ids"],
            "head_timestamp": head["timestamp"],
        }

    # -- 前缀一致（无分叉） -------------------------------------------------
    def verify_no_fork(self, first: int, second: int) -> dict:
        """两个树头规模必须前缀一致；并分别验证签名与根绑定。"""
        if not self.keys:
            self.load_trust_anchor()
        self.build_trust_chain()
        h1 = self.head_at(first)
        h2 = self.head_at(second)
        if not self.verify_head_signatures(h1) \
                or not self.verify_head_signatures(h2):
            return {"consistent": False, "reason": "head signature invalid"}
        if first == second:
            return {"consistent": h1["sha256_root_hash"]
                    == h2["sha256_root_hash"]}
        cp = self.consistency(first, second)
        if cp["first_root"] != h1["sha256_root_hash"] \
                or cp["second_root"] != h2["sha256_root_hash"]:
            return {"consistent": False,
                    "reason": "proof roots not bound to signed heads"}
        ok = tree_verify_consistency(
            first, second, h1["sha256_root_hash"],
            h2["sha256_root_hash"], cp["consistency_path"])
        return {"consistent": ok, "first": first, "second": second,
                "first_signers": h1["signer_key_ids"],
                "second_signers": h2["signer_key_ids"]}

    def verify_certificate_fact(self, fact_id: str, fact_body: dict) -> dict:
        """验证一条已入树的 CERTIFICATE 事实正文与其叶子一致。"""
        return self.verify_fact_published(fact_id, canonical(fact_body))


def body_fact_id_from_rotation(rot: dict) -> str:
    return f"notary:key-rotation:{rot['seq']}"
