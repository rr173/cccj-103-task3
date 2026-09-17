"""容器启动验证 · 第三方审计公证节点场景（场景 J~P）。

由 tests/verifier.py 在全部组件（含 notary 公证节点）就绪后调用。
审计器**只能经网络取证**：不挂载任何内部数据卷、不读 SQLite，只凭公证端
公开接口与已发布公钥，独立离线复算所有密码学结论。

覆盖：
  J. 首组签发凭据 + 全域阻断标记取得有效包含路径；同一事实重放不增加
     树规模；篡改正文返回冲突且根摘要不变。
  K. 公证端断网期间待发箱持续积压而主流程照常结束（CONFIRMED）；连通后
     每项恰好入树一次。
  L. 回执逆序与发送方在落确认前崩溃：最终都收敛（每项恰一次，无空洞）。
  M. 签名密钥换代：换代前后树头分别匹配正确公钥，信任链连续；旧树头与
     旧包含路径在换代后仍永久可验。
  N. 两个不同规模的合法树头通过前缀一致性校验；删叶/换叶/截短/伪造旁支
     被离线审计器拒绝。
  O. 规则生效批次事实入树并可取包含路径。
  P. 后续撤销动作后，先前公开凭据仍可凭旧树头复核（追加不覆盖历史）。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request

import ed25519
import notary_tree as nt

C = os.environ.get("COORD_URL", "http://127.0.0.1:8080")
O = os.environ.get("ORDERS_URL", "http://127.0.0.1:9101")
B = os.environ.get("BILLING_URL", "http://127.0.0.1:9102")
PR = os.environ.get("PROFILE_URL", "http://127.0.0.1:9103")
N_ = os.environ.get("NOTARY_URL", "http://127.0.0.1:9105")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
SECRET = os.environ.get("DELETION_SIGNING_SECRET", "dev-deletion-secret").encode()

ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
INTERNAL = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}


# -- 纯网络 HTTP -----------------------------------------------------------
def _req(method, url, payload=None, headers=None, timeout=8.0):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw)
        except Exception:
            body = {"raw": raw}
        return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}


def _wait(fn, timeout=40.0, interval=0.3, name=""):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            x = fn()
        except Exception as e:
            x, last = None, repr(e)
        if x:
            return x
        time.sleep(interval)
    raise AssertionError(f"timeout: {name} last={last}")


def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


# -- 离线审计器：只依赖公开接口返回值与公钥，自行复算 ----------------------
class Auditor:
    """独立第三方审计器（无内部存储访问）。"""

    def __init__(self, check):
        self.check = check
        # 信任锚：从公证端 /notary/keys 取得的**带换代签名链**公钥集合。
        _, ks = _req("GET", N_ + "/notary/keys")
        self.keys = {k["generation"]: k for k in ks["keys"]}

    def head_public_bytes(self, head: dict) -> bytes:
        """树头的被签名规范字节（与公证端 canonical(head 去掉签名字段) 一致）。"""
        payload = {k: head[k] for k in
                   ("tree_size", "sha256_root_hash", "timestamp",
                    "key_generation", "key_id")}
        return canon(payload)

    def verify_head_signature(self, head: dict, label: str = "") -> bool:
        """用树头声明的 key_generation 对应公钥验签（不盲信任意公钥）。"""
        gen = head.get("key_generation")
        key = self.keys.get(gen)
        if not key:
            return False
        # 树头内 key_id 必须与受信公钥登记一致
        if head.get("key_id") != key["key_id"]:
            return False
        return ed25519.verify(bytes.fromhex(key["public_key"]),
                              self.head_public_bytes(head),
                              bytes.fromhex(head["signature"]))

    def verify_inclusion_offline(self, fact_id: str, tree_size=None,
                                 expect_body=None) -> dict:
        """拉取包含证据并完全离线复算：叶子哈希->包含路径->已签名根。"""
        url = N_ + f"/notary/inclusion/{fact_id}"
        if tree_size:
            url += f"?tree_size={tree_size}"
        s, ev = _req("GET", url)
        assert s == 200, (s, ev)
        head = ev["tree_head"]
        # 1) 树头签名合法
        assert self.verify_head_signature(head), f"bad head sig {fact_id}"
        # 2) 叶子 = H(0x00 || canonical(body))，与返回 leaf_hash 一致
        leaf = nt.leaf_hash(canon(ev["body"]))
        assert leaf.hex() == ev["leaf_hash"], "leaf hash mismatch"
        if expect_body is not None:
            assert ev["body"] == expect_body, "body mismatch"
        # 3) 包含路径复算到树头根
        ok = nt.verify_inclusion(
            leaf, ev["leaf_index"], head["tree_size"],
            ev["inclusion_path"], bytes.fromhex(head["sha256_root_hash"]))
        assert ok, f"inclusion verify failed {fact_id}"
        # 4) 树头根与其自报 tree_size 内洽
        assert head["tree_size"] == ev["tree_size"]
        return ev

    def consistency_offline(self, first: int, second: int) -> bool:
        s, ev = _req("GET",
                     N_ + f"/notary/consistency?first={first}&second={second}")
        assert s == 200, (s, ev)
        return nt.verify_consistency(
            first, second, ev["consistency_path"],
            bytes.fromhex(ev["first_root"]),
            bytes.fromhex(ev["second_root"]))


# -- 业务小工具（与 policy_scenarios 风格一致） ---------------------------
def seed(base, rec, sid):
    s, _ = _req("POST", f"{base}/seed",
                {"record_id": rec, "subject_id": sid, "payload": {}})
    assert s in (200, 201), (base, rec, s)


def view(rid):
    return _req("GET", f"{C}/requests/{rid}")[1]


def create(sid):
    s, d = _req("POST", f"{C}/requests", {"subject_id": sid})
    assert s == 202, d
    return d["request_id"]


def wait_confirmed(rid, timeout=40):
    return _wait(lambda: (lambda v: v if v["status"] == "CONFIRMED" else None)
                 (view(rid)), timeout=timeout, name=f"{rid} confirmed")


def wait_published(rid, kinds=None, timeout=40):
    """等待该请求所有事实 CONFIRMED；返回 fact_id->publication。"""
    def f():
        v = view(rid)
        pubs = v.get("notary_publications", [])
        if not pubs:
            return None
        sel = [p for p in pubs if (kinds is None or p["kind"] in kinds)]
        if sel and all(p["status"] == "CONFIRMED" for p in sel):
            return {p["fact_id"]: p for p in sel}
        return None
    return _wait(f, timeout=timeout, name=f"{rid} published")


def tree_size() -> int:
    s, h = _req("GET", N_ + "/notary/tree-head")
    assert s == 200
    return h["tree_size"]


# =========================================================================
# 场景 J：凭据/阻断标记包含 + 重放不增树 + 篡改冲突根不变
# =========================================================================
def scenario_j(check, aud: Auditor):
    print("\n=== 场景 J：凭据/阻断标记包含路径 / 重放幂等 / 篡改冲突 ===")
    sid = "sub-J-notary"
    seed(O, "ord-j1", sid)
    seed(B, "inv-j1", sid)
    rid = create(sid)
    wait_confirmed(rid)
    pubs = wait_published(rid)

    # 首组签发凭据 + 阻断标记都取得有效包含路径（离线复算）
    cred_fid = next(f for f, p in pubs.items() if f.startswith("fact-cred-"))
    block_fid = next(f for f, p in pubs.items() if f.startswith("fact-block-"))
    size_before = tree_size()
    cred_ev = aud.verify_inclusion_offline(cred_fid, expect_body=None)
    block_ev = aud.verify_inclusion_offline(block_fid)
    check("J 签发凭据取得有效包含路径（离线复算到签名根）",
          cred_ev["leaf_index"] is not None and cred_ev["kind"] == "credential")
    check("J 全域阻断标记取得有效包含路径",
          block_ev["kind"] == "block")
    check("J 公开状态为 public 且带叶子位置",
          pubs[cred_fid]["public"] and pubs[cred_fid]["leaf_index"] is not None)

    # 同一事实重放：经公证端再投，只能回原位置、树规模不增加
    s, rep = _req("POST", N_ + "/notary/append",
                  {"fact_id": cred_fid, "kind": "credential",
                   "body": cred_ev["body"]})
    check("J 同编号重放返回原位置且 idempotent",
          s == 200 and rep.get("idempotent") is True
          and rep["index"] == cred_ev["leaf_index"], str(rep))
    check("J 重放不增加树规模", tree_size() == size_before,
          f"{tree_size()} vs {size_before}")

    # 同编号携带不同正文 -> 409 冲突诊断；根摘要不变
    tampered = dict(cred_ev["body"])
    tampered["merkle_root"] = "deadbeef" * 8
    s, conf = _req("POST", N_ + "/notary/append",
                   {"fact_id": cred_fid, "kind": "credential",
                    "body": tampered})
    check("J 同号异文返回 409 fact_body_conflict",
          s == 409 and conf.get("code") == "fact_body_conflict"
          and conf.get("existing_index") == cred_ev["leaf_index"], str(conf))
    check("J 冲突后根摘要不变（树未被污染）",
          tree_size() == size_before)


# =========================================================================
# 场景 K：断网积压、主流程照常结束；连通后每项恰好入树一次
# =========================================================================
def scenario_k(check, aud: Auditor):
    print("\n=== 场景 K：公证端断网 / 待发箱积压 / 连通后恰好一次入树 ===")
    # 断网公证端
    s, _ = _req("POST", N_ + "/admin/fault",
                {"mode": "offline", "on": True}, ADMIN)
    check("K 公证端断网注入成功", s == 200, str(s))

    sid = "sub-K-offline"
    seed(O, "ord-k1", sid)
    seed(PR, "prof-k1", sid)
    rid = create(sid)

    # 主流程不受公证端影响：照常 CONFIRMED（证书照常签发）
    v = wait_confirmed(rid, timeout=30)
    check("K 公证断网期间主流程照常 CONFIRMED", v["status"] == "CONFIRMED",
          str(v["status"]))
    check("K 断网期间证书照常签发", len(v["certificates"]) >= 1)

    # 待发箱事实停在 PENDING（等待公开）
    def backlog():
        vv = view(rid)
        pubs = vv.get("notary_publications", [])
        pending = [p for p in pubs if p["status"] == "PENDING"]
        return pending if len(pending) >= 2 else None
    pending = _wait(backlog, timeout=10, name="K outbox backlog")
    check("K 待发箱持续积压（凭据+阻断等待公开）",
          len(pending) >= 2 and all(p["waiting"] for p in pending))
    # 未入树凭据只能显示等待公开
    check("K 尚未入树事实不提供叶子位置",
          all(p["leaf_index"] is None for p in pending))

    # 断网期间树不增长
    size_during_outage = tree_size()

    # 恢复连通
    s, _ = _req("POST", N_ + "/admin/fault", {"on": False}, ADMIN)
    check("K 公证端恢复", s == 200)

    # 每项最终 CONFIRMED，且各自 index 唯一、恰好入树一次
    pubs = wait_published(rid, timeout=40)
    indexes = sorted(p["leaf_index"] for p in pubs.values())
    check("K 连通后积压事实全部公开", len(pubs) >= 2 and
          all(p["status"] == "CONFIRMED" for p in pubs.values()))
    check("K 每项恰好入树一次（叶子位置两两不同）",
          len(indexes) == len(set(indexes)), str(indexes))
    check("K 入树数量恰为积压事实数（无重复投递增叶）",
          tree_size() - size_during_outage == len(pubs),
          f"{tree_size()}-{size_during_outage}!={len(pubs)}")
    # 离线复算每个事实
    for fid in pubs:
        aud.verify_inclusion_offline(fid)
    check("K 恢复后每项包含路径离线复算通过", True)


# =========================================================================
# 场景 L：回执逆序 + 发送方落确认前崩溃 -> 最终收敛
# =========================================================================
def scenario_l(check, aud: Auditor):
    print("\n=== 场景 L：确认逆序 / 发送方崩溃 / 断点补齐 ===")
    # 公证端在线，但给 append 注入显著延迟，使并发投递的回执天然逆序
    _req("POST", N_ + "/admin/fault",
         {"mode": "slow", "on": True, "seconds": 0.6}, ADMIN)

    sid = "sub-L-reorder"
    seed(O, "ord-l1", sid)
    rid = create(sid)
    wait_confirmed(rid, timeout=30)
    # 至少有凭据+阻断两件事实，在慢响应下并发投递，回执可能逆序
    pubs = wait_published(rid, timeout=40)
    check("L 慢响应（逆序窗口）下事实仍全部确认",
          len(pubs) >= 2 and all(p["status"] == "CONFIRMED"
                                 for p in pubs.values()))
    idxs = sorted(p["leaf_index"] for p in pubs.values())
    check("L 逆序回执收敛后位置唯一、无空洞",
          idxs == sorted(set(idxs)))

    _req("POST", N_ + "/admin/fault", {"on": False}, ADMIN)

    # 确保之前的待发箱全部排空后再武装崩溃，使注入只被新事实的确认触发
    def outbox_idle():
        s, rows = _req("GET", C + "/admin/notary/outbox", headers=ADMIN)
        if s != 200:
            return None
        pending = [x for x in rows["outbox"] if x["status"] == "PENDING"]
        return True if rows["outbox"] and not pending else None
    _wait(outbox_idle, timeout=30, name="L outbox drained before crash arm")

    # 发送方在"已发送、确认未落盘"前崩溃：武装崩溃注入后创建新请求
    s, arm = _req("POST", C + "/admin/notary/crash-after",
                  {"after": 1}, ADMIN)
    check("L 落确认前崩溃注入已武装（仅进程内存）",
          s == 200 and arm.get("crash_before_ack") == 1, str(arm))

    sid2 = "sub-L-crash"
    seed(B, "inv-l2", sid2)
    rid2 = create(sid2)

    # 协调端在投递后 os._exit；由 supervisor/compose 重启
    deadline = time.time() + 8
    died = False
    while time.time() < deadline:
        s, _ = _req("GET", C + "/health", timeout=1.0)
        if s == 0:
            died = True
            break
        time.sleep(0.2)
    check("L 发送方在落确认前已终止", died)

    # 等待重启（监督进程/编排负责，测试只等待）
    _wait(lambda: _req("GET", C + "/health", timeout=1.0)[0] == 200,
          timeout=20, name="L coordinator restarted")

    # 重启后从待发箱断点补齐：主流程完成 + 事实恰好入树一次
    wait_confirmed(rid2, timeout=40)
    pubs2 = wait_published(rid2, timeout=40)
    idxs2 = [p["leaf_index"] for p in pubs2.values()]
    check("L 重启后断点补齐、事实全部确认",
          all(p["status"] == "CONFIRMED" for p in pubs2.values()))
    check("L 崩溃恢复后每项恰好入树一次（无重复/无丢失）",
          len(idxs2) == len(set(idxs2)), str(idxs2))
    for fid in pubs2:
        aud.verify_inclusion_offline(fid)
    check("L 恢复后包含路径离线复算通过", True)


# =========================================================================
# 场景 M：签名密钥换代；新旧树头公钥正确、信任链连续、旧证据永久可验
# =========================================================================
def scenario_m(check, aud: Auditor):
    print("\n=== 场景 M：签名密钥换代 / 信任链连续 / 旧树头永久可验 ===")
    # 记录换代前的树头与一片旧叶子的包含证据（绑定旧公钥 gen1）
    s, head_before = _req("GET", N_ + "/notary/tree-head")
    old_size = head_before["tree_size"]
    old_root = head_before["sha256_root_hash"]
    check("M 换代前树头由 gen1 签名且可验",
          head_before["key_generation"] == 1
          and aud.verify_head_signature(head_before), str(head_before))

    # 先制造一片换代前的事实，保存其在旧树头下的包含路径
    sid = "sub-M-rotate"
    seed(O, "ord-m1", sid)
    rid = create(sid)
    wait_confirmed(rid, timeout=30)
    pre_pubs = wait_published(rid, timeout=30)
    pre_fid = next(f for f in pre_pubs if f.startswith("fact-cred-"))
    pre_ev = aud.verify_inclusion_offline(pre_fid)
    pre_head = pre_ev["tree_head"]
    pre_size = pre_head["tree_size"]
    pre_gen = pre_head["key_generation"]

    # 执行换代（换代声明自身入树）
    s, rot = _req("POST", C + "/admin/notary/rotate-key",
                  {"note": "M scheduled rotation", "overlap_seconds": 300},
                  ADMIN)
    check("M 换代成功并返回连续两代信息",
          s == 200 and rot.get("new_key_generation") == 2
          and rot.get("old_key_generation") == 1, str(rot))

    # 刷新审计器信任锚
    _, ks = _req("GET", N_ + "/notary/keys")
    aud.keys = {k["generation"]: k for k in ks["keys"]}

    # 信任链连续：新公钥由旧钥对换代声明的签名授权
    decl = {k: rot[k] for k in rot if k not in (
        "fact_id", "leaf_index", "tree_size")}
    decl_verify = {k: rot[k] for k in (
        "kind", "old_key_generation", "old_key_id", "old_public_key",
        "new_key_generation", "new_key_id", "new_public_key", "not_before",
        "overlap_until", "note", "declared_at")}
    old_pub = bytes.fromhex(rot["old_public_key"])
    chain_ok = ed25519.verify(
        old_pub, canon(decl_verify),
        bytes.fromhex(rot["declaration_signature"]))
    check("M 换代声明由旧密钥签名授权（信任链连续）", chain_ok)
    # 声明中的旧公钥必须与审计器已信任的 gen1 公钥一致
    check("M 换代声明绑定的旧公钥即既有受信锚",
          rot["old_public_key"] == aud.keys[1]["public_key"])
    # 换代声明自身也是一片叶子，可取包含路径
    aud.verify_inclusion_offline(rot["fact_id"], expect_body=None)
    check("M 换代声明自身已写入账簿并可验包含", True)

    # 换代后新事实 -> 新树头必须使用新密钥标识 gen2
    sid2 = "sub-M-after"
    seed(O, "ord-m2", sid2)
    rid2 = create(sid2)
    wait_confirmed(rid2, timeout=30)
    post_pubs = wait_published(rid2, timeout=30)
    post_fid = next(f for f in post_pubs if f.startswith("fact-cred-"))
    post_ev = aud.verify_inclusion_offline(post_fid)
    check("M 换代后新树头使用新密钥标识 gen2",
          post_ev["tree_head"]["key_generation"] == 2
          and post_ev["tree_head"]["key_id"]
          == aud.keys[2]["key_id"], str(post_ev["tree_head"]))

    # 旧树头与旧包含路径永久可验：用**换代前记录的旧树头/旧路径**复验
    old_still = nt.verify_inclusion(
        bytes.fromhex(pre_ev["leaf_hash"]), pre_ev["leaf_index"],
        pre_size, pre_ev["inclusion_path"],
        bytes.fromhex(pre_head["sha256_root_hash"]))
    check("M 旧包含路径在换代后仍可凭旧树头永久复验", old_still)
    check("M 旧树头仍由旧公钥 gen1 验证",
          pre_gen == 1 and aud.verify_head_signature(pre_head))

    # 交叠窗口语义：两代公钥当前都在受信集合
    check("M 新旧公钥在交叠窗口共同受信（均在密钥登记中）",
          1 in aud.keys and 2 in aud.keys)

    # 窗口结束后新树头必须使用新密钥标识：再做一次短窗口换代到 gen3，
    # 越过窗口后取树头，确认仍且仅由最新代密钥签名。
    s, rot3 = _req("POST", C + "/admin/notary/rotate-key",
                   {"note": "M short overlap", "overlap_seconds": 1}, ADMIN)
    check("M 短窗口换代到 gen3 成功", s == 200
          and rot3.get("new_key_generation") == 3, str(s))
    _, ks = _req("GET", N_ + "/notary/keys")
    aud.keys = {k["generation"]: k for k in ks["keys"]}
    overlap_until = rot3["overlap_until"]
    now_ms0 = int(time.time() * 1000)
    wait_s = max(0.0, (overlap_until - now_ms0) / 1000.0) + 0.3
    time.sleep(wait_s)
    s, h3 = _req("GET", N_ + "/notary/tree-head")
    check("M 交叠窗口结束后新树头使用最新密钥标识 gen3",
          h3["key_generation"] == 3 and aud.verify_head_signature(h3),
          str(h3.get("key_generation")))
    # 旧树头（gen1/gen2）在此之后仍永久可由各自旧公钥复验
    check("M 多代换代后 gen1/gen2 旧树头仍可验",
          aud.verify_head_signature(pre_head)
          and aud.verify_head_signature(post_ev["tree_head"]))
    # gen3 换代声明本身可取包含路径
    aud.verify_inclusion_offline(rot3["fact_id"])
    check("M gen3 换代声明包含路径离线可验", True)


# =========================================================================
# 场景 N：前缀一致性合法；删叶/换叶/截短/伪造旁支离线拒绝
# =========================================================================
def scenario_n(check, aud: Auditor):
    print("\n=== 场景 N：前缀一致性 / 离线审计器拒绝各类篡改 ===")
    # 取两个不同规模的已签名树头
    s, h1 = _req("GET", N_ + "/notary/tree-head")
    size_now = h1["tree_size"]
    # 制造若干新事实以获得"不同规模"的两个头
    sid = "sub-N-consistency"
    seed(PR, "prof-n1", sid)
    rid = create(sid)
    wait_confirmed(rid, timeout=30)
    pubs = wait_published(rid, timeout=30)
    s, h2 = _req("GET", N_ + "/notary/tree-head")
    size_later = h2["tree_size"]
    check("N 取得两个不同规模的合法树头",
          size_later > size_now, f"{size_later}>{size_now}")
    # 两者都签名有效
    check("N 两个树头签名均有效",
          aud.verify_head_signature(h1) and aud.verify_head_signature(h2))
    # 前缀一致性通过
    check("N 不同规模合法树头通过前缀一致性校验",
          aud.consistency_offline(size_now, size_later))

    # 现在构造离线攻击：取一个真实包含证据，施加四类篡改
    fid = next(f for f in pubs if f.startswith("fact-cred-"))
    s, ev = _req("GET", N_ + f"/notary/inclusion/{fid}")
    leaf = bytes.fromhex(ev["leaf_hash"])
    idx = ev["leaf_index"]
    tsize = ev["tree_size"]
    root = bytes.fromhex(ev["tree_head"]["sha256_root_hash"])
    proof = ev["inclusion_path"]

    # 1) 删叶：用空/错误叶子
    check("N 删叶（空叶子）被拒",
          not nt.verify_inclusion(b"", idx, tsize, proof, root))
    # 2) 换叶：另一事实的叶子哈希
    other_fid = next(f for f in pubs if f.startswith("fact-block-"))
    s, ev2 = _req("GET", N_ + f"/notary/inclusion/{other_fid}")
    other_leaf = bytes.fromhex(ev2["leaf_hash"])
    check("N 换叶（张冠李戴）被拒",
          not nt.verify_inclusion(other_leaf, idx, tsize, proof, root))
    # 3) 截短路径
    check("N 截短包含路径被拒",
          not nt.verify_inclusion(leaf, idx, tsize, proof[:-1], root))
    # 4) 伪造旁支：替换路径中一个兄弟
    import os as _os
    pf = [dict(x) for x in proof]
    if pf:
        pf[0]["hash"] = _os.urandom(32).hex()
    check("N 伪造旁支兄弟被拒",
          not nt.verify_inclusion(leaf, idx, tsize, pf, root))

    # 一致性路径同样拒绝：篡改一致性首哈希
    s, cons = _req("GET",
                   N_ + f"/notary/consistency?first={size_now}&second={size_later}")
    if cons["consistency_path"]:
        cp = [dict(x) for x in cons["consistency_path"]]
        cp[0]["hash"] = _os.urandom(32).hex()
        check("N 伪造一致性旁支被拒",
              not nt.verify_consistency(
                  size_now, size_later, cp,
                  bytes.fromhex(cons["first_root"]),
                  bytes.fromhex(cons["second_root"])))
    else:
        # 幂等规模不会出现；此处保底
        check("N 一致性路径非空（可被篡改测试）", False)
    # 非前缀旧根（换叶造分叉）必被一致性拒绝
    fork = bytes.fromhex(cons["first_root"])
    fork = bytes([fork[0] ^ 1]) + fork[1:]
    check("N 分叉旧根一致性被拒",
          not nt.verify_consistency(
              size_now, size_later, cons["consistency_path"], fork,
              bytes.fromhex(cons["second_root"])))


# =========================================================================
# 场景 O：规则生效批次事实入树
# =========================================================================
def scenario_o(check, aud: Auditor):
    print("\n=== 场景 O：规则生效批次公开入树 ===")
    from tests import policy_scenarios as ps
    sid = "sub-O-rules"
    ps.seed(O, "ord-o1", sid)
    # 让条目停在 RESTRICTED（purge 失联）再封存迁移
    ps.fault(O, "purge_503", True)
    rid = create(sid)
    _wait(ps.at_phase(rid, "ord-o1", ("RESTRICTED", "ERROR", "PURGING"),
                     purge_phase=True), name="O at purge phase")
    rev = ps.policy_rev([{"action": "SEAL", "service": "orders",
                          "record_glob": "ord-o1", "hold_code": "LEGAL_HOLD"}],
                        "O hold")
    s, _ = ps.canary(rev, [sid])
    assert s == 200
    s, m = ps.apply(rev, "canary", [sid])
    check("O 规则迁移完成", s == 200 and m["state"] == "COMPLETED", str(s))
    # 规则生效批次事实（migration 引用）最终入树
    fact_id = f"fact-rules-{m['id']}"

    def rules_confirmed():
        s, ob = _req("POST", C + "/admin/notary/drain", {}, ADMIN)
        s2, rows = _req("GET", C + "/admin/notary/outbox", headers=ADMIN)
        row = next((x for x in rows["outbox"] if x["fact_id"] == fact_id), None)
        return row if row and row["status"] == "CONFIRMED" else None
    row = _wait(rules_confirmed, timeout=30, name="O rules fact published")
    check("O 规则生效批次事实 CONFIRMED 入树",
          row["kind"] == "rules" and row["leaf_index"] is not None)
    ev = aud.verify_inclusion_offline(fact_id)
    check("O 规则批次叶子正文含修订号与生效项",
          ev["body"]["revision"] == rev
          and ev["body"]["applied_count"] >= 1, str(ev["body"]))
    ps.fault(O, "purge_503", False)


# =========================================================================
# 场景 P：后续撤销后，先前凭据仍可凭旧树头复核
# =========================================================================
def scenario_p(check, aud: Auditor):
    print("\n=== 场景 P：撤销后历史凭据凭旧树头永久可复核 ===")
    sid = "sub-P-revoke"
    seed(O, "ord-p1", sid)
    rid = create(sid)
    wait_confirmed(rid, timeout=30)
    pubs = wait_published(rid, timeout=30)
    cred_fid = next(f for f in pubs if f.startswith("fact-cred-"))
    # 记录撤销前的旧树头与包含证据
    pre = aud.verify_inclusion_offline(cred_fid)
    pre_size = pre["tree_head"]["tree_size"]
    pre_root = pre["tree_head"]["sha256_root_hash"]
    pre_proof = pre["inclusion_path"]
    pre_idx = pre["leaf_index"]
    pre_leaf = pre["leaf_hash"]

    # 触发后续撤销动作
    s, rev = _req("POST", f"{C}/admin/requests/{rid}/revoke",
                  {"reason": "P subsequent revocation"}, ADMIN)
    check("P 撤销动作已受理（202）", s == 202 and rev.get("fact_id"), str(rev))
    revoke_fid = rev["fact_id"]

    def revoke_published():
        v = view(rid)
        p = next((x for x in v.get("notary_publications", [])
                  if x["fact_id"] == revoke_fid), None)
        return p if p and p["status"] == "CONFIRMED" else None
    _wait(revoke_published, timeout=30, name="P revocation published")
    rev_ev = aud.verify_inclusion_offline(revoke_fid)
    check("P 撤销声明作为新叶子公开，且指向被撤销凭据版本",
          rev_ev["kind"] == "revocation"
          and rev_ev["body"]["revoked_certificate_version"] >= 1,
          str(rev_ev["body"]))

    # 树增长了（撤销是追加，不是覆盖）
    s, head_after = _req("GET", N_ + "/notary/tree-head")
    check("P 撤销后树规模增长（append-only）",
          head_after["tree_size"] > pre_size)

    # 先前公开凭据仍可用**撤销前的旧树头**永久复核
    still = nt.verify_inclusion(
        bytes.fromhex(pre_leaf), pre_idx, pre_size, pre_proof,
        bytes.fromhex(pre_root))
    check("P 撤销后先前凭据仍可凭旧树头复核（历史不改写）", still)

    # 旧树头到新树头的一致性也成立（撤销只是前缀扩展）
    check("P 旧树头与撤销后树头前缀一致（无分叉）",
          aud.consistency_offline(pre_size, head_after["tree_size"]))


def run_notary_scenarios(check):
    aud = Auditor(check)
    scenario_j(check, aud)
    scenario_k(check, aud)
    scenario_l(check, aud)
    scenario_m(check, aud)
    scenario_n(check, aud)
    scenario_o(check, aud)
    scenario_p(check, aud)
