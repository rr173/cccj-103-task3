"""容器启动验证 · 第三方审计公证场景（场景 J）。

由 tests/verifier.py 在全部组件（含 notary 公证节点）就绪后调用，
仅用标准库、只走黑盒 HTTP。审计器是"只能经网络取证"的离线角色：
不挂载/读取任何内部数据库或卷，只用公证节点的**公开**端点与协调端对外
请求视图完成全部密码学复算。

验收点：
  J1. 首组签发凭据与全域阻断标记都能取得有效包含路径（树头签名合法）。
  J2. 同一事实重放不增加树规模；同编号篡改正文返回 409 冲突且根摘要不变；
      经主流程产生的冲突（抢占规则批次编号）被待发箱诊断为 CONFLICT。
  J3. 公证端断网期间待发箱持续积压而主流程照常 CONFIRMED；连通后每项
      恰好入树一次（树增长数 == 积压数，位置唯一）。
  J4. 回执逆序（首个事实被卡住，其余先入树）与"发送方落确认前崩溃"
      都最终收敛：重启后幂等重放，每项恰好入树一次、无重复叶片。
  J5. 可追溯签名换代：换代声明自身入树；窗口内双签、窗口后新头只带新
      密钥标识；换代前后树头分别匹配正确公钥，genesis->新钥信任链连续；
      旧签名密钥 RETIRED、后续事实发生后，先前凭据仍可凭旧树头永久复核。
  J6. 两个不同规模的合法树头通过前缀一致性校验；删叶、换叶、截短、
      伪造旁支（含攻击密钥签名的假树头）全部被离线审计器拒绝。
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from common import (
    canonical,
    now_ms,
    rsa_generate_keypair,
    rsa_public_key,
    rsa_sign,
    tree_leaf_hash,
    tree_mth,
    tree_verify_consistency,
    tree_verify_inclusion,
)
from tests.offline_auditor import OfflineAuditor

C = os.environ.get("COORD_URL", "http://127.0.0.1:8080")
O = os.environ.get("ORDERS_URL", "http://127.0.0.1:9101")
N = os.environ.get("NOTARY_URL", "http://127.0.0.1:9105")
P = os.environ.get("POLICY_URL", "http://127.0.0.1:9104")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
COORD_RESTART_GRACE = float(os.environ.get("COORD_RESTART_GRACE", "2.0"))

ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
INTERNAL = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}


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


def _http_get(url, timeout=8.0):
    r = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def _wait(fn, timeout=30.0, interval=0.3, name=""):
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


# -- 小工具 ---------------------------------------------------------------
def seed_order(rec, sid):
    s, _ = _req("POST", O + "/seed",
                {"record_id": rec, "subject_id": sid, "payload": {}})
    assert s in (200, 201), (rec, s)


def create_request(sid):
    s, b = _req("POST", C + "/requests", {"subject_id": sid})
    assert s == 202, b
    return b["request_id"]


def request_view(rid):
    return _req("GET", f"{C}/requests/{rid}")[1]


def wait_confirmed(rid, timeout=30):
    return _wait(lambda: (lambda v: v if v["status"] == "CONFIRMED" else None)
                 (request_view(rid)), timeout=timeout, name=f"confirm {rid}")


def outbox():
    return _req("GET", C + "/admin/notary/outbox", headers=ADMIN)[1]


def outbox_facts(rid):
    return [f for f in outbox()["outbox"] if f["ref_id"] == rid]


def wait_facts_state(rid, state, timeout=20):
    def f():
        fs = outbox_facts(rid)
        return fs if fs and all(x["state"] == state for x in fs) else None
    return _wait(f, timeout=timeout, name=f"facts {rid} -> {state}")


def sth():
    return _req("GET", N + "/notary/v1/get-sth")[1]


def head_at(size):
    return _req("GET", f"{N}/notary/v1/head-at?tree_size={size}")[1]


def entry(fact_id):
    return _req("GET", f"{N}/notary/v1/get-entry-by-fact?fact_id={fact_id}")[1]


def proof(fact_id, size=None):
    u = f"{N}/notary/v1/get-proof-by-fact?fact_id={fact_id}"
    if size:
        u += f"&tree_size={size}"
    return _req("GET", u)[1]


def consistency(first, second):
    return _req("GET", f"{N}/notary/v1/get-consistency?first={first}"
                       f"&second={second}")[1]


def all_entries():
    size = sth()["tree_size"]
    if size == 0:
        return []
    return _req("GET", f"{N}/notary/v1/get-entries?start=0&end={size}")[1]["entries"]


def public_cert(rid):
    return request_view(rid)["certificates"][-1]


def run_notary_scenarios(check):
    def notary_get(path, timeout=8.0):
        # 离线审计器只认完整 URL：为其公开端点补公证基址
        return _http_get(N + path, timeout=timeout)

    auditor = OfflineAuditor(notary_get)
    auditor.load_trust_anchor()
    chain = auditor.build_trust_chain()  # 起点无换代：仅 genesis 受信
    check("J0 离线审计器取得 genesis 信任锚（仅经公开端点）",
          len(chain["trusted"]) >= 1 and "notary-key-genesis" in chain["trusted"])

    scenario_j1_inclusion(check, auditor)
    scenario_j2_replay_conflict(check, auditor)
    scenario_j3_outage(check)
    scenario_j4_reorder_and_crash(check)
    scenario_j5_rotation(check, auditor)
    scenario_j6_consistency_attacks(check, auditor)


# =========================================================================
# J1：首组凭据 + 全域阻断标记的包含路径
# =========================================================================
def scenario_j1_inclusion(check, auditor):
    print("\n=== 场景 J1：签发凭据/阻断标记取得有效包含路径 ===")
    sid = "sub-J1"
    seed_order("ord-j1", sid)
    rid = create_request(sid)
    wait_confirmed(rid)
    fs = wait_facts_state(rid, "SENT")
    types = {f["fact_type"]: f for f in fs}
    check("J1 凭据(CERTIFICATE)与阻断标记(GLOBAL_TOMBSTONE)均已公开",
          set(types) == {"CERTIFICATE", "GLOBAL_TOMBSTONE"}, str(types))

    # 审计器只凭公开端点复核：叶子哈希由日志条目正文复算，包含到当前树头
    for ftype, fid in ((t, types[t]["fact_id"]) for t in types):
        ent = entry(fid)
        lh = tree_leaf_hash(ent["encoded_bytes"].encode())
        pr = proof(fid)
        head = sth()
        ok_inc = tree_verify_inclusion(pr["leaf_index"], head["tree_size"], lh,
                                       pr["inclusion_path"],
                                       head["sha256_root_hash"])
        ok_sig = auditor.verify_head_signatures(head)
        check(f"J1 {ftype} 包含路径有效且树头签名合法", ok_inc and ok_sig,
              f"inc={ok_inc} sig={ok_sig}")

    # 日志中的 CERTIFICATE 事实必须与协调端对外公布的证书绑定一致
    cert = public_cert(rid)
    cert_fid = types["CERTIFICATE"]["fact_id"]
    body = json.loads(entry(cert_fid)["encoded_bytes"])
    check("J1 日志凭据正文与对外证书绑定一致（merkle_root/计数）",
          body["merkle_root"] == cert["merkle_root"]
          and body["item_count"] == cert["item_count"]
          and body["sealed_count"] == cert["sealed_count"]
          and body["request_id"] == rid, str(body))


# =========================================================================
# J2：重放不增树 / 篡改冲突根不变 / 主流程冲突诊断
# =========================================================================
def scenario_j2_replay_conflict(check, auditor):
    print("\n=== 场景 J2：重放幂等 / 正文冲突诊断 / 根摘要不变 ===")
    sid = "sub-J2"
    seed_order("ord-j2", sid)
    rid = create_request(sid)
    wait_confirmed(rid)
    fs = wait_facts_state(rid, "SENT")
    fid = next(f["fact_id"] for f in fs if f["fact_type"] == "CERTIFICATE")
    ent = entry(fid)
    encoded_hex = ent["encoded_bytes"].encode().hex()
    size_before = sth()["tree_size"]
    root_before = sth()["sha256_root_hash"]

    # 同编号同正文重放：原位置、树不增长
    s, rep = _req("POST", N + "/notary/v1/submit",
                  {"fact_id": fid, "fact_type": "CERTIFICATE",
                   "encoded": encoded_hex}, INTERNAL)
    size_after = sth()["tree_size"]
    check("J2 同编号重放返回原位置(idempotent)且不增加树规模",
          s == 200 and rep.get("idempotent") is True
          and rep["seq"] == ent["seq"] and size_after == size_before,
          f"{s} {rep} {size_before}->{size_after}")

    # 同编号异正文：409 诊断冲突，根摘要不变
    s, conf = _req("POST", N + "/notary/v1/submit",
                   {"fact_id": fid, "fact_type": "CERTIFICATE",
                    "encoded": canonical({"tampered": True}).hex()}, INTERNAL)
    root_after = sth()["sha256_root_hash"]
    check("J2 篡改正文返回冲突(409)且根摘要不变",
          s == 409 and "conflict" in str(conf.get("error", "")).lower()
          and conf.get("existing_seq") == ent["seq"]
          and root_after == root_before
          and sth()["tree_size"] == size_before, str(conf)[:160])

    # 经主流程的冲突：抢占确定性的规则批次编号，随后真正批次投递必被诊断
    sid2 = "sub-J2b"
    seed_order("ord-j2b", sid2)
    revn = _req("POST", P + "/policies/revisions",
                {"rules": [{"action": "SEAL", "service": "orders",
                            "record_glob": "ord-j2b", "hold_code": "H_J2"}],
                 "note": "j2"}, ADMIN)[1]["revision"]
    _req("POST", f"{P}/policies/revisions/{revn}/canary",
         {"canary_subjects": [sid2]}, ADMIN)
    mid = f"mig_r{revn}_canary_{sid2}_expna"
    batch_fid = f"rules:{mid}"
    # 抢占者先用同一稳定编号写入不同正文
    s, sq = _req("POST", N + "/notary/v1/submit",
                 {"fact_id": batch_fid, "fact_type": "RULE_BATCH",
                  "encoded": canonical({"squatter": True}).hex()}, INTERNAL)
    assert s == 200, sq
    rid2 = create_request(sid2)
    wait_confirmed(rid2)
    _req("POST", C + "/admin/policy/apply",
         {"revision": revn, "mode": "canary", "subjects": [sid2]}, ADMIN)
    # 真正批次入待发箱后被公证端判冲突：本地诊断 CONFLICT（主流程不受影响）
    def conflict_seen():
        row = next((f for f in outbox()["outbox"]
                    if f["fact_id"] == batch_fid), None)
        return row if row and row["state"] == "CONFLICT" else None
    row = _wait(conflict_seen, timeout=15, name="batch CONFLICT")
    check("J2 主流程规则批次遇同编号异正文被诊断为 CONFLICT（停止重试）",
        row is not None and row["tree_seq"] is None, str(row))


# =========================================================================
# J3：公证端断网 -> 积压而主流程照常 -> 连通后恰好入树一次
# =========================================================================
def scenario_j3_outage(check):
    print("\n=== 场景 J3：公证断网积压 / 主流程不阻塞 / 恢复恰好一次 ===")
    _req("POST", N + "/admin/fault",
         {"mode": "submit_503", "on": True}, ADMIN)
    size_during = sth()["tree_size"]

    sid = "sub-J3"
    seed_order("ord-j3", sid)
    rid = create_request(sid)
    v = wait_confirmed(rid)
    fs = outbox_facts(rid)
    check("J3 公证断网期间主流程照常 CONFIRMED",
          v["status"] == "CONFIRMED" and len(fs) == 2
          and all(f["state"] == "PENDING" for f in fs),
          str([(f["state"], f["attempts"]) for f in fs]))
    check("J3 尚未入树的凭据显示等待公开(WAITING_PUBLICATION)",
          all(f["publication"] == "WAITING_PUBLICATION"
              for f in v["notary_publication"]["facts"])
          and v["notary_publication"]["waiting_publication"] == 2)
    # 尝试若干轮投递，attempts 增长但树不增长
    time.sleep(1.5)
    check("J3 断网期间待发箱持续积压、树不增长",
          sth()["tree_size"] == size_during
          and all(f["attempts"] >= 1 for f in outbox_facts(rid)),
          str(sth()["tree_size"]))

    # 恢复：记录积压总数 -> 树应恰好增长这么多
    pending_before = outbox()["counts"]["pending"]
    _req("POST", N + "/admin/fault",
         {"mode": "submit_503", "on": False}, ADMIN)
    _wait(lambda: outbox()["counts"]["pending"] == 0,
          timeout=20, name="outbox drained")
    grew = sth()["tree_size"] - size_during
    check("J3 连通后积压全部入树且树增长数恰为积压数（每项恰好一次）",
          grew == pending_before, f"grew={grew} pending={pending_before}")
    fs = outbox_facts(rid)
    seqs = [f["tree_seq"] for f in fs]
    check("J3 本组两项位置唯一且都已公开",
          len(set(seqs)) == 2 and all(f["state"] == "SENT" for f in fs), str(fs))


# =========================================================================
# J4：回执逆序 + 落确认前崩溃 -> 最终收敛、恰好一次
# =========================================================================
def scenario_j4_reorder_and_crash(check):
    print("\n=== 场景 J4：回执逆序 / 确认前崩溃 -> 幂等收敛 ===")
    # --- 4a. 逆序：卡住首个 fact_id，其余先入树，再放行 ---
    _req("POST", N + "/admin/fault",
         {"mode": "stall_first", "on": True}, ADMIN)
    s1, s2 = "sub-J4a1", "sub-J4a2"
    seed_order("ord-j4a1", s1); seed_order("ord-j4a2", s2)
    rid_a = create_request(s1)
    rid_b = create_request(s2)
    wait_confirmed(rid_a); wait_confirmed(rid_b)
    # 等其余事实先入树（被卡的首事实保持 PENDING）
    blocked = _req("GET", N + "/admin/fault", headers=ADMIN)[1]["stall_fid"]
    def others_sent_blocked_pending():
        rows = outbox()["outbox"]
        mine = [f for f in rows if f["ref_id"] in (rid_a, rid_b)]
        blk = next((f for f in mine if f["fact_id"] == blocked), None)
        if not blk or blk["state"] != "PENDING":
            return None
        rest = [f for f in mine if f["fact_id"] != blocked]
        return (blk, rest) if rest and all(f["state"] == "SENT"
                                           for f in rest) else None
    blk, rest = _wait(others_sent_blocked_pending, timeout=15,
                      name="reorder: others first")
    size_before_release = sth()["tree_size"]
    check("J4a 回执逆序：首个事实被卡、其余事实先入树",
          len(rest) >= 2 and all(f["tree_seq"] is not None for f in rest),
          f"blocked={blocked}")
    # 放行 -> 被卡事实入树，仅增长 1（不重复）
    _req("POST", N + "/admin/fault",
         {"mode": "stall_first", "on": False}, ADMIN)
    _wait(lambda: (lambda f: f if f and f["state"] == "SENT" else None)
          (next((f for f in outbox()["outbox"] if f["fact_id"] == blocked),
                None)), timeout=15, name="blocked drains")
    final_rows = [f for f in outbox()["outbox"]
                  if f["ref_id"] in (rid_a, rid_b)]
    seqs = [f["tree_seq"] for f in final_rows]
    check("J4a 放行后被卡事实恰好入树一次（树仅 +1，位置唯一）",
          sth()["tree_size"] == size_before_release + 1
          and len(seqs) == len(set(seqs))
          and all(f["state"] == "SENT" for f in final_rows),
          f"seqs={sorted(seqs)}")

    # --- 4b. 发送方在落确认前崩溃（公证端已入树、SENT 未落盘） ---
    sid = "sub-J4b"
    seed_order("ord-j4b", sid)
    rid = create_request(sid)
    cert_fid = f"cert:{rid}:v1"
    # 武装：该事实确认到达后、落 SENT 前进程退出（仅本进程内存）
    s, arm = _req("POST", C + "/admin/notary/crash-before-ack",
                  {"fact_id": cert_fid}, ADMIN)
    assert s == 200, arm

    def died_or_confirmed():
        h = _req("GET", C + "/health", timeout=1.0)[0]
        if h == 0:
            return "DIED"
        # 若事实已在武装前完成（时序竞态），直接返回
        return None
    outcome = _wait(died_or_confirmed, timeout=15, name="coord crash")
    check("J4b 协调端在公证确认落盘前终止", outcome == "DIED", str(outcome))
    time.sleep(COORD_RESTART_GRACE)
    _wait(lambda: _req("GET", C + "/health", timeout=1.0)[0] == 200,
          timeout=20, name="coord restarted")

    # 重启后从落盘待发箱断点补齐：事实最终 SENT
    fs = wait_facts_state(rid, "SENT", timeout=25)
    # 该 fact 在公证日志中只出现一次（无重复叶片）
    matching = [e for e in all_entries() if e["fact_id"] == cert_fid]
    cert_row = next(f for f in fs if f["fact_id"] == cert_fid)
    check("J4b 重启后幂等补齐、每项恰好入树一次（无重复叶片）",
          len(matching) == 1 and cert_row["tree_seq"] == matching[0]["seq"]
          and all(f["state"] == "SENT" for f in fs),
          f"log_entries={len(matching)} row={cert_row['tree_seq']}")


# =========================================================================
# J5：签名换代：声明入树 / 窗口双签 / 窗口后新钥 / 信任链连续 / 旧头永久
# =========================================================================
def scenario_j5_rotation(check, auditor):
    print("\n=== 场景 J5：可追溯签名密钥换代 ===")
    # 换代前规模与树头（旧密钥单签）
    pre_size = sth()["tree_size"]
    pre_head = head_at(pre_size)
    pre_signers = set(pre_head["signer_key_ids"])
    check("J5 换代前树头仅由 genesis 密钥签名",
          pre_signers == {"notary-key-genesis"}, str(pre_signers))

    # 换代（短交叠窗口，留出事实创建/投递的充分余量），声明自身作为叶子入树
    s, rot = _req("POST", C + "/admin/notary/rotate",
                  {"overlap_seconds": 8}, ADMIN, timeout=30)
    assert s == 200, rot
    decl_size = rot["tree_size"]
    new_id = rot["new_key_id"]; old_id = rot["old_key_id"]
    # 审计器先从 genesis 链式验证换代声明（声明叶子包含 + 旧钥签名 + 公钥一致）
    chain = auditor.build_trust_chain()
    rot_rep = next((r for r in chain["rotations"] if r["new"] == new_id), None)
    check("J5 换代信任链连续：genesis 验签声明并引入新公钥",
          rot_rep is not None and rot_rep["old"] == old_id
          and new_id in chain["trusted"], str(chain["rotations"]))

    # 新公钥经受信链引入后，声明树头的旧/新双钥签名方可完整核验
    decl_head = head_at(decl_size)
    check("J5 换代声明已入树且声明树头旧/新双钥共同签名",
          set(decl_head["signer_key_ids"]) == {old_id, new_id}
          and auditor.verify_head_signatures(decl_head),
          str(decl_head["signer_key_ids"]))

    # 窗口内新事实 -> 双签（以该事实实际入树规模的固化树头为准，不依赖当前 STH）
    sid = "sub-J5-in"
    seed_order("ord-j5in", sid)
    rid_in = create_request(sid)
    wait_confirmed(rid_in)
    in_facts = wait_facts_state(rid_in, "SENT")
    in_size = max(f["tree_size"] for f in in_facts)
    in_head = head_at(in_size)
    check("J5 交叠窗口内新树头由新旧密钥共同受信（双签）",
          set(in_head["signer_key_ids"]) == {old_id, new_id}
          and auditor.verify_head_signatures(in_head), str(in_head["signer_key_ids"]))

    # 窗口结束后新事实 -> 仅新密钥标识
    _wait(lambda: now_ms() > rot["overlap_end_ms"], timeout=12,
          name="overlap window elapsed")
    time.sleep(0.3)
    sid2 = "sub-J5-out"
    seed_order("ord-j5out", sid2)
    rid_out = create_request(sid2)
    wait_confirmed(rid_out)
    out_facts = wait_facts_state(rid_out, "SENT")
    out_size = max(f["tree_size"] for f in out_facts)
    out_head = head_at(out_size)
    check("J5 窗口结束后新树头只使用新密钥标识",
          out_head["signer_key_ids"] == [new_id]
          and auditor.verify_head_signatures(out_head), str(out_head["signer_key_ids"]))

    # 旧树头与旧包含路径永久可验（旧钥 RETIRED 后仍受信于其历史树头）
    old_fid = f"cert:{rid_in}:v1"
    ent = entry(old_fid)
    lh = tree_leaf_hash(ent["encoded_bytes"].encode())
    pr = proof(old_fid, in_size)
    old_inc = tree_verify_inclusion(pr["leaf_index"], in_size, lh,
                                    pr["inclusion_path"],
                                    in_head["sha256_root_hash"])
    check("J5 换代后旧包含路径与旧树头仍永久可验",
          old_inc and auditor.verify_head_signatures(in_head),
          f"inc={old_inc}")

    # 后续动作（新钥下更多事实）后，先前公开凭据仍可凭旧树头复核
    later = auditor.verify_fact_published(old_fid, ent["encoded_bytes"].encode(),
                                          tree_size=in_size)
    check("J5 旧签名密钥撤销/后续事实后，先前凭据仍可凭旧树头复核",
          later["published"] and later["tree_size"] == in_size, str(later))


# =========================================================================
# J6：合法前缀一致；删叶/换叶/截短/伪造旁支被离线审计器拒绝
# =========================================================================
def scenario_j6_consistency_attacks(check, auditor):
    print("\n=== 场景 J6：前缀一致 / 拒绝删叶换叶截短伪造旁支 ===")
    cur = sth()
    n = cur["tree_size"]
    # 取两个不同规模的合法树头（至少相差 1；树已含大量事实）
    first = max(1, n - 3)
    second = n
    h1, h2 = head_at(first), head_at(second)
    cp = consistency(first, second)
    legit = tree_verify_consistency(first, second, h1["sha256_root_hash"],
                                    h2["sha256_root_hash"],
                                    cp["consistency_path"])
    check("J6 两个不同规模合法树头通过前缀一致性校验",
          legit and auditor.verify_no_fork(first, second)["consistent"],
          f"{first}->{second}")

    # 重建公开日志的叶子序列（仅用公开条目正文）
    entries = all_entries()
    leaves = [tree_leaf_hash(e["encoded_bytes"].encode()) for e in entries]
    assert tree_mth(leaves) == cur["sha256_root_hash"]
    victim = min(2, n - 1)
    real_path = proof(entries[victim]["fact_id"], n)["inclusion_path"]

    # 1) 删叶：从日志删掉 victim 重算根，伪造规模 n 的旁支根
    deleted = leaves[:victim] + leaves[victim + 1:]
    root_deleted = tree_mth(deleted)
    # 用真实包含路径 + 被删规模的假根 -> 必拒
    reject_del = tree_verify_inclusion(victim, n - 1, leaves[victim],
                                       real_path, root_deleted)
    # 路径被截掉一个节点（长度不符）-> 必拒
    reject_short_path = tree_verify_inclusion(victim, n, leaves[victim],
                                              real_path[1:],
                                              cur["sha256_root_hash"])
    check("J6 删叶（重算旁支根/缩规模）与截断路径被拒绝",
          reject_del is False and reject_short_path is False,
          f"del={reject_del} short={reject_short_path}")

    # 2) 换叶：用攻击者叶子哈希走真实路径 -> 根不匹配
    swapped = tree_leaf_hash(canonical({"attacker": "swapped leaf"}))
    reject_swap = tree_verify_inclusion(victim, n, swapped, real_path,
                                        cur["sha256_root_hash"])
    check("J6 换叶被拒绝（叶哈希与公开事实不符）", reject_swap is False)

    # 3) 截短：把真实一致性路径拿去对"截短树"（second-1 规模的根）验证
    if second - 1 >= first:
        trunc_root = tree_mth(leaves[:second - 1])
        reject_trunc = tree_verify_consistency(
            first, second, h1["sha256_root_hash"], trunc_root,
            cp["consistency_path"])
        # 截短头即使结构自洽，也没有受信签名（规模/根与固化头不符）
        trunc_head = dict(h2); trunc_head["tree_size"] = second - 1
        trunc_head["sha256_root_hash"] = trunc_root
        sig_ok = auditor.verify_head_signatures(trunc_head)
        check("J6 截短（旧前缀冒充更小树头/签名不绑定）被拒绝",
              reject_trunc is False and sig_ok is False,
              f"cons={reject_trunc} sig={sig_ok}")

    # 4) 伪造旁支：保留前 first 个叶子，之后换成攻击者叶子，另造一致性路径
    fork = leaves[:first] + [tree_leaf_hash(canonical({"fork": i}))
                             for i in range(second - first)]
    fork_root = tree_mth(fork)
    # 用旁支自己的结构造路径，拿去对真实旧根/真实新根验证 -> 必拒
    fork_path_local = _local_consistency(fork, first)
    reject_fork = tree_verify_consistency(
        first, second, h1["sha256_root_hash"], cur["sha256_root_hash"],
        fork_path_local)
    # 旁支树头由攻击者私钥签名 -> 不在信任锚集合 -> 必拒
    atk = rsa_generate_keypair(1024)
    fork_head = {
        "tree_size": second, "sha256_root_hash": fork_root,
        "timestamp": cur["timestamp"],
        "signer_key_ids": ["attacker-key"], "notary_key_id": "attacker-key"}
    fork_head["signed_bytes"] = canonical(
        {k: fork_head[k] for k in ("tree_size", "sha256_root_hash",
                                   "timestamp", "signer_key_ids",
                                   "notary_key_id")}).decode()
    fork_head["signatures"] = {
        "attacker-key": rsa_sign(canonical(fork_head), atk)}
    reject_fork_sig = auditor.verify_head_signatures(fork_head)
    check("J6 伪造旁支（自造一致性路径/攻击密钥签名树头）被拒绝",
          reject_fork is False and reject_fork_sig is False,
          f"cons={reject_fork} sig={reject_fork_sig}")


def _local_consistency(leaf_list, first):
    """攻击者本地为其旁支树构造一致性路径（复用 common 的生产算法）。"""
    from common import tree_consistency_path
    return tree_consistency_path(leaf_list, first)
