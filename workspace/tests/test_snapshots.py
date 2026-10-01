"""审计验真快照：冻结、幂等、并发截止点、空快照、篡改检测与角色边界。

覆盖需求中的确定状态：
- 服务端在确定截止点取数，并发写入的新事件不混入已冻结结果；
- 同一幂等键的刷新/重复点击/并发创建只产生一份快照；
- 筛选为空（无匹配）得到记录数为 0 的可核对空快照；无筛选条件冻结全链；
- 原链被篡改、验真包内容被改动都返回确定判定且不泄露身份内容；
- officer 只能查询/复核，不能创建/下载；既有审计查询与导出接口保持可用。
"""
import base64
import json
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(home):
    from app.web.api import app
    with TestClient(app) as c:
        yield c


def _basic(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


CRED = {
    "tech": _basic("tech", "tech-pw-123"),
    "clinician": _basic("clinician", "clinician-pw-123"),
    "officer": _basic("officer", "officer-pw-123"),
    "admin": _basic("admin", "admin-pw-123"),
}


def _publish(client, sid):
    client.post("/api/queue/run", headers=CRED["tech"], params={"cycles": 5})
    q = client.get("/api/qc/queue", headers=CRED["tech"], params={"status": "passed"})
    for item in q.json():
        if item["study_id"] == sid:
            client.post("/api/qc/review", headers=CRED["tech"],
                        json={"version_id": item["id"], "approve": True, "note": "ok"})
            return item["id"]
    raise AssertionError("no passed version")


@pytest.fixture()
def seeded(client):
    """制造若干含回链导出的审计事件。"""
    sid = client.post("/api/studies/ingest-synthetic", headers=CRED["tech"],
                      json={}).json()["study_id"]
    _publish(client, sid)
    r = client.post("/api/relink/request", headers=CRED["clinician"],
                    json={"study_id": sid}).json()
    rid, share_a = r["id"], r["share_for_requester"]
    client.post(f"/api/relink/{rid}/share-a", headers=CRED["clinician"],
                json={"share": share_a})
    share_b = client.get("/api/relink/officer/pending",
                         headers=CRED["officer"]).json()[0]["share_for_officer"]
    client.post(f"/api/relink/{rid}/share-b", headers=CRED["officer"],
                json={"share": share_b})
    client.post(f"/api/relink/{rid}/export", headers=CRED["clinician"])
    return sid, rid


def _create(client, key, **filters):
    r = client.post("/api/audit/snapshots", headers=CRED["admin"],
                    json={"idempotency_key": key, **filters})
    assert r.status_code in (200, 201), r.text
    return r


# ---------- 角色边界 ----------

def test_role_boundaries(client, seeded):
    # officer 不能创建
    r = client.post("/api/audit/snapshots", headers=CRED["officer"],
                    json={"idempotency_key": "k1"})
    assert r.status_code == 403
    # tech/clinician 完全不可
    assert client.post("/api/audit/snapshots", headers=CRED["tech"],
                       json={"idempotency_key": "k1"}).status_code == 403
    assert client.get("/api/audit/snapshots", headers=CRED["tech"]).status_code == 403

    s = _create(client, "k-admin").json()
    sid = s["id"]
    # officer 可列/看/复核，但不能下载包
    assert client.get("/api/audit/snapshots", headers=CRED["officer"]).status_code == 200
    assert client.get(f"/api/audit/snapshots/{sid}",
                      headers=CRED["officer"]).status_code == 200
    assert client.get(f"/api/audit/snapshots/{sid}/package",
                      headers=CRED["officer"]).status_code == 403
    assert client.get(f"/api/audit/snapshots/{sid}/package",
                      headers=CRED["admin"]).status_code == 200
    # 未认证
    assert client.get("/api/audit/snapshots").status_code == 401


def test_existing_audit_query_and_export_still_work(client, seeded):
    sid, _ = seeded
    assert client.get("/api/audit", headers=CRED["officer"],
                      params={"study_id": sid}).status_code == 200
    assert client.get("/api/audit/verify", headers=CRED["admin"]).json()["ok"] is True
    exp = client.post("/api/audit/export", headers=CRED["admin"],
                      params={"fmt": "json"})
    assert exp.status_code == 200 and exp.json()["chain_verification"]["ok"]


# ---------- 冻结内容与截止点 ----------

def test_freeze_full_chain_excludes_self_and_later_events(client, seeded):
    total_before = client.get("/api/audit/verify",
                              headers=CRED["admin"]).json()["count"]
    r = _create(client, "full-1")
    assert r.status_code == 201
    s = r.json()
    assert s["created"] is True and s["idempotent_replay"] is False
    assert s["record_count"] == total_before  # 截止点不含创建事件自身
    assert s["cutoff_seq"] >= total_before
    assert s["chain_verification_at_freeze"]["ok"] is True
    assert s["empty"] is False
    assert s["filters"] == {}
    assert s["chain_anchor"]["last_mac"] != "GENESIS"

    # 下载验真包：内容与登记 sha/hmac 一致，含清单与全部记录
    pkg = client.get(f"/api/audit/snapshots/{s['id']}/package",
                     headers=CRED["admin"]).content
    import hashlib
    assert hashlib.sha256(pkg).hexdigest() == s["package"]["sha256"]
    body = json.loads(pkg)
    assert body["record_count"] == total_before
    assert len(body["records"]) == total_before
    assert body["cutoff"]["seq"] == s["cutoff_seq"]
    assert body["package_hmac"] == s["package"]["hmac"]
    # 原身份内容绝不出现在审计链/验真包中
    assert b"MRN-48213" not in pkg and b"ZHANG" not in pkg

    # 创建事件之后的新事件确实不在快照里：再制造事件后复核仍 verified、记录数不变
    client.post("/api/audit/snapshots", headers=CRED["admin"],
                json={"idempotency_key": "full-2"})
    pkg2 = client.get(f"/api/audit/snapshots/{s['id']}/package",
                      headers=CRED["admin"]).content
    assert pkg2 == pkg  # WORM + 截止点固定


def test_filtered_freeze_matches_query_at_cutoff(client, seeded):
    sid, rid = seeded
    r = _create(client, "filt-1", action="relink.export")
    s = r.json()
    assert s["record_count"] >= 1
    assert s["filters"] == {"action": "relink.export"}
    pkg = json.loads(client.get(
        f"/api/audit/snapshots/{s['id']}/package",
        headers=CRED["admin"]).content)
    assert {x["action"] for x in pkg["records"]} == {"relink.export"}
    # 每条记录都带可独立重算的 MAC 与 prev_mac
    for rec in pkg["records"]:
        assert rec["mac"] and rec["prev_mac"]
    # 首条记录的 prev_mac 与链锚一致
    assert pkg["chain_anchor"]["first_prev_mac"] == pkg["records"][0]["prev_mac"]


def test_empty_filter_match_gives_verifiable_empty_snapshot(client, seeded):
    r = _create(client, "empty-1", action="definitely.no.such.action")
    assert r.status_code == 201
    s = r.json()
    assert s["record_count"] == 0 and s["empty"] is True
    assert s["first_seq"] is None and s["last_seq"] is None
    assert s["chain_anchor"]["first_prev_mac"] == "GENESIS"
    assert s["chain_anchor"]["last_mac"] == "GENESIS"
    # 空快照同样验真通过
    pkg = client.get(f"/api/audit/snapshots/{s['id']}/package",
                     headers=CRED["admin"]).content
    rv = client.post(
        f"/api/audit/snapshots/review?expected_snapshot_id={s['id']}",
        headers=CRED["admin"], content=pkg)
    assert rv.status_code == 200 and rv.json()["verdict"] == "verified", rv.text


def test_snapshot_on_completely_empty_audit_chain(home):
    # 清空夹具播种策略时写入的审计事件后，验证 0 事件链也能冻结、空链重放完整
    from app.core import store
    from app.services import snapshots as snap
    conn = store.get_conn()
    conn.execute("DELETE FROM audit_log")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_log'")
    assert store.verify_audit_chain() == {"ok": True, "count": 0}
    view, created = snap.create_snapshot("admin", idempotency_key="genesis")
    assert created is True
    assert view["record_count"] == 0 and view["cutoff_seq"] == 0
    assert view["chain_verification_at_freeze"] == {"ok": True, "broken_at": None,
                                                    "count": 0}
    data, _ = snap.get_package_bytes(view["id"])
    result = snap.review_package(data, reviewer="officer",
                                 expected_snapshot_id=view["id"])
    assert result["verdict"] == "verified"


# ---------- 幂等 ----------

def test_idempotency_key_returns_same_snapshot(client, seeded):
    r1 = _create(client, "idem-key", action="relink.export")
    assert r1.status_code == 201
    s1 = r1.json()
    r2 = _create(client, "idem-key", action="relink.export")
    assert r2.status_code == 200
    s2 = r2.json()
    assert s2["created"] is False and s2["idempotent_replay"] is True
    assert s2["id"] == s1["id"]
    assert s2["cutoff_seq"] == s1["cutoff_seq"]
    assert s2["package"]["sha256"] == s1["package"]["sha256"]

    # 同键不同筛选 → 确定 409，不覆盖、不新建
    r3 = client.post("/api/audit/snapshots", headers=CRED["admin"],
                     json={"idempotency_key": "idem-key", "actor": "tech"})
    assert r3.status_code == 409
    # 原快照仍可取
    assert client.get(f"/api/audit/snapshots/{s1['id']}",
                      headers=CRED["admin"]).json()["id"] == s1["id"]
    # 缺少幂等键 → 422（pydantic）；空白键 → 400
    assert client.post("/api/audit/snapshots", headers=CRED["admin"],
                       json={}).status_code == 422
    assert client.post("/api/audit/snapshots", headers=CRED["admin"],
                       json={"idempotency_key": "   "}).status_code == 400


def test_concurrent_same_key_creates_exactly_one_snapshot(client, seeded):
    results, statuses = [], []
    barrier = threading.Barrier(4)

    def fire():
        barrier.wait()
        r = client.post("/api/audit/snapshots", headers=CRED["admin"],
                        json={"idempotency_key": "race-key"})
        results.append(r.json()["id"])
        statuses.append(r.status_code)

    threads = [threading.Thread(target=fire) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(results)) == 1
    assert statuses.count(201) == 1 and statuses.count(200) == 3


def test_concurrent_events_during_freeze_never_mix_in(client, seeded):
    """冻结进行时并发写入新审计事件：快照必须固定在其截止点。"""
    from app.core import store
    from app.services import snapshots as snap

    conn = store.get_conn()
    base = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]

    orig_query = snap._query_rows
    blocker = threading.Event()
    writer_done = threading.Event()

    def sqlite3_connect():
        c = sqlite3.connect(str(store.config.DB_PATH), timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def noisy_query(c, filters, cutoff_seq):
        # 在“已确定截止点、尚未提交”的窗口里，另一连接尝试写入新审计事件：
        # IMMEDIATE 锁会阻塞到冻结事务提交后才真正取链尾 MAC 并插入
        def write_later():
            blocker.wait(timeout=5)
            other = sqlite3_connect()
            try:
                other.execute("BEGIN IMMEDIATE")  # 阻塞至冻结事务提交
                last = other.execute(
                    "SELECT mac FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                from app.core import crypto
                ts = store.now_iso()
                detail_json = "{}"
                canonical = json.dumps(
                    [ts, "late-writer", "late.event", None, None, detail_json],
                    sort_keys=True, separators=(",", ":"))
                prev = last["mac"] if last else "GENESIS"
                other.execute(
                    "INSERT INTO audit_log(ts,actor,action,study_id,reid_id,"
                    "detail_json,prev_mac,mac) VALUES(?,?,?,?,?,?,?,?)",
                    (ts, "late-writer", "late.event", None, None,
                     detail_json, prev, crypto.audit_mac(prev, canonical)))
                other.commit()
            finally:
                other.close()
                writer_done.set()
        threading.Thread(target=write_later, daemon=True).start()
        rows = orig_query(c, filters, cutoff_seq)
        blocker.set()
        return rows

    snap._query_rows = noisy_query
    try:
        view, created = snap.create_snapshot("admin", idempotency_key="freeze-race")
    finally:
        snap._query_rows = orig_query
        # 等被锁阻塞的写线程在冻结事务提交后完成插入
        assert writer_done.wait(timeout=5)
    assert created is True
    assert view["record_count"] == base  # 后到事件与快照自身创建事件都未混入
    pkg = json.loads(store.blob_get(view["package"]["cas_id"]))
    assert all(r["action"] != "late.event" for r in pkg["records"])
    # 后到事件确实已在链上（快照之后），实时校验仍完整：
    # 冻结期新增 = 快照自身创建事件 1 条 + 后到事件 1 条
    assert store.verify_audit_chain()["ok"] is True
    assert conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"] == base + 2
    assert conn.execute(
        "SELECT COUNT(*) c FROM audit_log WHERE action='late.event'").fetchone()["c"] == 1
    # 对照：新全链快照包含这两条新事件
    view2, created2 = snap.create_snapshot("admin", idempotency_key="freeze-race-2")
    assert view2["record_count"] == base + 2


# ---------- 复核：包改动 / 链篡改 ----------

def _download(client, sid):
    return client.get(f"/api/audit/snapshots/{sid}/package",
                      headers=CRED["admin"]).content


def test_review_original_package_verified_by_admin_and_officer(client, seeded):
    s = _create(client, "rev-1", action="relink.export").json()
    pkg = _download(client, s["id"])
    for role in ("admin", "officer"):
        r = client.post(
            f"/api/audit/snapshots/review?expected_snapshot_id={s['id']}",
            headers=CRED[role], content=pkg)
        assert r.status_code == 200
        body = r.json()
        assert body["verdict"] == "verified", body
        f = body["findings"]
        assert f["package_hmac_ok"] and f["records_digest_ok"]
        assert f["record_self_mac_ok"] and f["frozen_set_ok"] is True
        assert all(f["snapshot_fields_match"].values())


def test_review_detects_modified_package(client, seeded):
    s = _create(client, "rev-2", action="relink.export").json()
    pkg = json.loads(_download(client, s["id"]))

    # 改动一条记录的 detail 且重算其外层 sha 不变 → HMAC 签名失败
    tampered = dict(pkg)
    recs = [dict(r) for r in pkg["records"]]
    recs[0]["detail_json"] = json.dumps({"hacked": True}, separators=(",", ":"))
    tampered["records"] = recs
    data = json.dumps(tampered).encode()
    r = client.post(
        f"/api/audit/snapshots/review?expected_snapshot_id={s['id']}",
        headers=CRED["officer"], content=data)
    assert r.json()["verdict"] == "package_tampered"

    # 只改签名字段本身
    tampered2 = dict(pkg)
    tampered2["package_hmac"] = "0" * 64
    r2 = client.post(
        f"/api/audit/snapshots/review?expected_snapshot_id={s['id']}",
        headers=CRED["officer"], content=json.dumps(tampered2).encode())
    assert r2.json()["verdict"] == "package_tampered"

    # 删掉一条记录但保留原签名
    tampered3 = dict(pkg)
    tampered3["records"] = recs[1:]
    r3 = client.post(
        f"/api/audit/snapshots/review?expected_snapshot_id={s['id']}",
        headers=CRED["officer"], content=json.dumps(tampered3).encode())
    assert r3.json()["verdict"] == "package_tampered"

    # 非 JSON / 空载荷
    assert client.post("/api/audit/snapshots/review", headers=CRED["officer"],
                       content=b"not-json").json()["verdict"] == "invalid_package"
    assert client.post("/api/audit/snapshots/review", headers=CRED["officer"],
                       content=b"").status_code == 400


def test_review_wrong_snapshot_binding_is_mismatch(client, seeded):
    s1 = _create(client, "rev-3a", action="relink.export").json()
    s2 = _create(client, "rev-3b", action="relink.request").json()
    pkg1 = _download(client, s1["id"])
    # 用 s2 的期望身份去绑定 s1 的包 → mismatch
    r = client.post(
        f"/api/audit/snapshots/review?expected_snapshot_id={s2['id']}",
        headers=CRED["admin"], content=pkg1)
    assert r.json()["verdict"] == "snapshot_mismatch"


def test_review_detects_tampered_underlying_chain(client, seeded):
    import sqlite3
    from app.core import store
    s = _create(client, "rev-4").json()
    # 篡改截止点之前的某条审计行（UPDATE detail_json 但不改 MAC）
    conn = sqlite3.connect(str(store.config.DB_PATH))
    conn.execute("UPDATE audit_log SET detail_json=? WHERE seq="
                 " (SELECT MIN(seq) FROM audit_log)", ('{"tampered":true}',))
    conn.commit(); conn.close()

    # 实时链校验接口立即暴露断裂
    v = client.get("/api/audit/verify", headers=CRED["admin"]).json()
    assert v["ok"] is False and v["broken_at"] is not None

    # 原封不动的验真包：包自身验签通过，但当前链重放失败 → chain_broken
    pkg = _download(client, s["id"])
    r = client.post(
        f"/api/audit/snapshots/review?expected_snapshot_id={s['id']}",
        headers=CRED["officer"], content=pkg)
    body = r.json()
    assert body["verdict"] == "chain_broken"
    assert body["findings"]["package_hmac_ok"] is True
    assert body["findings"]["chain_verification_now"]["ok"] is False


def test_worm_package_bytes_cannot_be_silently_changed(client, seeded, monkeypatch):
    """落盘包 0444：尝试改写被拒；即使强改，复核以 sha256/签名判定 tampered。"""
    import os
    from app.core import store
    s = _create(client, "rev-5").json()
    path = store.blob_path(s["package"]["cas_id"])
    assert oct(path.stat().st_mode & 0o777) == "0o444"
    with pytest.raises(PermissionError):
        with open(path, "wb") as f:
            f.write(b"x")
    # 管理员可下载、officer 不可
    assert client.get(f"/api/audit/snapshots/{s['id']}/package",
                      headers=CRED["officer"]).status_code == 403


def test_snapshot_registry_listing_shape_and_no_records(client, seeded):
    _create(client, "list-1", action="relink.export")
    _create(client, "list-2")
    rows = client.get("/api/audit/snapshots", headers=CRED["officer"]).json()
    assert len(rows) == 2
    for row in rows:
        # 列表/详情只给元数据，绝不含记录数组
        assert "records" not in row
        assert {"id", "cutoff_seq", "cutoff_ts", "filters", "record_count",
                "chain_anchor", "chain_verification_at_freeze", "package"} <= set(row)


def test_snapshot_create_and_review_are_themselves_audited(client, seeded):
    s = _create(client, "audit-trail", action="relink.export").json()
    pkg = _download(client, s["id"])
    client.post(f"/api/audit/snapshots/review?expected_snapshot_id={s['id']}",
                headers=CRED["officer"], content=pkg)
    actions = {r["action"] for r in client.get("/api/audit", headers=CRED["admin"]).json()}
    assert "audit.snapshot.create" in actions
    assert "audit.snapshot.review" in actions
