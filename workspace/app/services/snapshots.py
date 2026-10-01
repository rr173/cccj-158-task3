"""审计验真快照：服务端在确定截止点冻结筛选结果，产出可核对的验真包。

不变量：
- 快照由服务端在单个 IMMEDIATE 事务内取数：确定 cutoff（截止 seq/ts）、
  重放链完整性、按筛选取 seq<=cutoff 的记录，随后才在同一事务追加审计事件，
  因此并发写入的新审计事件不可能混入已冻结结果。
- 幂等键 UNIQUE：同键重复请求（刷新、重复点击、网络重试）一律返回原快照，
  不产生第二份包；同键但筛选不同返回 409，绝不静默改语义。
- 验真包是自描述 JSON：清单（范围/链锚/记录数/完整性）+ 逐条记录（含 MAC）
  + 记录集摘要 + 服务端 HMAC 签名。包落 WORM 内容寻址存储，
  任何字节改动都会在复核时暴露（sha256、签名、逐条 MAC 三重核对）。
- 包内只有审计链自身字段（actor/action/study_id/reid_id/detail），
  审计链从不记录原身份内容，故验真包不泄露身份。
- 隐私官（officer）只能查询快照与复核验真包；创建与下载为 admin 专属，
  由 Web 层强制。

复核判定（全部确定、可核对）：
  invalid_package   包不是合法 JSON / 结构缺字段
  package_tampered  签名、记录集摘要或记录自身 MAC 不一致 —— 验真包被改动
  snapshot_mismatch 包真实完整，但与登记快照/期望快照元数据不符（被换成另一份）
  chain_broken      包与登记一致，但冻结点声明或当前实时重放显示链已被篡改
  verified          全部通过（空快照也可 verified：0 条记录同样可核对）
"""
from __future__ import annotations

import json
import uuid

from ..core import crypto, store

SNAPSHOT_FILTER_KEYS = ("actor", "action", "study_id", "reid_id")


class SnapshotConflict(store.ConflictError):
    """幂等键已存在但请求参数与原快照不一致。"""


class SnapshotError(Exception):
    """快照请求或验真包本身不合法。"""


# ---------- 规范化（冻结与复核必须逐字节一致） ----------

def _canonical_row(rec: dict) -> str:
    return json.dumps(
        [rec["ts"], rec["actor"], rec["action"], rec["study_id"],
         rec["reid_id"], rec["detail_json"]],
        sort_keys=True, separators=(",", ":"))


def _canonical_obj(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _records_canonical(records: list[dict]) -> str:
    return "\n".join(_canonical_obj(rec) for rec in records)


def _normalize_filters(filters: dict | None) -> dict:
    out = {}
    for k in SNAPSHOT_FILTER_KEYS:
        v = (filters or {}).get(k)
        if v is not None and str(v).strip() != "":
            out[k] = str(v).strip()
    return out


def _query_rows(conn, filters: dict, cutoff_seq: int) -> list:
    """冻结点取数：仅取 seq<=cutoff 的行，升序（链顺序）。"""
    q = "SELECT * FROM audit_log WHERE seq<=?"
    args: list = [cutoff_seq]
    for k in SNAPSHOT_FILTER_KEYS:
        if filters.get(k):
            q += f" AND {k}=?"
            args.append(filters[k])
    q += " ORDER BY seq ASC"
    return conn.execute(q, tuple(args)).fetchall()


def _records_from_rows(rows: list) -> list[dict]:
    return [{
        "seq": r["seq"], "ts": r["ts"], "actor": r["actor"],
        "action": r["action"], "study_id": r["study_id"],
        "reid_id": r["reid_id"], "detail_json": r["detail_json"],
        "prev_mac": r["prev_mac"], "mac": r["mac"],
    } for r in rows]


def _build_package(*, snapshot_id: str, created_by: str, created_at: str,
                   cutoff_seq: int, cutoff_ts: str, filters: dict,
                   chain_verification: dict, records: list[dict]) -> tuple[bytes, dict]:
    """组装验真包并签名。冻结前已由全链重放确认链完整，故锚点直接取首尾。"""
    anchor_prev = records[0]["prev_mac"] if records else "GENESIS"
    anchor_mac = records[-1]["mac"] if records else "GENESIS"
    records_digest = crypto.sha256_hex(_records_canonical(records).encode())

    manifest = {
        "snapshot_id": snapshot_id,
        "schema": "audit-verification-package/v1",
        "created_by": created_by,
        "created_at": created_at,
        "cutoff": {"seq": cutoff_seq, "ts": cutoff_ts},
        "filters": filters,
        "record_count": len(records),
        "first_seq": records[0]["seq"] if records else None,
        "last_seq": records[-1]["seq"] if records else None,
        "empty": len(records) == 0,
        "chain_verification_at_freeze": chain_verification,
        "chain_anchor": {"first_prev_mac": anchor_prev, "last_mac": anchor_mac},
        "records_digest": records_digest,
        "records": records,
    }
    # 服务端签名覆盖 清单（除签名字段外的全部内容，含记录）
    package_hmac = crypto.snapshot_package_hmac(_canonical_obj(manifest))
    manifest["package_hmac"] = package_hmac
    data = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
    return data, {"anchor_prev_mac": anchor_prev, "anchor_mac": anchor_mac,
                  "records_digest": records_digest, "package_hmac": package_hmac}


# ---------- 创建（冻结） ----------

def create_snapshot(actor: str, *, idempotency_key: str,
                    filters: dict | None = None) -> tuple[dict, bool]:
    """创建（或按幂等键取回）验真快照。返回 (快照视图, created)。

    全程在服务端单事务内完成截止点确定与取数；
    快照创建审计事件在取数之后才于同一事务追加，截止点已固定，不会混入。
    """
    key = (idempotency_key or "").strip()
    if not key:
        raise SnapshotError("idempotency_key is required")
    if len(key) > 200:
        raise SnapshotError("idempotency_key too long")
    wanted = _normalize_filters(filters)
    conn = store.get_conn()
    conn.execute("BEGIN IMMEDIATE")
    try:
        # 1) 幂等判定（写锁串行化并发同键请求）
        existing = conn.execute(
            "SELECT * FROM audit_snapshots WHERE idempotency_key=?",
            (key,)).fetchone()
        if existing is not None:
            old_filters = json.loads(existing["filters_json"])
            if old_filters != wanted:
                conn.rollback()
                raise SnapshotConflict(
                    "idempotency_key already used with different filters")
            conn.rollback()  # 只读取回，不占写事务
            return _snapshot_view(existing["id"]), False

        # 2) 确定截止点：当前链尾即冻结边界
        tail = conn.execute(
            "SELECT seq,ts FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        if tail is None:
            cutoff_seq, cutoff_ts = 0, store.now_iso()
        else:
            cutoff_seq, cutoff_ts = tail["seq"], tail["ts"]

        # 3) 同一事务快照上重放全链完整性，并按筛选取冻结记录
        chain = store._verify_audit_chain_on(conn)
        rows = _query_rows(conn, wanted, cutoff_seq)
        records = _records_from_rows(rows)

        snapshot_id = f"snap_{uuid.uuid4().hex[:16]}"
        created_at = store.now_iso()
        data, extra = _build_package(
            snapshot_id=snapshot_id, created_by=actor, created_at=created_at,
            cutoff_seq=cutoff_seq, cutoff_ts=cutoff_ts, filters=wanted,
            chain_verification=chain, records=records)

        # 4) 验真包落 WORM（内容寻址，文件 0444）
        cas = store.blob_put("audit_snapshot_package", data, actor)
        if crypto.sha256_hex(data) != cas:
            raise SnapshotError("content-addressed storage mismatch")

        # 5) 快照元数据落盘
        conn.execute(
            "INSERT INTO audit_snapshots(id,idempotency_key,created_by,created_at,"
            " cutoff_seq,cutoff_ts,first_seq,last_seq,record_count,filters_json,"
            " chain_ok,chain_broken_at,chain_count,anchor_prev_mac,anchor_mac,"
            " records_digest,package_cas_id,package_sha256,package_hmac,package_size)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (snapshot_id, key, actor, created_at, cutoff_seq, cutoff_ts,
             records[0]["seq"] if records else None,
             records[-1]["seq"] if records else None,
             len(records), json.dumps(wanted, sort_keys=True, separators=(",", ":")),
             1 if chain["ok"] else 0, chain.get("broken_at"), chain["count"],
             extra["anchor_prev_mac"], extra["anchor_mac"],
             extra["records_digest"], cas, cas, extra["package_hmac"], len(data)))

        # 6) 冻结事件在取数之后追加：截止点已固定，本快照不含自身创建事件
        store.audit(actor, "audit.snapshot.create",
                    detail={"snapshot_id": snapshot_id, "idempotency_key": key,
                            "cutoff_seq": cutoff_seq, "records": len(records),
                            "chain_ok": chain["ok"],
                            "chain_broken_at": chain.get("broken_at"),
                            "package_cas_id": cas})
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _snapshot_view(snapshot_id), True


# ---------- 查询 ----------

def _row(snapshot_id: str):
    return store.one("SELECT * FROM audit_snapshots WHERE id=?", (snapshot_id,))


def _view_from_row(r) -> dict:
    return {
        "id": r["id"],
        "idempotency_key": r["idempotency_key"],
        "created_by": r["created_by"],
        "created_at": r["created_at"],
        "cutoff_seq": r["cutoff_seq"],
        "cutoff_ts": r["cutoff_ts"],
        "filters": json.loads(r["filters_json"]),
        "record_count": r["record_count"],
        "first_seq": r["first_seq"],
        "last_seq": r["last_seq"],
        "empty": r["record_count"] == 0,
        "chain_verification_at_freeze": {
            "ok": bool(r["chain_ok"]),
            "broken_at": r["chain_broken_at"],
            "count": r["chain_count"],
        },
        "chain_anchor": {
            "first_prev_mac": r["anchor_prev_mac"],
            "last_mac": r["anchor_mac"],
        },
        "records_digest": r["records_digest"],
        "package": {
            "cas_id": r["package_cas_id"],
            "sha256": r["package_sha256"],
            "hmac": r["package_hmac"],
            "size": r["package_size"],
        },
    }


def _snapshot_view(snapshot_id: str) -> dict:
    return _view_from_row(_row(snapshot_id))


def list_snapshots(limit: int = 200) -> list[dict]:
    rows = store.all_rows(
        "SELECT * FROM audit_snapshots ORDER BY created_at DESC, id DESC LIMIT ?",
        (max(1, min(limit, 1000)),))
    return [_view_from_row(r) for r in rows]


def get_snapshot(snapshot_id: str) -> dict:
    return _snapshot_view(snapshot_id)


def get_package_bytes(snapshot_id: str) -> tuple[bytes, dict]:
    """admin 下载用：返回包字节与快照元数据（包本身不含身份内容）。"""
    view = _snapshot_view(snapshot_id)
    return store.blob_get(view["package"]["cas_id"]), view


# ---------- 验真包复核（officer/admin；只回传核对结论，不回传额外身份内容） ----------

VERDICTS = ("verified", "package_tampered", "chain_broken", "snapshot_mismatch",
            "invalid_package")

_REQUIRED_KEYS = ("snapshot_id", "schema", "created_by", "created_at", "cutoff",
                  "filters", "record_count", "first_seq", "last_seq", "empty",
                  "chain_verification_at_freeze", "chain_anchor",
                  "records_digest", "records", "package_hmac")
_ROW_KEYS = {"seq", "ts", "actor", "action", "study_id", "reid_id",
             "detail_json", "prev_mac", "mac"}


def review_package(data: bytes, *, reviewer: str,
                   expected_snapshot_id: str | None = None) -> dict:
    """对一份验真包执行全部确定性核对（见模块文档字符串）。"""
    findings: dict = {}

    def finish(verdict: str) -> dict:
        findings["verdict"] = verdict
        store.audit(reviewer, "audit.snapshot.review",
                    detail={"snapshot_id": findings.get("snapshot_id"),
                            "expected_snapshot_id": expected_snapshot_id,
                            "verdict": verdict,
                            "record_count": findings.get("record_count_declared"),
                            "package_hmac_ok": findings.get("package_hmac_ok"),
                            "records_digest_ok": findings.get("records_digest_ok"),
                            "record_self_mac_ok": findings.get("record_self_mac_ok"),
                            "frozen_set_ok": findings.get("frozen_set_ok"),
                            "snapshot_fields_match": findings.get("snapshot_fields_match"),
                            "chain_ok_now": (findings.get("chain_verification_now") or {})
                            .get("ok"),
                            "chain_ok_at_freeze": (
                                findings.get("chain_verification_at_freeze") or {}).get("ok")})
        return {"verdict": verdict, "findings": findings}

    # 1) 结构
    try:
        pkg = json.loads(data.decode("utf-8"))
    except Exception as exc:
        findings["parse_error"] = f"package is not valid JSON: {exc}"
        return finish("invalid_package")
    if not isinstance(pkg, dict):
        findings["parse_error"] = "package root must be an object"
        return finish("invalid_package")
    missing = [k for k in _REQUIRED_KEYS if k not in pkg]
    if missing or pkg.get("schema") != "audit-verification-package/v1":
        findings["missing_fields"] = sorted(missing)
        findings["schema"] = pkg.get("schema")
        return finish("invalid_package")
    records = pkg["records"]
    filters = pkg["filters"]
    if not isinstance(records, list) or not isinstance(filters, dict):
        findings["structure"] = "records must be a list and filters an object"
        return finish("invalid_package")
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or _ROW_KEYS - set(rec):
            findings["record_error"] = {"index": i}
            return finish("invalid_package")

    findings["snapshot_id"] = pkg["snapshot_id"]
    findings["record_count_declared"] = pkg["record_count"]
    findings["package_sha256_actual"] = crypto.sha256_hex(data)

    db_row = store.maybe("SELECT * FROM audit_snapshots WHERE id=?",
                         (pkg["snapshot_id"],))
    findings["snapshot_exists_in_registry"] = db_row is not None

    # 2) 服务端 HMAC 签名（覆盖清单+记录；任一字节改动即不一致）
    unsigned = {k: v for k, v in pkg.items() if k != "package_hmac"}
    expect_hmac = crypto.snapshot_package_hmac(_canonical_obj(unsigned))
    findings["package_hmac_ok"] = crypto.hmac_compare(expect_hmac, pkg["package_hmac"])
    if not findings["package_hmac_ok"]:
        return finish("package_tampered")

    # 3) 记录集摘要与声明的范围/数量
    digest_ok = crypto.hmac_compare(
        crypto.sha256_hex(_records_canonical(records).encode()),
        pkg["records_digest"])
    findings["records_digest_ok"] = digest_ok
    findings["record_count_consistent"] = pkg["record_count"] == len(records)
    if records:
        findings["range_consistent"] = (
            pkg["first_seq"] == records[0]["seq"]
            and pkg["last_seq"] == records[-1]["seq"] and pkg["empty"] is False)
    else:
        findings["range_consistent"] = (
            pkg["first_seq"] is None and pkg["last_seq"] is None
            and pkg["empty"] is True)
    anchor_ok = (pkg["chain_anchor"] or {}).get("first_prev_mac") == (
        records[0]["prev_mac"] if records else "GENESIS") and (
        pkg["chain_anchor"] or {}).get("last_mac") == (
        records[-1]["mac"] if records else "GENESIS")
    findings["chain_anchor_consistent"] = anchor_ok
    if not (digest_ok and findings["record_count_consistent"]
            and findings["range_consistent"] and anchor_ok):
        return finish("package_tampered")

    # 4) 逐条记录自身 MAC（审计密钥仅服务端持有；签名有效的前提下能挡住换密钥等异常）
    self_mac_ok = True
    bad_seq = None
    for rec in records:
        expect = crypto.audit_mac(rec["prev_mac"], _canonical_row(rec))
        if not crypto.hmac_compare(expect, rec["mac"]):
            self_mac_ok, bad_seq = False, rec["seq"]
            break
    findings["record_self_mac_ok"] = self_mac_ok
    findings["record_self_mac_broken_at"] = bad_seq
    if not self_mac_ok:
        return finish("package_tampered")

    # 5) 与登记快照逐项核对（含按冻结筛选/截止重查当前库，比较记录集摘要）
    snapshot_fields_match: dict | None = None
    frozen_set_ok: bool | None = None
    if db_row is not None:
        stored_filters = json.loads(db_row["filters_json"])
        cur_rows = _query_rows(store.get_conn(), stored_filters, db_row["cutoff_seq"])
        cur_digest = crypto.sha256_hex(
            _records_canonical(_records_from_rows(cur_rows)).encode())
        frozen_set_ok = crypto.hmac_compare(cur_digest, pkg["records_digest"])
        findings["frozen_set_ok"] = frozen_set_ok
        worm_ok = False
        try:
            worm_ok = crypto.sha256_hex(
                store.blob_get(db_row["package_cas_id"])) == findings[
                "package_sha256_actual"]
        except store.NotFound:
            worm_ok = False
        snapshot_fields_match = {
            "cutoff_seq": db_row["cutoff_seq"] == pkg["cutoff"]["seq"],
            "cutoff_ts": db_row["cutoff_ts"] == pkg["cutoff"]["ts"],
            "record_count": db_row["record_count"] == pkg["record_count"],
            "records_digest": crypto.hmac_compare(db_row["records_digest"],
                                                  pkg["records_digest"]),
            "package_hmac": crypto.hmac_compare(db_row["package_hmac"],
                                                pkg["package_hmac"]),
            "package_sha256": db_row["package_sha256"] == findings[
                "package_sha256_actual"],
            "worm_bytes_sha256": worm_ok,
            "filters": stored_filters == filters,
        }
        findings["snapshot_fields_match"] = snapshot_fields_match

    # 6) 链完整性：冻结点声明 + 当前实时重放并列报告
    current_chain = store.verify_audit_chain()
    findings["chain_verification_now"] = current_chain
    findings["chain_verification_at_freeze"] = pkg["chain_verification_at_freeze"]

    # 7) 汇总结论（顺序即优先级）
    if expected_snapshot_id and expected_snapshot_id != pkg["snapshot_id"]:
        findings["expected_snapshot_id"] = expected_snapshot_id
        return finish("snapshot_mismatch")
    if db_row is not None and not all(snapshot_fields_match.values()):
        return finish("snapshot_mismatch")
    if db_row is None and expected_snapshot_id:
        # 要求绑定某个登记快照，但包中的快照身份查不到
        return finish("snapshot_mismatch")
    if not current_chain.get("ok") or not pkg["chain_verification_at_freeze"].get("ok"):
        return finish("chain_broken")
    return finish("verified")
