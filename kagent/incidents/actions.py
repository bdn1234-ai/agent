"""Đưa hành động đề xuất qua gateway, theo dõi duyệt và xác minh."""
from __future__ import annotations

import json
from datetime import timedelta

from .. import db
from .common import _event, _later
from .config import settings
from .ingest import poll


def strip_dry_run(args: dict) -> dict:
    """Gateway đã chạy thử trước khi hỏi; --dry-run trong lệnh được duyệt làm lệnh thật không bao giờ chạy."""
    import shlex
    command = args.get("command")
    if not isinstance(command, str) or "--dry-run" not in command:
        return args
    try:
        argv = shlex.split(command)
    except ValueError:
        return args
    return {**args, "command": shlex.join(a for a in argv if a != "--dry-run" and not a.startswith("--dry-run="))}


def _auto_count(actions: list[dict], since: str) -> int:
    return sum(1 for a in actions if a.get("auto") and (a.get("at") or "") >= since)


def act(conn, tenant_id: str, incident_id: str, report: dict, user: str, episode_id: str | None, alerts: list[dict] | None = None,
        steps: list[dict] | None = None) -> dict:
    """Đưa hành động đề xuất qua gateway. Tự xử lý đang tắt hay đã quá số lần thì ép hỏi người duyệt.

    Auto mode xét hành động theo luật tự xử lý của admin cùng tên và nhãn cảnh báo, không theo báo cáo hay kết quả điều tra
    vì cả hai được viết từ log và dữ liệu người ngoài ghi được.
    """
    from .. import gateway
    cfg = settings(conn, tenant_id)
    inc = db.row(conn.execute("SELECT * FROM incident WHERE id=?", (incident_id,)).fetchone(), "actions")
    env = inc["env"]
    if not report["actions"]:
        with db.tx(conn):
            conn.execute("UPDATE incident SET stage='reported', updated_at=? WHERE id=?", (db.iso(), incident_id))
            _event(conn, tenant_id, incident_id, "no_action", "không có hành động an toàn để đề xuất; cần người xem")
        return report
    rule = cfg["auto"][env]
    reasons = []
    if not rule["enabled"]:
        reasons.append(f"tự xử lý đang tắt ở {env}")
    hour_ago = (db.now() - timedelta(hours=1)).isoformat(timespec="seconds")
    if _auto_count(inc["actions"], hour_ago) >= cfg["max_auto_actions_per_hour"]:
        reasons.append(f"đã tự xử lý {cfg['max_auto_actions_per_hour']} lần trong 1 giờ cho sự cố này")
    if any(a.get("verified") is False for a in inc["actions"]):
        reasons.append("lần tự xử lý trước không làm hết cảnh báo")
    intent = [f"Tự xử lý sự cố ở môi trường {env}, chỉ trong phạm vi các luật sau của admin:\n" + "\n".join(f"- {r}" for r in cfg["auto_rules"]),
              "Cảnh báo của sự cố (tên và nhãn): " + json.dumps([{"alertname": a.get("alertname"), "labels": a.get("labels")} for a in alerts or []],
                                                               ensure_ascii=False)[:3000]]
    calls = [{"tool": s["tool"], "args": s.get("args"), "status": s.get("status")} for s in steps or []]
    ctx = gateway.CallContext(tenant_id, user, env, f"Xử lý sự cố: {inc['title']}", episode_id, intent=intent, calls=calls, escalate_on_block=True,
                              roles=gateway.user_roles(conn, tenant_id, user), forced=reasons)
    done = []
    for a in report["actions"]:
        a = {**a, "args": strip_dry_run(a["args"])}
        step = gateway.invoke(conn, ctx, a["tool"], a["args"])  # như agent: không bọc giao dịch quanh lệnh gọi mạng
        entry = {"tool": a["tool"], "args": a["args"], "why": a["why"], "at": db.iso(), "episode_id": episode_id, "status": step["status"], "decision": step.get("decision"),
                 "risk_tier": step.get("risk_tier"), "reasons": step.get("reasons") or [], "approval_id": step.get("approval_id"),
                 "dry_run": step.get("dry_run"), "auto": step["status"] == "ok",
                 "result": json.dumps(step.get("result"), ensure_ascii=False)[:2000] if step.get("result") is not None else None}
        done.append(entry)
        label = {"ok": "đã tự chạy", "pending": "chờ duyệt", "blocked": "bị chặn", "error": "lỗi", "invalid": "sai tham số"}.get(step["status"], step["status"])
        with db.tx(conn):
            _event(conn, tenant_id, incident_id, "action", f"{a['tool']}: {label}" + (f" ({'; '.join(entry['reasons'])})" if entry["reasons"] else ""),
                   {"tool": a["tool"], "status": step["status"]})
        if step["status"] != "ok":
            break  # bước sau dựa trên bước trước: chưa chạy được thì dừng
    stage = "verifying" if any(d["status"] == "ok" for d in done) else "awaiting_approval" if any(d["status"] == "pending" for d in done) else "needs_human"
    with db.tx(conn):
        conn.execute("UPDATE incident SET actions=?, stage=?, verify_due=?, updated_at=? WHERE id=?",
                     (json.dumps(inc["actions"] + done, ensure_ascii=False), stage, _later(cfg["verify_minutes"] * 60) if stage == "verifying" else None,
                      db.iso(), incident_id))
    return report


def _sync_approvals(conn, tenant_id: str, inc) -> None:
    """Lệnh chờ duyệt của sự cố đã được quyết: cập nhật trạng thái; có lệnh đã chạy thì chuyển sang xác minh."""
    cfg = settings(conn, tenant_id)
    actions = json.loads(inc["actions"])
    changed, executed, open_ = False, False, False
    for a in actions:
        if not a.get("approval_id") or a["status"] != "pending":
            continue
        req = conn.execute("SELECT status, result, decided_at FROM approval_request WHERE id=?", (a["approval_id"],)).fetchone()
        if req is None or req["status"] == "pending":
            open_ = True
            continue
        result = json.loads(req["result"]) if req["result"] else {}
        a["status"] = result.get("status", "ok") if req["status"] == "approved" else req["status"]
        a["ran_at"] = req["decided_at"] if a["status"] == "ok" else None
        if result.get("result") is not None:
            a["result"] = json.dumps(result.get("result"), ensure_ascii=False)[:2000]
        changed = True
        executed = executed or a["status"] == "ok"
        with db.tx(conn):
            _event(conn, tenant_id, inc["id"], "approval", f"{a['tool']}: {'đã duyệt và chạy' if a['status'] == 'ok' else a['status']}")
    if changed:
        stage = "verifying" if executed else "awaiting_approval" if open_ else "needs_human"
        with db.tx(conn):
            conn.execute("UPDATE incident SET actions=?, stage=?, verify_due=?, updated_at=? WHERE id=?",
                         (json.dumps(actions, ensure_ascii=False), stage, _later(cfg["verify_minutes"] * 60) if executed else None, db.iso(), inc["id"]))


def on_approval(conn, tenant_id: str, approval_id: str) -> None:
    """Gọi ngay sau khi có người duyệt/từ chối, để sự cố không phải đợi vòng nền."""
    req = conn.execute("SELECT episode_id FROM approval_request WHERE id=? AND tenant_id=?", (approval_id, tenant_id)).fetchone()
    if req is None or not req["episode_id"]:
        return
    for inc in conn.execute("SELECT * FROM incident WHERE tenant_id=? AND stage='awaiting_approval' AND actions LIKE ?", (tenant_id, f"%{approval_id}%")).fetchall():
        _sync_approvals(conn, tenant_id, inc)


def follow_up(conn, tenant_id: str) -> None:
    """Theo dõi duyệt và xác minh: lệnh được duyệt thì chờ xác minh; tới hạn thì xem cảnh báo đã hết chưa."""
    cfg = settings(conn, tenant_id)
    for inc in conn.execute("SELECT * FROM incident WHERE tenant_id=? AND stage='awaiting_approval' AND status!='closed'", (tenant_id,)).fetchall():
        _sync_approvals(conn, tenant_id, inc)
    now = db.iso()
    due = conn.execute("SELECT * FROM incident WHERE tenant_id=? AND stage='verifying' AND verify_due<=? AND status!='closed'", (tenant_id, now)).fetchall()
    if due and not cfg["enabled"] and cfg["sources"]:
        poll(conn, tenant_id)  # luồng đang tắt thì không ai poll; cần số liệu mới để xác minh
    for inc in due:
        left = conn.execute("SELECT count(*) n FROM alert_event WHERE incident_id=? AND status='firing'", (inc["id"],)).fetchone()["n"]
        actions = json.loads(inc["actions"])
        for a in actions:
            if a["status"] == "ok" and "verified" not in a:
                a["verified"] = left == 0
        with db.tx(conn):
            conn.execute("UPDATE incident SET actions=?, stage=?, verify_due=NULL, updated_at=? WHERE id=?",
                         (json.dumps(actions, ensure_ascii=False), "handled" if left == 0 else "needs_human", now, inc["id"]))
            _event(conn, tenant_id, inc["id"], "verified", "đã xác minh: cảnh báo đã hết" if left == 0 else
                   f"sau {cfg['verify_minutes']} phút vẫn còn {left} cảnh báo; chuyển cho người xử lý")
