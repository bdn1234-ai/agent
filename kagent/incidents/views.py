"""Dữ liệu cho danh sách, trang chi tiết và hội thoại của sự cố."""
from __future__ import annotations

import json

from .. import db
from . import actions
from .common import STAGE_LABEL, IncidentError, _is_write, describe, _method_label, _running, _shown_stage
from .grouping import merged_from
from .investigate import queued
from .summary import summary_view


def list_incidents(conn, tenant_id: str, status: str = "open", limit: int = 100) -> list[dict]:
    where = "" if status == "all" else "AND status=?"
    args = (tenant_id,) if status == "all" else (tenant_id, status)
    rs = conn.execute(f"SELECT * FROM incident WHERE tenant_id=? {where} ORDER BY last_alert_at DESC LIMIT ?", (*args, limit)).fetchall()
    out = []
    for r in rs:
        d = db.row(r, "evidence")
        counts = conn.execute("SELECT count(*) n, sum(status='firing') f, group_concat(DISTINCT source) s FROM alert_event WHERE incident_id=?", (r["id"],)).fetchone()
        last = conn.execute("SELECT * FROM incident_action WHERE incident_id=? AND origin='investigation' ORDER BY proposed_at DESC, rowid DESC LIMIT 1",
                            (r["id"],)).fetchone()
        last_action = view(dict(last)) if last else None
        d["stage"] = _shown_stage(d)
        out.append({**{k: d[k] for k in ("id", "env", "title", "severity", "status", "stage", "confidence", "created_at", "last_alert_at", "resolved_at")},
                    "stage_label": STAGE_LABEL.get(d["stage"], d["stage"]), "alerts": counts["n"], "firing": counts["f"] or 0,
                    "sources": (counts["s"] or "").split(",") if counts["s"] else [], "investigating": r["id"] in _running,
                    "last_action": {k: last_action.get(k) for k in ("tool", "args", "status", "risk_tier", "auto", "verified")} if last_action else None})
    return out


SHOWN_EVENTS = ("investigated", "verified", "resolved", "reopened", "closed", "no_action", "stopped", "error",
                "proposed", "ran", "failed", "denied", "expired")


def timeline(conn, inc: dict, alerts: list[dict]) -> list[dict]:
    """Nhật ký xử lý sự cố: cảnh báo bắt đầu/hết theo giờ thật, rồi các sự kiện đã ghi lúc việc xảy ra (nhận định, lệnh, quyết định, xác minh).

    Bỏ các mốc nội bộ (gộp, bắt đầu điều tra) vì không nói gì về bản thân sự cố.
    """
    out: list[dict] = []
    by_name: dict[str, list[dict]] = {}
    for a in alerts:
        by_name.setdefault(a["alertname"] or "?", []).append(a)
    for name, group in by_name.items():
        start = min((a["starts_at"] or a["first_seen"]) for a in group)
        out.append({"at": start, "kind": "alert", "actor": "alert", "text": f"{name} bắt đầu" + (f" ({len(group)} cảnh báo)" if len(group) > 1 else "")})
        if all(a["status"] == "resolved" for a in group):
            out.append({"at": max(a["resolved_at"] or "" for a in group), "kind": "alert_resolved", "actor": "alert", "text": f"{name} hết"})
    for e in conn.execute("SELECT at, kind, text, actor, action_id FROM incident_event WHERE incident_id=? AND kind IN (%s) ORDER BY id"
                          % ",".join("?" * len(SHOWN_EVENTS)), (inc["id"], *SHOWN_EVENTS)).fetchall():
        out.append(dict(e))
    return sorted(out, key=lambda e: e["at"] or "")


def actions_by_episode(conn, incident_id: str, episodes: list[dict]) -> dict[str, list[dict]]:
    """Hành động khắc phục của sự cố theo lượt chat đã đề xuất ra chúng, để hội thoại điều tra hiện như trang sự cố.

    Hành động lưu trước khi có episode_id: theo lượt của lệnh chờ duyệt, không có thì lượt cuối bắt đầu trước lúc đề xuất.
    """
    inc = conn.execute("SELECT tenant_id FROM incident WHERE id=?", (incident_id,)).fetchone()
    if inc is None or not episodes:
        return {}
    ids = {e["id"] for e in episodes}
    out: dict[str, list[dict]] = {}
    for a in actions.rows(conn, incident_id, "investigation"):
        ep = a["episode_id"]
        if ep is None and a["approval_id"]:
            req = conn.execute("SELECT episode_id FROM approval_request WHERE id=?", (a["approval_id"],)).fetchone()
            ep = req["episode_id"] if req else None
        if ep not in ids:
            ep = next((e["id"] for e in reversed(episodes) if (e["started_at"] or "") <= a["proposed_at"]), None)
        if ep is None:
            continue
        a = view(a)
        try:
            result = json.loads(a["result"]) if a["result"] else None
        except ValueError:
            result = a["result"]  # bị cắt 2000 ký tự nên không còn là JSON
        out.setdefault(ep, []).append({**{k: a[k] for k in ("tool", "args", "why", "status", "auto", "risk_tier", "reasons", "approval_id", "verified")},
                                       "result": result, "summary": describe(a["args"]),
                                       "action_class": "write" if _is_write(conn, inc["tenant_id"], a["tool"]) else "read"})
    return out


def view(row: dict) -> dict:
    """Một dòng incident_action theo dạng các phần tử incident.actions cũ (giao diện hiện tại đọc dạng này), kèm các cột mới."""
    def parsed(v):
        try:
            return json.loads(v) if v else None
        except ValueError:
            return v
    return {**row, "at": row["proposed_at"], "args": parsed(row["args"]), "reasons": parsed(row["reasons"]) or [], "dry_run": parsed(row["dry_run"]),
            "auto": bool(row["auto"]), "verified": None if row["verified"] is None else bool(row["verified"])}


def get(conn, tenant_id: str, incident_id: str) -> dict:
    r = conn.execute("SELECT * FROM incident WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
    if r is None:
        raise IncidentError("không tìm thấy sự cố", 404)
    d = db.row(r, "evidence")
    d["stage"] = _shown_stage(d)
    d["stage_label"] = STAGE_LABEL.get(d["stage"], d["stage"])
    d["investigating"] = incident_id in _running
    d["queued"] = queued(incident_id)
    d["summary"] = summary_view(conn, r)
    d["merged_from"] = merged_from(conn, incident_id)
    d["alerts"] = [{**db.row(a, "labels"), "join_label": _method_label(a["join_method"] or "")} for a in conn.execute(
        "SELECT * FROM alert_event WHERE incident_id=? ORDER BY starts_at", (incident_id,)).fetchall()]
    d["timeline"] = timeline(conn, d, d["alerts"])
    d["actions"] = [view(a) for a in actions.rows(conn, incident_id, "investigation")]
    for a in d["actions"]:
        if a.get("approval_id"):
            req = conn.execute("SELECT status FROM approval_request WHERE id=?", (a["approval_id"],)).fetchone()
            a["approval_status"] = req["status"] if req else None
    d["steps"] = []
    if d["episode_id"]:
        ep = conn.execute("SELECT trace, output FROM episode WHERE id=?", (d["episode_id"],)).fetchone()
        if ep:
            d["investigation"] = ep["output"]
            d["steps"] = [{"tool": s["tool"], "args": s.get("args"), "status": s["status"], "untrusted": bool(s.get("untrusted"))}
                          for s in json.loads(ep["trace"]) if s["type"] == "tool_call"]
    return d
