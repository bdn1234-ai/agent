"""Dữ liệu cho danh sách, trang chi tiết và hội thoại của sự cố."""
from __future__ import annotations

import json

import yaml

from .. import db
from .common import STAGE_LABEL, IncidentError, _cmd, _is_write, _method_label, _running, _shown_stage
from .grouping import merged_from
from .investigate import queued
from .summary import summary_view


def list_incidents(conn, tenant_id: str, status: str = "open", limit: int = 100) -> list[dict]:
    where = "" if status == "all" else "AND status=?"
    args = (tenant_id,) if status == "all" else (tenant_id, status)
    rs = conn.execute(f"SELECT * FROM incident WHERE tenant_id=? {where} ORDER BY last_alert_at DESC LIMIT ?", (*args, limit)).fetchall()
    out = []
    for r in rs:
        d = db.row(r, "evidence", "actions")
        counts = conn.execute("SELECT count(*) n, sum(status='firing') f, group_concat(DISTINCT source) s FROM alert_event WHERE incident_id=?", (r["id"],)).fetchone()
        last_action = d["actions"][-1] if d["actions"] else None
        d["stage"] = _shown_stage(d)
        out.append({**{k: d[k] for k in ("id", "env", "title", "severity", "status", "stage", "confidence", "created_at", "last_alert_at", "resolved_at")},
                    "stage_label": STAGE_LABEL.get(d["stage"], d["stage"]), "alerts": counts["n"], "firing": counts["f"] or 0,
                    "sources": (counts["s"] or "").split(",") if counts["s"] else [], "investigating": r["id"] in _running,
                    "last_action": {k: last_action.get(k) for k in ("tool", "args", "status", "risk_tier", "auto", "verified")} if last_action else None})
    return out


SHOWN_EVENTS = ("investigated", "verified", "resolved", "reopened", "closed", "no_action", "stopped", "error")


def timeline(conn, inc: dict, alerts: list[dict]) -> list[dict]:
    """Diễn biến của sự cố: cảnh báo bắt đầu/hết theo giờ thật, nhận định, lệnh khắc phục đã chạy, xác minh.

    Bỏ các mốc nội bộ (gộp, bắt đầu điều tra, lúc duyệt) vì không nói gì về bản thân sự cố.
    """
    out: list[dict] = []
    by_name: dict[str, list[dict]] = {}
    for a in alerts:
        by_name.setdefault(a["alertname"] or "?", []).append(a)
    for name, group in by_name.items():
        start = min((a["starts_at"] or a["first_seen"]) for a in group)
        out.append({"at": start, "kind": "alert", "text": f"{name} bắt đầu" + (f" ({len(group)} cảnh báo)" if len(group) > 1 else "")})
        if all(a["status"] == "resolved" for a in group):
            out.append({"at": max(a["resolved_at"] or "" for a in group), "kind": "alert_resolved", "text": f"{name} hết"})
    for e in conn.execute("SELECT at, kind, text FROM incident_event WHERE incident_id=? AND kind IN (%s) ORDER BY id" % ",".join("?" * len(SHOWN_EVENTS)),
                          (inc["id"], *SHOWN_EVENTS)).fetchall():
        out.append(dict(e))
    seen = set()
    for a in inc["actions"]:
        if a["status"] == "ok":
            seen.add(a.get("approval_id"))
            out.append({"at": a.get("ran_at") or a["at"], "kind": "fix", "text": f"chạy {_cmd(a)}" + (" (tự động)" if a.get("auto") else "")})
    if inc.get("conversation_id"):
        # Lệnh khắc phục người dùng chạy thêm trong hội thoại của sự cố.
        for ep in conn.execute("SELECT id, started_at, trace FROM episode WHERE conversation_id=? ORDER BY started_at", (inc["conversation_id"],)).fetchall():
            for s in json.loads(ep["trace"]):
                if s.get("type") == "tool_call" and s.get("status") == "ok" and _is_write(conn, inc["tenant_id"], s["tool"]):
                    out.append({"at": ep["started_at"], "kind": "fix", "text": f"chạy {_cmd(s)}"})
            for r in conn.execute("SELECT id, tool, args, result, decided_at FROM approval_request WHERE episode_id=? AND status='approved'", (ep["id"],)).fetchall():
                result = json.loads(r["result"]) if r["result"] else {}
                if r["id"] not in seen and result.get("status") == "ok":
                    out.append({"at": r["decided_at"], "kind": "fix", "text": f"chạy {_cmd({'tool': r['tool'], 'args': json.loads(r['args'])})}"})
    return sorted(out, key=lambda e: e["at"] or "")


def actions_by_episode(conn, incident_id: str, episodes: list[dict]) -> dict[str, list[dict]]:
    """Hành động khắc phục của sự cố theo lượt chat đã đề xuất ra chúng, để hội thoại điều tra hiện như trang sự cố.

    Hành động lưu trước khi có episode_id: theo lượt của lệnh chờ duyệt, không có thì lượt cuối bắt đầu trước lúc đề xuất.
    """
    inc = conn.execute("SELECT tenant_id, actions FROM incident WHERE id=?", (incident_id,)).fetchone()
    if inc is None or not episodes:
        return {}
    ids = {e["id"] for e in episodes}
    out: dict[str, list[dict]] = {}
    for a in json.loads(inc["actions"] or "[]"):
        ep = a.get("episode_id")
        if ep is None and a.get("approval_id"):
            req = conn.execute("SELECT episode_id FROM approval_request WHERE id=?", (a["approval_id"],)).fetchone()
            ep = req["episode_id"] if req else None
        if ep not in ids:
            ep = next((e["id"] for e in reversed(episodes) if (e["started_at"] or "") <= (a.get("at") or "")), None)
        if ep is None:
            continue
        try:
            result = json.loads(a["result"]) if a.get("result") else None
        except ValueError:
            result = a["result"]  # bị cắt 2000 ký tự nên không còn là JSON
        out.setdefault(ep, []).append({"tool": a["tool"], "args": a.get("args"), "why": a.get("why"), "status": a["status"], "auto": bool(a.get("auto")),
                                       "risk_tier": a.get("risk_tier"), "reasons": a.get("reasons") or [], "approval_id": a.get("approval_id"),
                                       "verified": a.get("verified"), "result": result, "summary": describe(a.get("args")),
                                       "action_class": "write" if _is_write(conn, inc["tenant_id"], a["tool"]) else "read"})
    return out


MANIFEST_VERBS = {"apply": "tạo hoặc cập nhật", "create": "tạo", "replace": "thay", "delete": "xóa", "patch": "sửa"}


def describe(args) -> str | None:
    """Câu ngắn cho lệnh kubectl kèm manifest khi không có _why: dòng lệnh chỉ còn "apply -f -", không nói đụng vào đối tượng nào."""
    if not isinstance(args, dict) or not isinstance(args.get("manifest"), str):
        return None
    try:
        docs = [d for d in yaml.safe_load_all(args["manifest"]) if isinstance(d, dict)]
    except yaml.YAMLError:
        return None
    command = args.get("command") if isinstance(args.get("command"), str) else ""
    words = command.split()
    verb = MANIFEST_VERBS.get(next((w for w in words if w in MANIFEST_VERBS), ""), "áp manifest")
    flag_ns = next((words[i + 1] for i, w in enumerate(words[:-1]) if w in ("-n", "--namespace")), None)
    names = []
    for d in docs[:5]:
        meta = d.get("metadata") if isinstance(d.get("metadata"), dict) else {}
        ns = meta.get("namespace") or flag_ns
        names.append(f"{d.get('kind', '?')} {meta.get('name', '?')}" + (f" (namespace {ns})" if ns else ""))
    if not names:
        return None
    return f"{verb} " + ", ".join(names) + (f" và {len(docs) - 5} đối tượng khác" if len(docs) > 5 else "")


def get(conn, tenant_id: str, incident_id: str) -> dict:
    r = conn.execute("SELECT * FROM incident WHERE id=? AND tenant_id=?", (incident_id, tenant_id)).fetchone()
    if r is None:
        raise IncidentError("không tìm thấy sự cố", 404)
    d = db.row(r, "evidence", "actions")
    d["stage"] = _shown_stage(d)
    d["stage_label"] = STAGE_LABEL.get(d["stage"], d["stage"])
    d["investigating"] = incident_id in _running
    d["queued"] = queued(incident_id)
    d["summary"] = summary_view(conn, r)
    d["merged_from"] = merged_from(conn, incident_id)
    d["alerts"] = [{**db.row(a, "labels"), "join_label": _method_label(a["join_method"] or "")} for a in conn.execute(
        "SELECT * FROM alert_event WHERE incident_id=? ORDER BY starts_at", (incident_id,)).fetchall()]
    d["timeline"] = timeline(conn, d, d["alerts"])
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
