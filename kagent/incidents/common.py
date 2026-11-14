"""Hằng số, trạng thái trong tiến trình và hàm nhỏ dùng chung của các module sự cố."""
from __future__ import annotations

import json
import threading
from datetime import timedelta

from .. import db

SOURCE_TEMPLATES = ("alertmanager", "prometheus")
STAGES = ("new", "investigating", "reported", "awaiting_approval", "verifying", "handled", "needs_human", "error")
SEVERITY = {"critical": 4, "error": 3, "high": 3, "warning": 2, "medium": 2, "info": 1, "low": 1}
BOT = "kagent-alerts"


class IncidentError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


_state: dict[str, dict] = {}  # tenant → {"last_poll": giây, "sources": {tên: {"at", "count", "error"}}}
_running: set[str] = set()
_waiting: set[str] = set()  # trong _running nhưng chưa có chỗ trong _slots
_lock = threading.Lock()
_slots = threading.Semaphore(2)  # tối đa 2 lượt điều tra cùng lúc trong cả tiến trình
_summarizing: set[str] = set()
_summary_failed: dict[str, str] = {}  # sự cố → mốc hoạt động đã tóm tắt lỗi: không thử lại tới khi có hoạt động mới


def _method_label(method: str) -> str:
    return {"rule": "luật nhãn", "topology": "quan hệ k8s", "ai": "AI", "manual": "người gộp", "root": "gốc"}.get(method, method)


def _worse(a: str | None, b: str | None) -> str | None:
    return max((a, b), key=lambda s: SEVERITY.get(s or "", 0)) if a or b else None


def _later(seconds: int) -> str:
    return (db.now() + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _event(conn, tenant_id: str, incident_id: str, kind: str, text: str, data: dict | None = None) -> None:
    conn.execute("INSERT INTO incident_event(tenant_id,incident_id,at,kind,text,data) VALUES (?,?,?,?,?,?)",
                 (tenant_id, incident_id, db.iso(), kind, text[:1000], json.dumps(data, ensure_ascii=False) if data else None))


STAGE_LABEL = {"new": "mới", "investigating": "đang điều tra", "reported": "đã báo cáo, cần người xem", "awaiting_approval": "chờ duyệt",
               "verifying": "đang xác minh", "handled": "đã xử lý", "needs_human": "cần người xử lý", "error": "lỗi",
               "cleared": "cảnh báo đã hết", "closed": "đã đóng"}
WAITING_ON_HUMAN = ("new", "reported", "needs_human", "error")


def _shown_stage(d: dict) -> str:
    """Sự cố không còn mở thì không còn chờ ai. Tính lúc đọc vì stage còn bị ghi sau khi hết cảnh báo (điều tra đang chạy, lệnh bị từ chối)."""
    if d["status"] != "open" and d["stage"] in WAITING_ON_HUMAN:
        return "cleared" if d["status"] == "resolved" else "closed"
    return d["stage"]


def _cmd(step: dict) -> str:
    args = step.get("args") or {}
    return f"{step['tool'].split('.')[-1]} {args['command']}" if isinstance(args.get("command"), str) else f"{step['tool']} {json.dumps(args, ensure_ascii=False)}"


def _is_write(conn, tenant_id: str, tool: str) -> bool:
    r = conn.execute("SELECT action_class FROM tool_registry WHERE tenant_id=? AND tool=?", (tenant_id, tool)).fetchone()
    return bool(r and r["action_class"] != "read")
