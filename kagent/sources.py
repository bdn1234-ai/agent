"""Nguồn tri thức ngoài episode: tài liệu người dùng tải lên và bản ghi sự cố đã xử lý xong.

Nguyên bản giữ trong source_doc. Mỗi đoạn (theo tiêu đề markdown) được LLM tách thành KU rồi đi qua đúng Curator và cổng duyệt
như KU học từ episode; source_eps của KU ghi "doc:<id>#<số đoạn>" để truy ngược về đúng đoạn nguồn.
"""
from __future__ import annotations

import json
import logging
import re
import threading

from . import db, entities, knowledge, learning, llm
from .config import settings

log = logging.getLogger("kagent.sources")

KINDS = ("doc", "incident")
MAX_CHARS = 200_000
MAX_CHUNK = 6000
MAX_CHUNKS = 40  # mỗi đoạn một lần gọi model mạnh; tài liệu dài hơn thì tách file
MIN_INCIDENT_CONFIDENCE = 0.5
INCIDENT_QUIET_MINUTES = 30  # để bản tóm tắt sự cố kịp viết lại sau khi yên
INGEST_PER_TICK = 3
DOC_ITEMS, INCIDENT_ITEMS = 6, 3  # số KU tối đa mỗi đoạn
_HEADING = re.compile(r"^(#{1,3})[ \t]+(.+?)[ \t#]*$", re.M)
_running: set[str] = set()
_running_lock = threading.Lock()


class SourceError(Exception):
    pass


def chunks(title: str, text: str) -> list[dict]:
    """Cắt theo tiêu đề cấp 1-3; mục dài quá MAX_CHUNK thì tách theo đoạn văn, giữ tiêu đề mục."""
    marks = list(_HEADING.finditer(text))
    sections = []
    if not marks or marks[0].start() > 0:
        sections.append((title, text[:marks[0].start()] if marks else text))
    for i, m in enumerate(marks):
        sections.append((m.group(2).strip(), text[m.end():marks[i + 1].start() if i + 1 < len(marks) else len(text)]))
    out = []
    for heading, body in sections:
        body = body.strip()
        if not body:
            continue
        part, parts = "", []
        for para in re.split(r"\n\s*\n", body):
            if part and len(part) + len(para) > MAX_CHUNK:
                parts.append(part)
                part = ""
            part = f"{part}\n\n{para}" if part else para[:MAX_CHUNK]
        parts.append(part)
        for k, p in enumerate(parts, 1):
            out.append({"section": heading if len(parts) == 1 else f"{heading} (phần {k})", "text": p})
    return out


def add(conn, tenant_id: str, *, title: str, content: str, kind: str = "doc", trust: str = "internal_doc", ref: str | None = None,
        created_by: str | None = None, user_id: str | None = None, activate: bool = False) -> dict:
    title, content = knowledge.scrub(title.strip())[:200], knowledge.scrub(content)
    if kind not in KINDS:
        raise SourceError("loại nguồn không hợp lệ")
    if not title or not content.strip():
        raise SourceError("tài liệu cần tiêu đề và nội dung")
    if len(content) > MAX_CHARS:
        raise SourceError(f"tài liệu dài quá {MAX_CHARS:,} ký tự, hãy tách thành nhiều file")
    n = len(chunks(title, content))
    if n > MAX_CHUNKS:
        raise SourceError(f"tài liệu có {n} đoạn, tối đa {MAX_CHUNKS}; hãy tách thành nhiều file")
    doc_id = db.new_id()
    conn.execute("INSERT INTO source_doc(id,tenant_id,kind,title,content,trust,ref,created_by,user_id,activate,status,created_at) "
                 "VALUES (?,?,?,?,?,?,?,?,?,?,'pending',?)",
                 (doc_id, tenant_id, kind, title, content, trust, ref, created_by, user_id, int(activate), db.iso()))
    return get(conn, tenant_id, doc_id)


def get(conn, tenant_id: str, doc_id: str) -> dict | None:
    return db.row(conn.execute("SELECT * FROM source_doc WHERE id=? AND tenant_id=?", (doc_id, tenant_id)).fetchone(), "result")


def kus_of(conn, tenant_id: str, doc_id: str) -> list[dict]:
    rs = conn.execute("SELECT k.id, k.kind, k.title, k.status, group_concat(e.value) srcs FROM knowledge_unit k, json_each(k.source_eps) e "
                      "WHERE k.tenant_id=? AND e.value LIKE ? GROUP BY k.id ORDER BY k.recorded_at DESC", (tenant_id, f"doc:{doc_id}#%")).fetchall()
    return [{"id": r["id"], "kind": r["kind"], "title": r["title"], "status": r["status"],
             "sections": sorted({int(s.rsplit("#", 1)[1]) for s in r["srcs"].split(",")})} for r in rs]


def resolve(conn, tenant_id: str, source_eps: list[str]) -> list[dict]:
    """Nguồn của một KU cho màn xem: episode hoặc tài liệu kèm đoạn."""
    docs = {}
    out = []
    for e in source_eps:
        if not e.startswith("doc:"):
            out.append({"type": "episode", "id": e})
            continue
        doc_id, _, n = e[4:].partition("#")
        if doc_id not in docs:
            r = conn.execute("SELECT kind, title FROM source_doc WHERE id=? AND tenant_id=?", (doc_id, tenant_id)).fetchone()
            docs[doc_id] = dict(r) if r else None
        d = docs[doc_id]
        out.append({"type": d["kind"] if d else "doc", "id": doc_id, "section": int(n) if n.isdigit() else None,
                    "title": d["title"] if d else "(tài liệu không còn)"})
    return out


def _claim(conn, tenant_id: str, doc_id: str) -> bool:
    return conn.execute("UPDATE source_doc SET status='running' WHERE id=? AND tenant_id=? AND status='pending'", (doc_id, tenant_id)).rowcount == 1


def ingest(conn, tenant_id: str, doc_id: str, provider=None) -> dict:
    """Tách KU từ từng đoạn; đoạn lỗi không chặn các đoạn khác. Gọi sau _claim."""
    provider = provider or llm.get_provider()
    doc = get(conn, tenant_id, doc_id)
    ops: dict[str, int] = {}
    errors, titles = [], []
    known = entities.top(conn, tenant_id)
    # Bản ghi sự cố là một ca liền mạch: đọc riêng từng mục (cảnh báo, nguyên nhân, lệnh) thì các KU lặp ý nhau.
    parts = [{"section": doc["title"], "text": doc["content"][:MAX_CHUNK * 2]}] if doc["kind"] == "incident" else chunks(doc["title"], doc["content"])
    max_items = INCIDENT_ITEMS if doc["kind"] == "incident" else DOC_ITEMS
    with llm.collect_usage(tenant_id) as usage:
        try:
            for n, part in enumerate(parts, 1):
                source = {"kind": doc["kind"], "doc_title": doc["title"], "section": part["section"], "text": part["text"],
                          "max_items": max_items, "known_entities": known, "known_titles": titles[-40:]}
                try:
                    items = provider.extract(source)[:max_items]
                except llm.LLMError as exc:
                    errors.append(f"đoạn {n} ({part['section'][:60]}): {exc}")
                    continue
                for item in items:
                    origin = {"id": f"doc:{doc_id}#{n}", "user_id": doc["user_id"], "scope": "tenant", "task_type": item["domain"]}
                    op = learning.curate_item(conn, tenant_id, provider, {**item, "scope": "tenant"}, origin, doc["trust"])
                    ops[op] = ops.get(op, 0) + 1
                    titles.append(item["title"])
        finally:
            if usage:
                llm.save_usage(conn, tenant_id, None, usage)
    kus = kus_of(conn, tenant_id, doc_id)
    if doc["activate"]:
        # Người tải lên là admin và đã chọn chấp nhận luôn: họ đứng ra bảo đảm cho tài liệu này.
        for ku in kus:
            if ku["status"] == "candidate":
                knowledge.promote(conn, tenant_id, ku["id"], doc["created_by"] or "admin", f"tài liệu \"{doc['title'][:80]}\" được chấp nhận khi tải lên")
        kus = kus_of(conn, tenant_id, doc_id)
    status = "error" if errors and len(errors) == len(parts) else "done"
    result = {"chunks": len(parts), "ops": ops, "errors": errors, "kus": len(kus)}
    conn.execute("UPDATE source_doc SET status=?, result=?, done_at=? WHERE id=?", (status, json.dumps(result, ensure_ascii=False), db.iso(), doc_id))
    return {**get(conn, tenant_id, doc_id), "kus": kus}


def _run(tenant_id: str, doc_id: str) -> None:
    try:
        with db.session() as conn:
            if _claim(conn, tenant_id, doc_id):
                ingest(conn, tenant_id, doc_id)
    except Exception as exc:
        log.exception("không đọc được tài liệu %s", doc_id)
        with db.session() as conn:
            conn.execute("UPDATE source_doc SET status='error', result=?, done_at=? WHERE id=?",
                         (json.dumps({"errors": [str(exc)[:300]]}, ensure_ascii=False), db.iso(), doc_id))
    finally:
        with _running_lock:
            _running.discard(doc_id)


def start(tenant_id: str, doc_id: str) -> None:
    with _running_lock:
        if doc_id in _running:
            return
        _running.add(doc_id)
    threading.Thread(target=_run, args=(tenant_id, doc_id), name=f"ingest-{doc_id[:8]}", daemon=True).start()


def resume(conn) -> None:
    """Server khởi động lại giữa chừng: đọc lại từ đầu; Curator gặp KU đã thêm thì coi là trùng."""
    conn.execute("UPDATE source_doc SET status='pending' WHERE status='running'")


def _untrusted(conn, inc) -> bool:
    rs = conn.execute("SELECT trace FROM episode WHERE tenant_id=? AND (id=? OR (conversation_id IS NOT NULL AND conversation_id=?))",
                      (inc["tenant_id"], inc["episode_id"], inc["conversation_id"])).fetchall()
    for r in rs:
        trace = json.loads(r["trace"] or "[]", parse_constant=lambda _: None)
        if any(isinstance(s, dict) and s.get("untrusted") for s in trace):
            return True
    return False


def incident_text(conn, inc) -> str:
    cause = inc["cause"] or inc["root_cause"]
    lines = [f"Môi trường: {inc['env']}. Mức độ: {inc['severity'] or 'không rõ'}. Từ {inc['created_at']} tới {inc['resolved_at'] or inc['updated_at']}."]
    alerts = conn.execute("SELECT alertname, max(summary) summary, count(*) n FROM alert_event WHERE incident_id=? GROUP BY alertname", (inc["id"],)).fetchall()
    if alerts:
        lines += ["", "## Cảnh báo", *[f"- {a['alertname']} ({a['n']} lần): {a['summary'] or ''}" for a in alerts]]
    lines += ["", "## Nguyên nhân", f"{cause} (độ tin {inc['confidence'] or 0:.2f})"]
    if inc["summary"]:
        lines += ["", "## Tóm tắt", inc["summary"]]
    ran = conn.execute("SELECT tool, args, why, result_line, verified FROM incident_action WHERE incident_id=? AND status='ok' ORDER BY ran_at", (inc["id"],)).fetchall()
    if ran:
        lines += ["", "## Lệnh khắc phục đã chạy"]
        for a in ran:
            check = {1: "kiểm tra sau khi chạy: đạt", 0: "kiểm tra sau khi chạy: không đạt"}.get(a["verified"], "")
            lines.append(f"- {a['tool']} {a['args'] or ''}{' — ' + a['why'] if a['why'] else ''}. Kết quả: {a['result_line'] or 'ok'}. {check}".strip())
    done = conn.execute("SELECT text FROM incident_task WHERE incident_id=? AND done_at IS NOT NULL", (inc["id"],)).fetchall()
    if done:
        lines += ["", "## Việc người vận hành đã làm", *[f"- {t['text']}" for t in done]]
    return "\n".join(lines)


def queue_incidents(conn, tenant_id: str, limit: int = 5) -> int:
    """Sự cố đã hết, có nguyên nhân đủ tin và đã yên một lúc thì thành một nguồn; mở lại rồi có nguyên nhân mới thì thành nguồn mới."""
    rs = conn.execute(
        "SELECT * FROM incident i WHERE tenant_id=? AND status IN ('resolved','closed') AND coalesce(cause, root_cause, '')!='' "
        "AND coalesce(confidence, 0) >= ? AND updated_at < ? "
        "AND NOT EXISTS (SELECT 1 FROM incident_event v WHERE v.incident_id=i.id AND v.kind='merged') "
        "AND NOT EXISTS (SELECT 1 FROM source_doc d WHERE d.tenant_id=i.tenant_id AND d.kind='incident' AND d.ref=i.id || '@' || coalesce(i.cause_at, '')) "
        "ORDER BY updated_at LIMIT ?",
        (tenant_id, MIN_INCIDENT_CONFIDENCE, db.later(minutes=-INCIDENT_QUIET_MINUTES), limit)).fetchall()
    for inc in rs:
        add(conn, tenant_id, title=f"Sự cố: {inc['title']}", content=incident_text(conn, inc), kind="incident",
            trust="external_untrusted" if _untrusted(conn, inc) else "verified_tool", ref=f"{inc['id']}@{inc['cause_at'] or ''}", created_by="incident")
    return len(rs)


def tick(conn, tenant_id: str) -> None:
    if settings.incident_learn:
        queue_incidents(conn, tenant_id)
    for r in conn.execute("SELECT id FROM source_doc WHERE tenant_id=? AND status='pending' ORDER BY created_at LIMIT ?", (tenant_id, INGEST_PER_TICK)).fetchall():
        if r["id"] in _running or not _claim(conn, tenant_id, r["id"]):
            continue
        try:
            ingest(conn, tenant_id, r["id"])
        except Exception as exc:
            log.exception("không đọc được nguồn %s", r["id"])
            conn.execute("UPDATE source_doc SET status='error', result=?, done_at=? WHERE id=?",
                         (json.dumps({"errors": [str(exc)[:300]]}, ensure_ascii=False), db.iso(), r["id"]))
