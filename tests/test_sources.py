"""Nguồn tri thức ngoài episode: tài liệu tải lên và sự cố đã xử lý xong (sources.py)."""
import time

from kagent import db, knowledge, learning, lint, sources

DOC = """Giới thiệu chung về hệ thống.

# Khôi phục etcd
Chụp snapshot bằng etcdctl snapshot save trước khi đổi member.

## Kiểm tra dung lượng
Cảnh báo khi etcd_mvcc_db_total_size_in_bytes vượt 6GB thì chạy defrag từng member.

# Mục rỗng
"""


def _wait(user, doc_id):
    for _ in range(200):
        d = user.get(f"/api/knowledge/sources/{doc_id}").json()
        if d["status"] in ("done", "error"):
            return d
        time.sleep(0.05)
    raise AssertionError("đọc tài liệu không xong")


def test_chunks_follow_headings_and_split_long_sections():
    parts = sources.chunks("Runbook", DOC)
    assert [p["section"] for p in parts] == ["Runbook", "Khôi phục etcd", "Kiểm tra dung lượng"]
    long = "# Dài\n\n" + "\n\n".join("x" * 4000 for _ in range(3))
    assert [p["section"] for p in sources.chunks("t", long)] == ["Dài (phần 1)", "Dài (phần 2)", "Dài (phần 3)"]


def test_upload_creates_candidates_traced_to_sections(users):
    admin = users["admin"]
    r = admin.post("/api/knowledge/sources", json={"title": "Runbook etcd", "content": DOC})
    assert r.status_code == 200, r.text
    d = _wait(admin, r.json()["id"])
    assert d["status"] == "done" and len(d["chunks"]) == 3
    assert {k["title"]: k["sections"] for k in d["kus"]} == {"Runbook etcd": [1], "Khôi phục etcd": [2], "Kiểm tra dung lượng": [3]}
    ku = admin.get(f"/api/ku/{d['kus'][1]['id']}").json()
    assert ku["status"] == "candidate" and ku["source_trust"] == "internal_doc"
    assert ku["source_eps"] == [f"doc:{d['id']}#2"]
    assert ku["sources"] == [{"type": "doc", "id": d["id"], "section": 2, "title": "Runbook etcd"}]
    assert admin.get("/api/knowledge/sources").json()[0]["result"]["kus"] == 3


def test_admin_can_accept_on_upload_but_member_cannot(users):
    admin, alice = users["admin"], users["alice"]
    assert alice.post("/api/knowledge/sources", json={"title": "x", "content": "# a\nb", "activate": True}).status_code == 403
    d = _wait(admin, admin.post("/api/knowledge/sources", json={"title": "Runbook", "content": DOC, "activate": True}).json()["id"])
    assert {k["status"] for k in d["kus"]} == {"active"}


def test_limits(users):
    admin = users["admin"]
    many = "\n".join(f"# Mục {i}\nnội dung {i}" for i in range(sources.MAX_CHUNKS + 1))
    assert admin.post("/api/knowledge/sources", json={"title": "dài", "content": many}).status_code == 400


def test_sections_of_one_doc_count_as_one_source(users):
    tenant = users["admin"].tenant
    with db.session() as conn:
        ku = knowledge.add(conn, tenant, kind="fact", title="t", content="c", source_eps=["doc:abc#1", "doc:abc#2"], source_trust="internal_doc")
        learning.gate(conn, tenant)
        assert knowledge.get(conn, tenant, ku["id"])["status"] == "candidate"
        conn.execute("UPDATE knowledge_unit SET recorded_at=? WHERE id=?", (db.later(days=-30), ku["id"]))
        assert lint.expire_candidates(conn, tenant, 7) == []  # KU từ tài liệu tải lên không bị loại vì quá hạn
    assert knowledge.source_count(["e1", "doc:abc#1", "doc:abc#3", "doc:xyz#1"]) == 3


def _incident(conn, tenant, **kw):
    now, old = db.iso(), db.later(hours=-2)
    row = {"id": db.new_id(), "tenant_id": tenant, "env": "staging", "title": "Pod ImagePullBackOff", "status": "resolved", "created_at": old,
           "updated_at": old, "last_alert_at": old, "resolved_at": old, "cause": "Image không còn trên registry", "cause_at": now, "confidence": 0.8, **kw}
    conn.execute(f"INSERT INTO incident({','.join(row)}) VALUES ({','.join('?' * len(row))})", tuple(row.values()))
    return row


def test_resolved_incidents_become_sources_once(users):
    tenant = users["admin"].tenant
    with db.session() as conn:
        inc = _incident(conn, tenant)
        _incident(conn, tenant, confidence=0.2)  # nguyên nhân chưa đủ tin
        _incident(conn, tenant, status="open")
        _incident(conn, tenant, updated_at=db.iso())  # chưa yên đủ lâu
        conn.execute("INSERT INTO incident_action(id,tenant_id,incident_id,origin,requested_by,tool,args,status,proposed_at,ran_at,result_line,verified) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (db.new_id(), tenant, inc["id"], "chat", "alice", "k8s.kubectl_admin", '{"command": "rollout undo deploy/web"}', "ok", db.iso(), db.iso(), "rolled back", 1))
        assert sources.queue_incidents(conn, tenant) == 1
        assert sources.queue_incidents(conn, tenant) == 0
        doc = conn.execute("SELECT * FROM source_doc WHERE tenant_id=? AND kind='incident'", (tenant,)).fetchone()
        assert doc["ref"] == f"{inc['id']}@{inc['cause_at']}" and doc["trust"] == "verified_tool"
        assert "Image không còn trên registry" in doc["content"] and "rollout undo deploy/web" in doc["content"] and "đạt" in doc["content"]
        sources.tick(conn, tenant)
        assert sources.get(conn, tenant, doc["id"])["status"] == "done"
        assert sources.kus_of(conn, tenant, doc["id"])
        # Mở lại rồi có nguyên nhân mới: thêm một nguồn mới, nguồn cũ giữ nguyên.
        conn.execute("UPDATE incident SET cause_at=? WHERE id=?", (db.later(seconds=5), inc["id"]))
        assert sources.queue_incidents(conn, tenant) == 1
