"""Ghép một lượt hội thoại: lịch sử, tri thức theo lượt, số đo tri thức trong trace."""
import importlib.util
import json
import sqlite3
from pathlib import Path

from kagent import conversation, db

ROOT = Path(__file__).resolve().parent.parent


def _measure_module():
    spec = importlib.util.spec_from_file_location("measure_context", ROOT / "scripts" / "measure_context.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_turn_matches_assembled_context(users):
    alice = users["alice"]
    alice.run("xem pod trong namespace default")
    with db.session() as conn:
        history = {"messages": [{"role": "user", "content": "trước"}], "last_task": "xem pod", "intent": [], "calls": []}
        turn = conversation.build_turn(conn, alice.tenant, "xem log", "k8s_ops", history)
        ctx = conversation.assemble_context(conn, alice.tenant, "xem pod xem log", "k8s_ops")
    assert turn.stable == ctx["stable"] and turn.turn_context == ctx["turn"] and turn.ku_used == ctx["ku_used"]
    assert turn.history is history["messages"]
    assert turn.stats["knowledge_chars"] == len(ctx["turn"]) and turn.stats["skipped_chars"] == 0 and turn.stats["skipped_ids"] == []


def test_context_text_joins_stable_and_turn(users):
    with db.session() as conn:
        ctx = conversation.assemble_context(conn, users["alice"].tenant, "xem pod", "k8s_ops")
    assert ctx["text"] == "\n\n".join(p for p in (ctx["stable"], ctx["turn"]) if p)


def test_trace_records_knowledge_size(users):
    ep = users["alice"].run("xem pod trong namespace default")
    step = next(s for s in ep["trace"] if s["type"] == "context")
    assert {"knowledge_chars", "skipped_chars", "skipped_ids", "tokens_est", "has_core", "has_playbook"} <= step.keys()


def test_task_blocks_put_context_before_task():
    assert conversation.task_blocks("hỏi", "") == "hỏi"
    blocks = conversation.task_blocks("hỏi", "tri thức")
    assert blocks[0]["text"].startswith("<context") and "tri thức" in blocks[0]["text"] and blocks[1] == {"type": "text", "text": "hỏi"}


def test_measure_counts_knowledge_repeated_across_turns(tmp_path):
    path = tmp_path / "m.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE episode(conversation_id TEXT, transcript TEXT, started_at TEXT)")

    def turn(lines, task):
        ctx = conversation.task_blocks(task, "<knowledge section=\"units\">\n" + "\n".join(lines) + "\n</knowledge>")
        return json.dumps({"format": "anthropic", "messages": [{"role": "user", "content": ctx}, {"role": "assistant", "content": "ok"}]})

    conn.executemany("INSERT INTO episode VALUES (?,?,?)", [("c1", turn(["- [ku:aaaa] một", "- [ku:bbbb] hai"], "a"), "1"),
                                                            ("c1", turn(["- [ku:aaaa] một", "- [ku:cccc] ba"], "b"), "2"),
                                                            ("c2", None, "3")])
    conn.commit()
    convs = {c["conversation_id"]: c for c in _measure_module().measure(sqlite3.connect(f"file:{path}?mode=ro", uri=True))}
    c1 = convs["c1"]
    assert c1["turns"] == 2 and c1["repeated_chars"] == len("- [ku:aaaa] một")
    second = len("- [ku:aaaa] một") + len("- [ku:cccc] ba")
    assert [t["repeated_pct"] for t in c1["per_turn"]] == [0, round(100 * len("- [ku:aaaa] một") / second)]
    assert convs["c2"]["knowledge_chars"] == 0
