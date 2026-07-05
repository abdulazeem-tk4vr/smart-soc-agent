# Ported from soc_defender.
from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.llm import StaticJSONLLMClient


def test_agentic_graph_warms_schema_before_llm():
    llm = StaticJSONLLMClient({"intent_type": "query_logs", "sql": "SELECT nonexistent FROM AlertEvidence"})
    agent = SmartSocAgent(max_steps=8, mode="agentic", llm=llm, rag_enabled=False)

    action, submit = agent.act("Question: What IP address was involved?")

    assert (action, submit) == ("SHOW TABLES", False)
    assert agent.get_logging()["action_trace"][-1]["reason"] == "schema warmup"

    action, submit = agent.act("[('AlertEvidence',)]")
    assert (action, submit) == ("DESCRIBE AlertEvidence", False)


def test_agentic_graph_rejects_unsafe_llm_sql_and_falls_back():
    llm = StaticJSONLLMClient({"intent_type": "query_logs", "sql": "DROP TABLE AlertEvidence"})
    agent = SmartSocAgent(max_steps=8, mode="agentic", llm=llm, rag_enabled=False)

    agent.act("Question: What IP address was involved?")
    agent.act("[('AlertEvidence',)]")
    action, submit = agent.act("[('RemoteIP', 'varchar(64)', 'YES', '', None, '')]")

    assert submit is False
    assert action == "SELECT * FROM AlertEvidence LIMIT 15"
    trace = agent.get_logging()["action_trace"][-1]
    assert trace["graph_traces"]


def test_agentic_graph_rejects_unknown_column_sql():
    llm = StaticJSONLLMClient({"intent_type": "query_logs", "sql": "SELECT ip_address FROM AlertEvidence WHERE host = 'x'"})
    agent = SmartSocAgent(max_steps=8, mode="agentic", llm=llm, rag_enabled=False)

    agent.act("Question: What IP address was involved?")
    agent.act("[('AlertEvidence',)]")
    action, submit = agent.act("[('RemoteIP', 'varchar(64)', 'YES', '', None, '')]")

    assert submit is False
    assert "ip_address" not in action
    trace = agent.get_logging()["action_trace"][-1]
    grounding = [item for item in trace["graph_traces"] if item["node"] == "grounding"]
    assert grounding
    assert "unknown column(s)" in grounding[0]["output_summary"]["reason"]
    assert "RemoteIP" in grounding[0]["output_summary"]["reason"]


def test_agentic_graph_gates_supported_submit_answer():
    llm = StaticJSONLLMClient(
        {
            "intent_type": "submit_answer",
            "answer": "Answer: 198.51.100.77. Evidence: AlertEvidence RemoteIP.",
            "entity_value": "198.51.100.77",
            "confidence": 0.9,
        }
    )
    agent = SmartSocAgent(max_steps=10, mode="agentic", llm=llm, rag_enabled=False)
    agent.act("Question: What IP address was involved?")
    agent.act("[('AlertEvidence',)]")
    agent.act("[('RemoteIP', 'varchar(64)', 'YES', '', None, '')]")
    action, submit = agent.act("[('198.51.100.77',)]")

    assert submit is True
    assert "198.51.100.77" in action
    assert agent.get_logging()["action_trace"][-1]["gate_decision"]["approved"] is True
