# Ported from soc_defender.
from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.llm import StaticJSONLLMClient


def test_agentic_graph_rejects_unsafe_llm_sql_and_falls_back():
    llm = StaticJSONLLMClient({"intent_type": "query_logs", "sql": "DROP TABLE AlertEvidence"})
    agent = SmartSocAgent(max_steps=5, mode="agentic", llm=llm, rag_enabled=False)

    action, submit = agent.act("Question: What IP address was involved?")

    assert submit is False
    assert action == "SHOW TABLES"
    trace = agent.get_logging()["action_trace"][-1]
    assert trace["graph_traces"]


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
