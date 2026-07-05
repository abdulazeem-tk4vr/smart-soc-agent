from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.rag.rag import LocalKeywordRAGRetriever, RAGDocument, RAGIntel, build_rag_intel, default_rag_data_dir
from smart_soc_agent.rag.rag_query import RAGQueryPlanner


def test_rag_query_planner_uses_question_answer_gaps():
    agent = SmartSocAgent()
    agent.question = "Question: What IP address was involved?"
    plan = RAGQueryPlanner().plan(question=agent.question, registry=agent.registry, known_entities=agent._known_entities())

    assert "IP address" in plan.query or "IP" in plan.query
    assert "select " not in plan.query.lower()


def test_default_rag_data_dir_finds_packaged_corpus():
    data_dir = default_rag_data_dir()

    assert data_dir is not None
    assert (data_dir / "chunks.jsonl").exists()


def test_agentic_graph_calls_rag_once_and_caches_context():
    rag = RAGIntel(LocalKeywordRAGRetriever((RAGDocument("test", "IP evidence", "IP address alert investigation"),)))
    agent = SmartSocAgent(max_steps=6, mode="agentic", rag_intel=rag)

    agent.act("Question: What IP address was involved?")
    action, submit = agent.act("[('AlertEvidence',)]")
    first_trace = agent.get_logging()["action_trace"][-1]

    assert submit is False
    assert action == "DESCRIBE AlertEvidence"
    assert agent.rag_called is True
    assert agent.rag_context_cache
    assert any(item["node"] == "rag" for item in first_trace["graph_traces"])

    agent.act("[('RemoteIP', 'varchar(64)', 'YES', '', None, '')]")
    second_trace = agent.get_logging()["action_trace"][-1]
    rag_trace = next(item for item in second_trace["graph_traces"] if item["node"] == "rag")
    assert rag_trace["output_summary"]["cache_hit"] is True


def test_build_rag_intel_keyword_backend_uses_local_chunks():
    rag = build_rag_intel(backend="keyword")
    docs = rag.context_for("phishing credential", limit=1)

    assert len(docs) <= 1
