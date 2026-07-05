# Ported from soc_defender.
from smart_soc_agent.answer_gate import best_gated_answer, gate_answer
from smart_soc_agent.evidence_registry import EvidenceRegistry


def test_answer_gate_rejects_question_only_entity():
    registry = EvidenceRegistry()
    registry.seed_question("Context: host host-a is known. Question: Which host is involved?")

    decision = gate_answer("Answer: host-a", registry, question="Which host is involved?", entity_value="host-a")

    assert decision.approved is False
    assert "question" in decision.reason


def test_answer_gate_accepts_non_question_trusted_support():
    registry = EvidenceRegistry()
    registry.seed_question("Question: What IP address was involved?")
    registry.add_row({"RemoteIP": "198.51.100.77", "ActionType": "Suspicious alert"}, step_seen=2, source_table="AlertEvidence")

    decision = gate_answer("Answer: 198.51.100.77", registry, question="What IP address was involved?", entity_value="198.51.100.77")

    assert decision.approved is True


def test_best_gated_answer_caps_candidate_list_and_uses_requested_type():
    registry = EvidenceRegistry()
    registry.seed_question("Question: What IP address was involved?")
    for idx in range(12):
        registry.add_row({"RemoteIP": f"198.51.100.{idx}", "ActionType": "Suspicious alert"}, step_seen=idx + 1, source_table="AlertEvidence")

    answer, decision = best_gated_answer("Question: What IP address was involved?", registry)

    assert decision.approved is True
    assert answer is not None
    ranked_segment = answer.split(". Evidence:", 1)[0]
    assert ranked_segment.count("198.51.100.") <= 9
