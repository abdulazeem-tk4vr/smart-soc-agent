# Ported from soc_defender.
from smart_soc_agent.budget import budget_state


def test_budget_phases_follow_documented_step_bands():
    assert budget_state(2, 15, 14, 5).phase == "investigate_first"
    assert budget_state(6, 15, 14, 5).phase == "targeted_query"
    assert budget_state(12, 15, 14, 5).phase == "answer_fill"


def test_budget_answer_fill_priority_only_near_deadline():
    early = budget_state(4, 15, 14, 5)
    middle = budget_state(6, 15, 14, 5)
    late = budget_state(13, 15, 14, 5)

    assert early.answer_fill_priority is False
    assert middle.answer_fill_priority is False
    assert late.answer_fill_priority is True
