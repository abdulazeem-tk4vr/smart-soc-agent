# Regression tests for the remote_agent_live 0-reward runs: the deadline
# submission must salvage registry evidence instead of giving up, and
# question stopwords must not become planner entities.
from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.answer_gate import best_effort_answer


QUESTION = (
    "Question: A command and control behavior was blocked on host `vnevado-win10r`. "
    "What is the IP address associated with the Manatee Tempest activity group?"
)


def _agent_with_evidence(max_steps: int = 3) -> SmartSocAgent:
    agent = SmartSocAgent(max_steps=max_steps, mode="deterministic")
    agent.question = QUESTION
    agent.registry.seed_question(QUESTION)
    agent.question_seeded = True
    agent.registry.add_row(
        {
            "Title": "Manatee Tempest activity group",
            "RemoteIP": "198.43.121.209",
            "RemoteUrl": "vectorsandarrows.com",
        },
        step_seen=1,
        source_table="AlertEvidence",
    )
    return agent

def test_deadline_submission_contains_registry_ip_not_boilerplate():
    agent = _agent_with_evidence(max_steps=1)
    action, submit = agent.act("[]")

    assert submit is True
    assert "198.43.121.209" in action
    assert "not have enough grounded database evidence" not in action


def test_deadline_boilerplate_only_when_registry_is_empty():
    agent = SmartSocAgent(max_steps=1, mode="deterministic")
    action, submit = agent.act(QUESTION)

    assert submit is True
    assert "budget deadline reached" in action


def test_best_effort_answer_excludes_question_only_entities():
    agent = SmartSocAgent()
    agent.registry.seed_question(QUESTION)
    answer = best_effort_answer(QUESTION, agent.registry)

    assert answer is None


def test_question_name_phrases_seed_planner_pivots():
    agent = SmartSocAgent(mode="deterministic")
    agent.registry.seed_question(QUESTION)
    names = agent.registry.best_entities("name")

    assert "Manatee Tempest" in names
    assert "vnevado-win10r" in names


def test_question_stopwords_do_not_become_entities():
    agent = SmartSocAgent()
    agent.registry.seed_question("A command and control behavior was blocked on host `vnevado-win10r`.")
    values = {support.entity_value.lower() for support in agent.registry.supports}

    assert "and" not in values
    assert "command" not in values
    assert "was" not in values
    assert any("vnevado-win10r" == value for value in values)
