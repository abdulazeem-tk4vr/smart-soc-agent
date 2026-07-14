# Ported from soc_defender.
from smart_soc_agent.agent import SmartSocAgent, build_agent


def test_agent_matches_secrl_action_contract():
    agent = SmartSocAgent(max_steps=5)

    action, submit = agent.act("Context: host h-001 alerted.\nQuestion: Which user?")

    assert action == "SHOW TABLES"
    assert submit is False
    assert agent.name == "SmartSocAgent"
    assert agent.max_steps == 10


def test_fixed_steps_are_configurable_and_can_be_disabled():
    configured = SmartSocAgent(max_steps=25, fixed_steps=7)
    disabled = SmartSocAgent(max_steps=25, fixed_steps_enabled=False)

    assert configured.max_steps == 7
    assert disabled.max_steps == 25


def test_agent_discovers_alert_tables_and_does_not_repeat_probe():
    agent = SmartSocAgent(max_steps=6, fixed_steps_enabled=False)
    agent.act("Question?")
    action, submit = agent.act("[('AlertEvidence',), ('SecurityAlert',)]")

    assert action == "DESCRIBE AlertEvidence"
    assert submit is False

    agent.act("[]")
    action, submit = agent.act("[]")

    assert action in {"SELECT * FROM AlertEvidence LIMIT 15", "SELECT * FROM SecurityAlert LIMIT 15"}
    assert submit is False

    next_action, submit = agent.act("[]")
    assert submit is False
    assert next_action != action

    action, submit = agent.act("[]")
    assert submit is True
    assert "not have enough grounded database evidence" in action


def test_agent_submits_before_budget_and_logs():
    agent = SmartSocAgent(max_steps=1, fixed_steps_enabled=False)
    action, submit = agent.act("Question?")

    assert submit is True
    assert "not have enough grounded database evidence" in action
    assert agent.get_logging()["action_trace"]


def test_build_agent_returns_smart_soc_agent_and_reset_keeps_schema_cache():
    agent = build_agent(max_steps=3, layer="alert")
    agent.act("Question?")
    agent.act("[('AlertEvidence',)]")

    assert "AlertEvidence" in agent.table_names
    agent.reset()
    assert "AlertEvidence" in agent.table_names
    assert agent.step_count == 0


def test_failed_describe_is_not_repeated():
    agent = SmartSocAgent(max_steps=5)
    agent.act("Question?")
    agent.act("[('Usage',)]")
    action, submit = agent.act("ProgrammingError: None")

    assert submit is True
    assert action != "DESCRIBE Usage"


def test_agent_submits_early_when_requested_entity_is_supported():
    agent = SmartSocAgent(max_steps=25)
    agent.act("What is the IP address associated with this incident?")
    agent.act("[('AlertEvidence',)]")
    agent.act("[('Entity', 'text', 'YES', '', None, '')]")
    action, submit = agent.act("[('198.43.121.209',)]")

    assert submit is True
    assert "198.43.121.209" in action
    assert agent.step_count < 25
