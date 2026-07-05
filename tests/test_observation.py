# Ported from soc_defender.
from smart_soc_agent.observation import parse_observation


def test_parse_initial_question_as_question():
    parsed = parse_observation("Context: host h-001 was alerted.\nQuestion: Which account was involved?")

    assert parsed.kind == "question"
    assert parsed.question.startswith("Context:")


def test_parse_tuple_rows_with_projected_columns():
    parsed = parse_observation("[('alice@example.com', 'host-1')]", columns=("AccountUpn", "DeviceName"))

    assert parsed.kind == "rows"
    assert parsed.rows[0]["AccountUpn"] == "alice@example.com"
    assert parsed.rows[0]["DeviceName"] == "host-1"


def test_parse_truncated_prefix_and_error():
    parsed = parse_observation("Retrieved 42 entries. Displaying first 15 entries.\n[('a',)]")
    error = parse_observation("ProgrammingError: None")

    assert parsed.retrieved_count == 42
    assert parsed.displayed_count == 15
    assert error.kind == "error"
    assert error.failed
