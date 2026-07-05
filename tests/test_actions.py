# Ported from soc_defender.
from smart_soc_agent.actions import add_limit, projected_columns, validate_sql


def test_validate_read_only_sql_and_adds_limit():
    validation = validate_sql("SELECT AccountUpn, DeviceName FROM AlertEvidence")

    assert validation.ok
    assert validation.sql.endswith("LIMIT 15")
    assert validation.columns == ("AccountUpn", "DeviceName")


def test_rejects_mutating_and_multi_statement_sql():
    assert not validate_sql("SELECT * FROM AlertEvidence; DROP TABLE AlertEvidence").ok
    assert not validate_sql("DELETE FROM AlertEvidence").ok


def test_allows_schema_discovery_without_limit():
    validation = validate_sql("SHOW TABLES")

    assert validation.ok
    assert validation.sql == "SHOW TABLES"


def test_projected_columns_handles_aliases():
    assert projected_columns("SELECT AccountUpn AS account, DeviceName FROM AlertEvidence LIMIT 15") == (
        "account",
        "DeviceName",
    )
    assert add_limit("SELECT * FROM SecurityAlert LIMIT 3") == "SELECT * FROM SecurityAlert LIMIT 3"
