# Ported from soc_defender.
from smart_soc_agent.schema_cache import SchemaCache


def test_schema_cache_records_tables_and_describe_rows():
    cache = SchemaCache()
    cache.record_tables((("AlertEvidence",), ("SecurityAlert",)))
    cache.record_describe(
        "AlertEvidence",
        (
            ("AlertId", "varchar(64)", "YES", "", None, ""),
            ("EntityType", "text", "YES", "", None, ""),
        ),
    )

    assert cache.has_table("alertevidence")
    assert cache.columns_for("AlertEvidence") == ("AlertId", "EntityType")
    assert cache.undescribed_preferred(("AlertEvidence", "SecurityAlert")) == "SecurityAlert"


def test_schema_cache_resets_only_when_incident_changes():
    cache = SchemaCache()
    cache.reset_for_incident("incident_5")
    cache.record_tables((("AlertEvidence",),))
    cache.reset_for_incident("incident_5")
    assert cache.has_table("AlertEvidence")

    cache.reset_for_incident("incident_38")
    assert not cache.table_names()
