# Ported from soc_defender.
from smart_soc_agent.evidence_registry import EvidenceRegistry


def test_question_seeding_extracts_excytin_entities():
    registry = EvidenceRegistry()
    registry.seed_question(
        "Device vnevado-win11u with IP address 99.83.111.100 launched curl http://vectorsandarrows.com."
    )

    assert registry.support_for("99.83.111.100", "ip")
    assert registry.support_for("http://vectorsandarrows.com", "url")


def test_row_extraction_uses_source_table_and_field_hints():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "AccountUpn": "alice@example.com",
            "DeviceName": "vnevado-win10r",
            "RemoteIP": "198.43.121.209",
            "ProcessCommandLine": "cmd.exe /c whoami",
        },
        step_seen=3,
        source_table="AlertEvidence",
    )

    assert registry.support_for("alice@example.com", "account")[0].source_table == "AlertEvidence"
    assert registry.support_for("198.43.121.209", "ip")
    assert registry.support_for("cmd.exe", "file")


def test_process_names_are_not_domains():
    registry = EvidenceRegistry()
    registry.add_row({"ProcessCommandLine": "rundll32.exe malware.dll"}, step_seen=1, source_table="DeviceProcessEvents")

    assert not registry.support_for("rundll32.exe", "domain")
    assert registry.support_for("rundll32.exe", "file")
