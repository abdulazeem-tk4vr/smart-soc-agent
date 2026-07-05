# Ported from soc_defender.
from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

import yaml

from .scanner import InjectionScanner


MALICIOUS_WORDS = {
    "alert",
    "blocked",
    "command",
    "compromise",
    "credential",
    "exfil",
    "failed",
    "malware",
    "payload",
    "phish",
    "ransomware",
    "suspicious",
}
ENTITY_PATTERN_RESOURCE = "entity_patterns.yaml"
PROCESS_LIKE_RE = re.compile(r"^[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|js|vbs|lnk)$", re.IGNORECASE)
STOPWORD_VALUES = frozenset(
    """a an and are as at be been but by can could did for from had has have how in into is it its
    may might must not of on or ran should that the this to via was were what when where which who
    why will with would command control behavior process host device account alert alerts incident
    incidents malware attacker attackers infection activity evidence measures signs remote active
    blocked involved detected indicated precautionary residual security malicious suspicious
    check known group id address""".split()
)


@dataclass(frozen=True)
class EntitySupport:
    entity_value: str
    entity_type: str
    evidence_id: str
    source_table: str
    trust_tier: str | None
    source: str | None
    injection_id: str | None
    content_exposed: bool
    step_seen: int
    supporting_fields: tuple[str, ...] = ()
    malicious_indicators: tuple[str, ...] = ()
    scanner_status: str = "unknown"
    localized_spans: tuple[Any, ...] = ()

    @property
    def trusted(self) -> bool:
        return self.trust_tier != "untrusted" and not self.injection_id


@dataclass(frozen=True)
class EntityPatternConfig:
    patterns: dict[str, tuple[re.Pattern[str], ...]]
    field_hints: dict[str, frozenset[str]]


def load_entity_patterns() -> EntityPatternConfig:
    with resources.files("smart_soc_agent.configs").joinpath(ENTITY_PATTERN_RESOURCE).open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    patterns = {
        entity_type: tuple(re.compile(pattern, re.IGNORECASE) for pattern in raw_patterns)
        for entity_type, raw_patterns in (data.get("patterns") or {}).items()
    }
    field_hints = {
        entity_type: frozenset(str(item).lower() for item in values)
        for entity_type, values in (data.get("field_hints") or {}).items()
    }
    return EntityPatternConfig(patterns=patterns, field_hints=field_hints)


def _text_from_row(row: dict[str, Any]) -> str:
    return " ".join(str(v) for v in row.values() if v is not None)


def _indicators(text: str) -> tuple[str, ...]:
    lower = text.lower()
    return tuple(sorted(word for word in MALICIOUS_WORDS if word in lower))


def _entity_id(row: dict[str, Any], table: str) -> str:
    for key in ("AlertId", "SystemAlertId", "ReportId", "Timestamp", "TimeGenerated", "event_id", "alert_id"):
        if row.get(key):
            return f"{table}:{row[key]}"
    return f"{table}:{abs(hash(_text_from_row(row)))}"


def _normalize_entity(value: str, entity_type: str) -> str:
    normalized = value.strip().strip("`'\".,;()[]{}")
    if entity_type in {"domain", "url"}:
        normalized = normalized.rstrip("/")
    return normalized


NAME_PHRASE_RE = re.compile(r"\b([A-Z][a-z0-9]+(?:\s+[A-Z][a-z0-9]+)+)\b")
BACKTICK_SPAN_RE = re.compile(r"`([^`]{2,80})`")


def _question_name_phrases(question: str) -> list[str]:
    """Proper-noun phrases and backticked spans worth pivoting on (e.g. threat
    actor names like 'Manatee Tempest' that no entity regex captures)."""
    phrases: list[str] = []
    for match in NAME_PHRASE_RE.finditer(question):
        phrase = match.group(1)
        first_word = phrase.split()[0].lower()
        if first_word in STOPWORD_VALUES:
            continue
        if phrase not in phrases:
            phrases.append(phrase)
    for match in BACKTICK_SPAN_RE.finditer(question):
        span = match.group(1).strip()
        if span and span not in phrases:
            phrases.append(span)
    return phrases


def _looks_like_noise(value: str, entity_type: str) -> bool:
    if not value or value == ".":
        return True
    if value.lower() in STOPWORD_VALUES:
        return True
    if entity_type == "domain" and PROCESS_LIKE_RE.match(value):
        return True
    if entity_type == "host" and "." in value:
        return True
    return False


@dataclass
class EvidenceRegistry:
    supports: list[EntitySupport] = field(default_factory=list)
    content_ids: set[str] = field(default_factory=set)
    seen_ids: set[str] = field(default_factory=set)
    scanner: InjectionScanner = field(default_factory=InjectionScanner)
    patterns: EntityPatternConfig = field(default_factory=load_entity_patterns)

    def seed_question(self, question: str, step_seen: int = 0) -> None:
        self.add_text(question, source_table="question", step_seen=step_seen, trust_tier="trusted", source="question")
        for phrase in _question_name_phrases(question):
            support = EntitySupport(
                entity_value=phrase,
                entity_type="name",
                evidence_id="question:names",
                source_table="question",
                trust_tier="trusted",
                source="question",
                injection_id=None,
                content_exposed=True,
                step_seen=step_seen,
                supporting_fields=("text",),
            )
            if support not in self.supports:
                self.supports.append(support)

    def add_text(
        self,
        text: str,
        *,
        source_table: str,
        step_seen: int,
        trust_tier: str | None = None,
        source: str | None = None,
    ) -> None:
        self.add_row(
            {"text": text, "trust_tier": trust_tier, "source": source},
            step_seen=step_seen,
            source_table=source_table,
        )

    def update_from_observation(self, observation: Any) -> None:
        rows = getattr(observation, "rows", ()) or ()
        for row in rows:
            self.add_row(dict(row), step_seen=getattr(observation, "step_index", 0))

    def add_row(self, row: dict[str, Any], step_seen: int, source_table: str | None = None) -> None:
        table = source_table or str(row.get("_source_table") or "unknown")
        evidence_id = _entity_id(row, table)
        self.content_ids.add(evidence_id)
        text = _text_from_row(row)
        indicators = _indicators(text)
        scan = self.scanner.scan_evidence_row(row)
        for value, entity_type, fields in self._extract_entities(row):
            support = EntitySupport(
                entity_value=value,
                entity_type=entity_type,
                evidence_id=evidence_id,
                source_table=table,
                trust_tier=row.get("trust_tier"),
                source=row.get("source"),
                injection_id=row.get("injection_id"),
                content_exposed=True,
                step_seen=step_seen,
                supporting_fields=fields,
                malicious_indicators=indicators,
                scanner_status=scan.status,
                localized_spans=scan.localized_spans,
            )
            if support not in self.supports:
                self.supports.append(support)

    def support_for(self, entity_value: str, entity_type: str | None = None) -> list[EntitySupport]:
        return [
            support
            for support in self.supports
            if support.entity_value == entity_value and (entity_type is None or support.entity_type == entity_type)
        ]

    def best_entities(self, entity_type: str, limit: int = 8) -> list[str]:
        seen: list[str] = []
        for support in self.ranked_supports(entity_type):
            if support.entity_value not in seen:
                seen.append(support.entity_value)
            if len(seen) >= limit:
                break
        return seen

    def ranked_supports(self, entity_type: str) -> list[EntitySupport]:
        supports = [
            support
            for support in self.supports
            if support.entity_type == entity_type and support.trusted and support.content_exposed
        ]
        return sorted(supports, key=self._support_rank, reverse=True)

    def compact(self, limit: int = 16) -> list[dict[str, Any]]:
        ranked = sorted(self.supports, key=self._support_rank, reverse=True)
        return [
            {
                "value": support.entity_value,
                "type": support.entity_type,
                "source_table": support.source_table,
                "fields": list(support.supporting_fields),
                "step_seen": support.step_seen,
            }
            for support in ranked[:limit]
        ]

    def _extract_entities(self, row: dict[str, Any]) -> list[tuple[str, str, tuple[str, ...]]]:
        values: dict[tuple[str, str], set[str]] = {}
        for field, raw_value in row.items():
            if field.startswith("_"):
                continue
            text = "" if raw_value is None else str(raw_value)
            lower_field = field.lower()
            for entity_type, hinted_fields in self.patterns.field_hints.items():
                if lower_field in hinted_fields:
                    value = _normalize_entity(text, entity_type)
                    if not _looks_like_noise(value, entity_type):
                        values.setdefault((value, entity_type), set()).add(field)
            for entity_type, regexes in self.patterns.patterns.items():
                for regex in regexes:
                    for match in regex.finditer(text):
                        value = _normalize_entity(match.group(0), entity_type)
                        if not _looks_like_noise(value, entity_type):
                            values.setdefault((value, entity_type), set()).add(field)
        return [(value, entity_type, tuple(sorted(fields))) for (value, entity_type), fields in values.items()]

    @staticmethod
    def _support_rank(support: EntitySupport) -> tuple[int, int, int, int]:
        trust_score = {"trusted": 3, "verified": 3, None: 1}.get(support.trust_tier, 1)
        source_score = {
            "question": 3,
            "AlertEvidence": 5,
            "SecurityAlert": 5,
            "AlertInfo": 4,
            "DeviceProcessEvents": 4,
            "DeviceFileEvents": 4,
            "IdentityLogonEvents": 4,
            "AADSignInEventsBeta": 4,
            "EmailEvents": 3,
            "OfficeActivity": 3,
        }.get(support.source_table, 1)
        indicator_score = min(5, len(support.malicious_indicators))
        field_score = min(3, len(support.supporting_fields))
        return (trust_score, source_score, indicator_score, field_score)
