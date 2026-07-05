# Ported from soc_defender.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .regex_classifier import RegexFinding, RegexPromptInjectionClassifier


@dataclass(frozen=True)
class ScanAnnotation:
    status: str
    max_confidence: float
    findings: tuple[RegexFinding, ...] = ()
    localized_spans: tuple[tuple[int, int, str], ...] = ()


class InjectionScanner:
    def __init__(
        self,
        regex_classifier: RegexPromptInjectionClassifier | None = None,
    ) -> None:
        self.regex_classifier = regex_classifier or RegexPromptInjectionClassifier()

    def scan_text(self, text: str | None) -> ScanAnnotation:
        result = self.regex_classifier.scan(text)
        max_confidence = result.max_confidence
        spans = tuple((finding.start, finding.end, finding.rule_id) for finding in result.findings)
        if max_confidence >= 0.85:
            status = "flagged"
        elif max_confidence >= 0.60:
            status = "suspicious"
        else:
            status = "clean"
        return ScanAnnotation(
            status=status,
            max_confidence=max_confidence,
            findings=result.findings,
            localized_spans=spans,
        )

    def scan_evidence_row(self, row: dict[str, Any]) -> ScanAnnotation:
        text = " ".join(str(value) for value in row.values() if isinstance(value, str))
        return self.scan_text(text)
