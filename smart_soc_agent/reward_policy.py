# Ported from soc_defender and adapted for ExCyTIn-Bench.
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .answer_gate import best_gated_answer
from .observation import ParsedObservation
from .sql_planner import answer_gap_entity_types

if TYPE_CHECKING:
    from .policy import InvestigationPolicy


STEP_COST = 0.1
SUPPORTED_ANSWER_GAIN = 2.0
QUERY_GAIN = 0.5


@dataclass(frozen=True)
class AnswerDecision:
    submit: bool
    reason: str
    best_next_gain: float


def answer_decision(policy: InvestigationPolicy, parsed: ParsedObservation, *, step_count: int = 0) -> AnswerDecision:
    max_steps = max(1, int(policy.max_steps))
    if step_count >= max_steps - 1:
        return AnswerDecision(True, "answer deadline reached", 0.0)

    _, gate = best_gated_answer("", policy.registry)
    if gate.approved:
        return AnswerDecision(True, "trusted answer support is available", SUPPORTED_ANSWER_GAIN)

    gain = investigation_gain_estimate(policy, parsed)
    if gain <= STEP_COST:
        return AnswerDecision(True, "remaining investigation is not worth another environment step", gain)
    return AnswerDecision(False, "more evidence can still improve the answer", gain)


def report_decision(policy: InvestigationPolicy, parsed: ParsedObservation) -> AnswerDecision:
    """Compatibility alias for older callers."""

    return answer_decision(policy, parsed)


def answer_gaps(question: str) -> set[str]:
    return set(answer_gap_entity_types(question))


def investigation_gain_estimate(policy: InvestigationPolicy, parsed: ParsedObservation) -> float:
    if parsed.failed:
        return QUERY_GAIN
    if parsed.kind == "rows" and parsed.rows:
        return QUERY_GAIN
    if policy.schema_cache.table_names():
        return QUERY_GAIN
    return QUERY_GAIN
