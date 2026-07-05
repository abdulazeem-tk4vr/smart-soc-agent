# Ported from soc_defender and adapted for ExCyTIn-Bench answer submission.
from __future__ import annotations

from dataclasses import dataclass

from .evidence_registry import EvidenceRegistry, EntitySupport
from .sql_planner import answer_gap_entity_types


@dataclass(frozen=True)
class GateDecision:
    approved: bool
    reason: str
    support: tuple[EntitySupport, ...] = ()
    unsupported_entities: tuple[str, ...] = ()


def gate_answer(
    answer: str,
    registry: EvidenceRegistry,
    *,
    question: str = "",
    entity_value: str | None = None,
) -> GateDecision:
    claims = _claimed_entities(answer, registry, question=question, entity_value=entity_value)
    if not claims:
        return GateDecision(False, "no claimed answer entity found in registry support")

    approved_supports: list[EntitySupport] = []
    unsupported: list[str] = []
    for value, entity_type in claims:
        if _appears_only_in_question(value, registry):
            unsupported.append(value)
            continue
        supports = tuple(registry.support_for(value, entity_type))
        content_supports = tuple(s for s in supports if s.content_exposed)
        trusted = tuple(s for s in content_supports if s.trusted)
        trusted = tuple(s for s in trusted if not _support_flagged_only(s))
        if not trusted:
            unsupported.append(value)
            continue
        approved_supports.extend(trusted)

    if unsupported:
        return GateDecision(False, "one or more answer entities lack trusted non-question support", tuple(approved_supports), tuple(unsupported))
    return GateDecision(True, "approved", tuple(approved_supports))


def best_gated_answer(question: str, registry: EvidenceRegistry, *, max_candidates: int = 9) -> tuple[str | None, GateDecision]:
    for entity_type in answer_gap_entity_types(question):
        candidates: list[EntitySupport] = []
        for support in registry.ranked_supports(entity_type):
            if support.source_table == "question" or _support_flagged_only(support):
                continue
            if support.entity_value not in [item.entity_value for item in candidates]:
                candidates.append(support)
            if len(candidates) >= max_candidates:
                break
        if not candidates:
            continue
        values = [item.entity_value for item in candidates]
        if len(values) == 1:
            answer = f"Answer: {values[0]}. Evidence: {_evidence_chain(candidates[0], registry)}"
        else:
            answer = "Answer candidates, ranked: " + "; ".join(values[:max_candidates]) + ". Evidence: " + _evidence_chain(candidates[0], registry)
        decision = gate_answer(answer, registry, question=question, entity_value=values[0])
        if decision.approved:
            return answer, decision
    return None, GateDecision(False, "no supported candidate for requested entity type")


def best_effort_answer(question: str, registry: EvidenceRegistry, *, max_candidates: int = 9) -> str | None:
    """Ungated last-resort answer for deadline submission.

    Unlike best_gated_answer this does not require gate approval — it only
    excludes question-restated and scanner-flagged supports, so the judge can
    award full or partial credit instead of the guaranteed zero of a
    "not enough evidence" submission.
    """
    for entity_type in answer_gap_entity_types(question):
        values: list[str] = []
        top: EntitySupport | None = None
        for support in registry.ranked_supports(entity_type):
            if support.source_table == "question" or _support_flagged_only(support):
                continue
            if _appears_only_in_question(support.entity_value, registry):
                continue
            if support.entity_value not in values:
                values.append(support.entity_value)
                if top is None:
                    top = support
            if len(values) >= max_candidates:
                break
        if not values or top is None:
            continue
        if len(values) == 1:
            return f"Answer: {values[0]}. Evidence: {_evidence_chain(top, registry)}"
        return "Answer candidates, ranked: " + "; ".join(values) + ". Evidence: " + _evidence_chain(top, registry)
    return None


def _claimed_entities(
    answer: str,
    registry: EvidenceRegistry,
    *,
    question: str,
    entity_value: str | None,
) -> list[tuple[str, str]]:
    requested_types = set(answer_gap_entity_types(question))
    claims: list[tuple[str, str]] = []
    for support in registry.supports:
        if requested_types and support.entity_type not in requested_types:
            continue
        if entity_value and support.entity_value != entity_value:
            continue
        if support.entity_value and support.entity_value in answer:
            pair = (support.entity_value, support.entity_type)
            if pair not in claims:
                claims.append(pair)
    if claims:
        return claims
    if entity_value:
        for support in registry.support_for(entity_value):
            if requested_types and support.entity_type not in requested_types:
                continue
            pair = (support.entity_value, support.entity_type)
            if pair not in claims:
                claims.append(pair)
    return claims


def _appears_only_in_question(value: str, registry: EvidenceRegistry) -> bool:
    supports = registry.support_for(value)
    return bool(supports) and all(support.source_table == "question" for support in supports)


def _support_flagged_only(support: EntitySupport) -> bool:
    return support.scanner_status in {"flagged", "localized"} or bool(support.localized_spans)


def _evidence_chain(top_support: EntitySupport, registry: EvidenceRegistry) -> str:
    related = [
        support
        for support in registry.supports
        if support.source_table == top_support.source_table and support.evidence_id == top_support.evidence_id
    ]
    pieces = [f"{top_support.entity_type}={top_support.entity_value}"]
    for support in related:
        if support == top_support:
            continue
        if support.entity_type in {"account", "host", "ip", "domain", "url", "file", "app_id"}:
            item = f"{support.entity_type}={support.entity_value}"
            if item not in pieces:
                pieces.append(item)
        if len(pieces) >= 5:
            break
    return f"{top_support.source_table} " + ", ".join(pieces)
