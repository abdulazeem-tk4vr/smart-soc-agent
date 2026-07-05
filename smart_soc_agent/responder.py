# Ported from soc_defender and adapted for ExCyTIn-Bench.
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .actions import validate_sql
from .answer_gate import GateDecision, best_gated_answer, gate_answer
from .investigator import InvestigationIntent, VerifierCandidate


@dataclass(frozen=True)
class VerifiedActionCandidate:
    action_type: str
    sql: str | None = None
    answer: str | None = None
    entity_value: str | None = None
    gate_decision: GateDecision | None = None
    rationale: str = ""
    confidence: float = 0.0


@dataclass
class Responder:
    runtime: Any

    def respond(
        self,
        intent: InvestigationIntent,
        candidate: VerifierCandidate,
    ) -> tuple[str, bool, VerifiedActionCandidate]:
        verified = self._verify_candidate(candidate)
        deadline = self.runtime.step_count >= max(0, self.runtime.max_steps - 1)

        if verified.action_type == "submit_answer" and verified.gate_decision and verified.gate_decision.approved and verified.answer:
            return verified.answer, True, verified

        if deadline:
            answer, decision = best_gated_answer(self.runtime.question, self.runtime.registry)
            if answer:
                return answer, True, VerifiedActionCandidate("submit_answer", answer=answer, gate_decision=decision)
            return self.runtime._compose_answer("budget deadline reached"), True, verified

        sql = verified.sql or intent.sql
        if sql:
            validation = validate_sql(sql, table_allowlist=self.runtime._available_tables() or None, default_limit=self.runtime.default_limit)
            if validation.ok and not self.runtime._already_emitted(validation.sql):
                return validation.sql, False, verified

        fallback = self.runtime._next_query(self.runtime.current_observation)
        if fallback is not None:
            return fallback, False, verified

        answer, decision = best_gated_answer(self.runtime.question, self.runtime.registry)
        if answer:
            return answer, True, VerifiedActionCandidate("submit_answer", answer=answer, gate_decision=decision)
        return self.runtime._compose_answer("agentic discovery exhausted"), True, verified

    def _verify_candidate(self, candidate: VerifierCandidate) -> VerifiedActionCandidate:
        if candidate.action_type == "submit_answer" and candidate.answer:
            decision = gate_answer(
                candidate.answer,
                self.runtime.registry,
                question=self.runtime.question,
                entity_value=candidate.entity_value,
            )
            return VerifiedActionCandidate(
                action_type="submit_answer",
                sql=candidate.sql,
                answer=candidate.answer,
                entity_value=candidate.entity_value,
                gate_decision=decision,
                rationale=candidate.rationale,
                confidence=candidate.confidence,
            )
        return VerifiedActionCandidate(
            action_type="investigate",
            sql=candidate.sql,
            answer=candidate.answer,
            entity_value=candidate.entity_value,
            rationale=candidate.rationale,
            confidence=candidate.confidence,
        )


def verified_candidate_payload(candidate: VerifiedActionCandidate) -> dict[str, Any]:
    payload = asdict(candidate)
    decision = candidate.gate_decision
    if decision is not None:
        payload["gate_decision"] = {
            "approved": decision.approved,
            "reason": decision.reason,
            "support_count": len(decision.support),
            "unsupported_entities": list(decision.unsupported_entities),
        }
    return payload
