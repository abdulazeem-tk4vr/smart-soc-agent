# Ported from soc_defender and adapted for ExCyTIn-Bench.
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .budget import budget_state
from .graph_state import DefenderGraphState
from .investigator import InvestigationIntent, Investigator, LLMVerifier, VerifierCandidate
from .observation import ParsedObservation
from .responder import Responder, verified_candidate_payload
from .scanner import InjectionScanner
from .rag.rag_query import RAGQueryPlanner


@dataclass
class SmartSocGraph:
    runtime: Any
    scanner: InjectionScanner = field(default_factory=InjectionScanner)
    rag: Any | None = None
    investigator: Investigator = field(default_factory=Investigator)
    verifier: LLMVerifier = field(default_factory=LLMVerifier)

    def next_action(self, parsed: ParsedObservation) -> tuple[str, bool, DefenderGraphState]:
        state = DefenderGraphState(
            scenario_id=str(self.runtime.schema_cache.incident_key or ""),
            open_sec_step_index=int(self.runtime.step_count),
            max_steps=self.runtime.max_steps,
            observation={"kind": parsed.kind, "raw": parsed.raw[:2000]},
            parsed_observation=parsed,
            episode_summary=dict(getattr(self.runtime, "episode_summary", {}) or {}),
        )
        self._scanner_node(state)
        self._registry_node(state)
        self._budget_node(state)
        self._investigator_node(state)
        self._rag_node(state)
        self._verifier_node(state)
        action, submit = self._responder_node(state)
        return action, submit, state

    def _scanner_node(self, state: DefenderGraphState) -> None:
        if not getattr(self.runtime, "scanner_enabled", True):
            state.scanner_annotations = []
            state.append_trace("scanner", {"annotations": [], "skipped_reason": "disabled"})
            return
        parsed = state.parsed_observation
        texts = [parsed.raw] if parsed and parsed.kind == "rows" else []
        annotations = []
        for text in texts:
            scan = self.scanner.scan_text(text)
            annotations.append(
                {
                    "status": scan.status,
                    "max_confidence": scan.max_confidence,
                    "rule_ids": [finding.rule_id for finding in scan.findings],
                }
            )
        state.scanner_annotations = annotations
        state.append_trace("scanner", {"annotations": annotations})

    def _registry_node(self, state: DefenderGraphState) -> None:
        state.append_trace(
            "registry",
            {
                "support_count": len(self.runtime.registry.supports),
                "top": self.runtime.registry.compact(limit=8),
            },
        )

    def _budget_node(self, state: DefenderGraphState) -> None:
        deadline = max(0, self.runtime.max_steps - 1)
        state.budget_state = budget_state(
            step_index=self.runtime.step_count,
            max_steps=self.runtime.max_steps,
            report_deadline_step=deadline,
            containment_min_step=0,
        ).to_dict()
        state.append_trace("budget", state.budget_state)

    def _investigator_node(self, state: DefenderGraphState) -> None:
        intent = self.investigator.investigate(
            question=self.runtime.question,
            registry=self.runtime.registry,
            schema_digest=self.runtime.schema_cache.digest(),
            query_history=list(self.runtime.query_history),
            known_entities=self.runtime._known_entities(),
            budget_state=state.budget_state,
            latest_result=self._latest_result_summary(state.parsed_observation),
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            episode_summary=state.episode_summary,
        )
        intent = self._ground_intent(intent, state)
        state.investigation_intent = asdict(intent)
        state.rag_query = intent.rag_query
        state.append_trace("investigator", state.investigation_intent)

    def _ground_intent(self, intent: InvestigationIntent, state: DefenderGraphState) -> InvestigationIntent:
        if intent.intent_type != "query_logs" or not intent.sql:
            return intent
        validation = self.runtime._validate_candidate_sql(intent.sql)
        if validation.ok and self.runtime._already_emitted(validation.sql):
            reason = "SQL already attempted this episode; propose a different pivot"
        elif validation.ok:
            return intent
        else:
            reason = validation.reason
        state.append_trace("grounding", {"rejected_sql": intent.sql, "reason": reason})
        return InvestigationIntent(
            "query_logs",
            sql=None,
            rationale=f"SQL rejected by action guard: {reason}",
            confidence=0.0,
            evidence_summary=intent.evidence_summary,
            uncertainty=intent.uncertainty,
            rag_query=intent.rag_query,
        )

    def _rag_node(self, state: DefenderGraphState) -> None:
        query_source = "investigator" if state.rag_query else "cache"
        query = state.rag_query or getattr(self.runtime, "rag_query_cache", "")
        if not query:
            plan = RAGQueryPlanner(getattr(self.runtime, "llm", None)).plan(
                question=self.runtime.question,
                registry=self.runtime.registry,
                known_entities=self.runtime._known_entities(),
                schema_digest=self.runtime.schema_cache.digest(),
            )
            query = plan.query
            query_source = plan.source
        if getattr(self.runtime, "rag_called", False):
            state.rag_context = list(getattr(self.runtime, "rag_context_cache", []) or [])
            state.append_trace("rag", {"query": query, "query_source": query_source, "documents": len(state.rag_context), "cache_hit": True})
            return
        if not query or self.rag is None:
            state.append_trace("rag", {"query": query, "query_source": query_source, "documents": 0, "cache_hit": False, "skipped_reason": "no_query_or_backend"})
            return
        docs = self.rag.context_for(query)
        state.rag_context = [asdict(doc) for doc in docs]
        self.runtime.rag_context_cache = list(state.rag_context)
        self.runtime.rag_query_cache = query
        self.runtime.rag_called = True
        state.append_trace("rag", {"query": query, "query_source": query_source, "documents": len(state.rag_context), "cache_hit": False})

    def _verifier_node(self, state: DefenderGraphState) -> None:
        intent = InvestigationIntent(**state.investigation_intent)
        candidate = self.verifier.candidate(
            intent,
            question=self.runtime.question,
            registry=self.runtime.registry,
            budget_state=state.budget_state,
            query_history=list(self.runtime.query_history),
            known_entities=self.runtime._known_entities(),
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            episode_summary=state.episode_summary,
        )
        state.verifier_candidate = asdict(candidate)
        if candidate.episode_summary:
            self.runtime.episode_summary = dict(candidate.episode_summary)
            state.episode_summary = dict(candidate.episode_summary)
        state.append_trace("verifier", state.verifier_candidate)

    def _responder_node(self, state: DefenderGraphState) -> tuple[str, bool]:
        responder = Responder(self.runtime)
        intent = InvestigationIntent(**state.investigation_intent)
        candidate = VerifierCandidate(**state.verifier_candidate)
        action, submit, verified = responder.respond(intent, candidate)
        state.responder_action = {"action": action, "submit": submit}
        state.gate_decision = verified_candidate_payload(verified).get("gate_decision") or {}
        state.append_trace(
            "responder",
            {
                "verifier_candidate": verified_candidate_payload(verified),
                "action": state.responder_action,
            },
        )
        return action, submit

    @staticmethod
    def _latest_result_summary(parsed: ParsedObservation | None) -> dict[str, Any]:
        if parsed is None:
            return {}
        return {
            "kind": parsed.kind,
            "row_count": len(parsed.rows),
            "error_type": parsed.error_type,
            "retrieved_count": parsed.retrieved_count,
            "displayed_count": parsed.displayed_count,
        }


DefenderGraph = SmartSocGraph
