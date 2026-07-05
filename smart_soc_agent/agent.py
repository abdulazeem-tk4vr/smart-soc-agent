# Ported from soc_defender.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import projected_columns, referenced_tables, submit_answer, validate_sql
from .answer_gate import best_gated_answer
from .evidence_registry import EvidenceRegistry
from .llm import LLMClient, build_llm_client_from_env
from .observation import ParsedObservation, parse_observation
from .schema_cache import SchemaCache
from .sql_planner import answer_gap_entity_types, deterministic_candidates, preferred_tables


DEFAULT_MAX_STEPS = 15


@dataclass
class SmartSocAgent:
    max_steps: int = DEFAULT_MAX_STEPS
    mode: str = "deterministic"
    layer: str = "alert"
    default_limit: int = 15
    step_count: int = 0
    question: str = ""
    last_columns: tuple[str, ...] = ()
    schema_seen: set[str] = field(default_factory=set)
    emitted_sql: set[str] = field(default_factory=set)
    failed_tables: set[str] = field(default_factory=set)
    schema_cache: SchemaCache = field(default_factory=SchemaCache)
    registry: EvidenceRegistry = field(default_factory=EvidenceRegistry)
    llm: LLMClient | None = None
    last_query_table: str | None = None
    question_seeded: bool = False
    current_observation: ParsedObservation | None = None
    query_history: list[dict[str, Any]] = field(default_factory=list)
    episode_summary: dict[str, Any] = field(default_factory=dict)
    rag_context_cache: list[dict[str, Any]] = field(default_factory=list)
    rag_query_cache: str = ""
    rag_called: bool = False
    rag_intel: Any | None = None
    rag_enabled: bool = True
    scanner_enabled: bool = True
    messages: list[dict[str, str]] = field(default_factory=list)
    action_trace: list[dict[str, Any]] = field(default_factory=list)
    usage_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return "SmartSocAgent"

    @property
    def table_names(self) -> set[str]:
        return self.schema_cache.table_names()

    def act(self, observation: str) -> tuple[str, bool]:
        parsed = parse_observation(observation, columns=self.last_columns)
        self.current_observation = parsed
        self._record_observation(parsed)

        if parsed.kind == "question" and parsed.question:
            self.question = parsed.question
            if not self.question_seeded:
                self.registry.seed_question(parsed.question)
                self.question_seeded = True

        if self.step_count >= max(0, self.max_steps - 1):
            return self._emit_submit(self._compose_answer("budget deadline reached"))

        if parsed.kind == "rows":
            self._update_backbone_state(parsed)
        elif parsed.failed:
            self._update_failed_state()

        if self.mode in {"agentic", "full", "graph"}:
            action, submit, state = self._run_graph(parsed)
            return self._emit_validated(action, submit=submit, reason="agentic graph", graph_state=state)

        early_answer = self._early_answer()
        if early_answer:
            return self._emit_submit(early_answer)

        action = self._next_query(parsed)
        if action is None:
            return self._emit_submit(self._compose_answer("deterministic discovery exhausted"))

        table_names = self._available_tables()
        validation = validate_sql(action, table_allowlist=table_names or None, default_limit=self.default_limit)
        if not validation.ok and table_names:
            fallback = "SHOW TABLES"
            validation = validate_sql(fallback, default_limit=self.default_limit)

        self.last_query_table = self._query_table(validation.sql)
        self.last_columns = validation.columns or self.schema_cache.columns_for(self.last_query_table) or projected_columns(validation.sql)
        return self._emit_action(validation.sql, submit=False, reason="deterministic query")

    def reset(self, change_seed: bool = True) -> None:
        _ = change_seed
        self.step_count = 0
        self.question = ""
        self.last_columns = ()
        self.schema_seen.clear()
        self.emitted_sql.clear()
        self.failed_tables.clear()
        self.registry = EvidenceRegistry()
        self.last_query_table = None
        self.question_seeded = False
        self.current_observation = None
        self.query_history = []
        self.episode_summary = {}
        self.rag_context_cache = []
        self.rag_query_cache = ""
        self.rag_called = False
        self.messages = []
        self.action_trace = []
        self.usage_summary = {}

    def get_logging(self) -> dict[str, Any]:
        return {
            "messages": list(self.messages),
            "usage_summary": dict(self.usage_summary),
            "action_trace": list(self.action_trace),
            "table_names": sorted(self.schema_cache.table_names()),
            "schema_seen": sorted(self.schema_seen),
            "schema_digest": self.schema_cache.digest(),
            "registry": self.registry.compact(),
            "query_history": list(self.query_history),
            "episode_summary": dict(self.episode_summary),
            "mode": self.mode,
            "layer": self.layer,
        }

    def _run_graph(self, parsed: ParsedObservation):
        from .graph import SmartSocGraph
        from .investigator import Investigator, LLMVerifier
        from .rag.rag import build_rag_intel

        if self.llm is None:
            self.llm = build_llm_client_from_env()
        if self.rag_enabled and self.rag_intel is None:
            self.rag_intel = build_rag_intel()
        graph = SmartSocGraph(
            runtime=self,
            investigator=Investigator(self.llm),
            verifier=LLMVerifier(self.llm),
            rag=self.rag_intel if self.rag_enabled else None,
        )
        return graph.next_action(parsed)

    def _next_query(self, parsed: ParsedObservation) -> str | None:
        table_names = self._available_tables()
        if not table_names:
            if not self.schema_cache.table_names():
                return "SHOW TABLES"
            return None

        table = self.schema_cache.undescribed_preferred(preferred_tables(self.layer))
        if table:
            self.schema_seen.add(table)
            return f"DESCRIBE {table}"

        known_entities = self._known_entities()
        columns = {table: self.schema_cache.columns_for(table) for table in table_names}
        for candidate in deterministic_candidates(
            question=self.question,
            table_names=table_names,
            table_columns=columns,
            known_entities=known_entities,
            layer=self.layer,
            default_limit=self.default_limit,
        ):
            if not self._already_emitted(candidate):
                return candidate

        for table in sorted(table_names):
            candidate = f"SELECT * FROM {table}"
            if not self._already_emitted(candidate):
                return candidate

        return None

    def _update_backbone_state(self, parsed: ParsedObservation) -> None:
        self._record_query_result(parsed)
        if self._last_action_was("SHOW TABLES"):
            self.schema_cache.record_tables(parsed.row_values)
            return
        if self._last_action_was("DESCRIBE") and self.last_query_table:
            self.schema_cache.record_describe(self.last_query_table, parsed.row_values)
            return
        if self.last_query_table:
            self.schema_cache.mark_sampled(self.last_query_table)
            for row in parsed.rows:
                enriched = dict(row)
                enriched["_source_table"] = self.last_query_table
                self.registry.add_row(enriched, step_seen=self.step_count, source_table=self.last_query_table)

    def _update_failed_state(self) -> None:
        self._record_query_result(self.current_observation)
        if self._last_action_was("DESCRIBE") and self.last_query_table:
            self.schema_cache.record_describe(self.last_query_table, ())
            self.failed_tables.add(self.last_query_table.lower())

    def _compose_answer(self, reason: str) -> str:
        if self.question:
            return (
                "I do not have enough grounded database evidence to identify a final entity. "
                f"Reason: {reason}. Question: {self.question}"
            )
        return f"I do not have enough grounded database evidence to identify a final entity. Reason: {reason}."

    def _early_answer(self) -> str | None:
        answer, decision = best_gated_answer(self.question, self.registry)
        if decision.approved:
            return answer
        return None

    def _evidence_chain(self, top_support: Any) -> str:
        related = [
            support
            for support in self.registry.supports
            if support.source_table == top_support.source_table and support.evidence_id == top_support.evidence_id
        ]
        pieces = [f"{top_support.entity_type}={top_support.entity_value}"]
        for support in related:
            if support is top_support:
                continue
            if support.entity_type in {"account", "host", "ip", "domain", "url", "file", "app_id"}:
                item = f"{support.entity_type}={support.entity_value}"
                if item not in pieces:
                    pieces.append(item)
            if len(pieces) >= 5:
                break
        return f"{top_support.source_table} " + ", ".join(pieces)

    def _emit_validated(self, action: str, *, submit: bool, reason: str, graph_state: Any | None = None) -> tuple[str, bool]:
        if submit:
            return self._emit_action(action, submit=True, reason=reason, graph_state=graph_state)

        validation = self._validate_candidate_sql(action)
        if not validation.ok:
            fallback = self._next_query(self.current_observation or ParsedObservation(raw="", kind="empty"))
            if fallback is None:
                return self._emit_submit(self._compose_answer(f"invalid graph SQL: {validation.reason}"))
            validation = self._validate_candidate_sql(fallback)
        self.last_query_table = self._query_table(validation.sql)
        self.last_columns = validation.columns or self.schema_cache.columns_for(self.last_query_table) or projected_columns(validation.sql)
        return self._emit_action(validation.sql, submit=False, reason=reason, graph_state=graph_state)

    def _emit_action(self, action: str, *, submit: bool, reason: str, graph_state: Any | None = None) -> tuple[str, bool]:
        self.step_count += 1
        if not submit:
            self.emitted_sql.add(action.strip().lower())
        self.messages.append({"role": "assistant", "content": f"Action: {'submit' if submit else 'execute'}[{action}]"})
        trace: dict[str, Any] = {"step": self.step_count, "action": action, "submit": submit, "reason": reason}
        if graph_state is not None:
            trace["graph_traces"] = [
                {"node": item.node, "input_summary": item.input_summary, "output_summary": item.output_summary}
                for item in graph_state.traces
            ]
            trace["gate_decision"] = graph_state.gate_decision
        self.action_trace.append(trace)
        return action, submit

    def _emit_submit(self, answer: str) -> tuple[str, bool]:
        action, submit = submit_answer(answer)
        return self._emit_action(action, submit=submit, reason="submit")

    def _record_observation(self, parsed: ParsedObservation) -> None:
        summary = parsed.question if parsed.kind == "question" else parsed.kind
        self.messages.append({"role": "user", "content": str(summary or "")[:4000]})

    def _last_action_was(self, prefix: str) -> bool:
        if not self.action_trace:
            return False
        return str(self.action_trace[-1]["action"]).strip().lower().startswith(prefix.lower())

    def _already_emitted(self, sql: str) -> bool:
        table_names = self._available_tables()
        normalized = validate_sql(sql, table_allowlist=table_names or None, default_limit=self.default_limit)
        candidate = normalized.sql if normalized.ok else sql
        return candidate.strip().lower() in self.emitted_sql

    def _known_entities(self) -> dict[str, list[str]]:
        return {
            entity_type: self.registry.best_entities(entity_type)
            for entity_type in ("account", "ip", "host", "domain", "url", "sha256", "file", "app_id", "timestamp")
        }

    @staticmethod
    def _query_table(sql: str) -> str | None:
        tables = referenced_tables(sql)
        return next(iter(tables), None)

    def _available_tables(self) -> set[str]:
        return {table for table in self.schema_cache.table_names() if table.lower() not in self.failed_tables}

    def _validate_candidate_sql(self, sql: str):
        return validate_sql(sql, table_allowlist=self._available_tables() or None, default_limit=self.default_limit)

    def _record_query_result(self, parsed: ParsedObservation | None) -> None:
        if parsed is None or not self.action_trace:
            return
        last = self.action_trace[-1]
        if last.get("submit"):
            return
        sql = str(last.get("action") or "")
        if not sql:
            return
        record = {
            "sql": sql,
            "table": self.last_query_table,
            "rows_returned": len(parsed.rows),
            "ok": not parsed.failed,
            "kind": parsed.kind,
        }
        if parsed.error_type:
            record["error_type"] = parsed.error_type
        if not self.query_history or self.query_history[-1].get("sql") != sql:
            self.query_history.append(record)


SocDefenderAgent = SmartSocAgent


def build_agent(
    mode: str = "deterministic",
    max_steps: int = DEFAULT_MAX_STEPS,
    layer: str = "alert",
    llm: LLMClient | None = None,
    rag_intel: Any | None = None,
    rag_enabled: bool = True,
    scanner_enabled: bool = True,
    **_: Any,
) -> SmartSocAgent:
    return SmartSocAgent(
        mode=mode,
        max_steps=max_steps,
        layer=layer,
        llm=llm,
        rag_intel=rag_intel,
        rag_enabled=rag_enabled,
        scanner_enabled=scanner_enabled,
    )
