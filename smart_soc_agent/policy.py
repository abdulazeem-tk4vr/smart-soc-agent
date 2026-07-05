# Ported from soc_defender and adapted for ExCyTIn-Bench.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .evidence_registry import EvidenceRegistry
from .schema_cache import SchemaCache


@dataclass
class InvestigationPolicy:
    """Small SecRL policy-state container kept for graph/paper terminology.

    The executable decision loop lives in SmartSocAgent so it can satisfy the
    SecRL `act(observation) -> (action, submit)` contract directly.
    """

    mode: str = "deterministic"
    max_steps: int = 15
    layer: str = "alert"
    registry: EvidenceRegistry = field(default_factory=EvidenceRegistry)
    schema_cache: SchemaCache = field(default_factory=SchemaCache)
    query_history: list[dict[str, Any]] = field(default_factory=list)
    episode_summary: dict[str, Any] = field(default_factory=dict)
    rag_context_cache: list[dict[str, Any]] = field(default_factory=list)
    rag_query_cache: str = ""
    rag_called: bool = False

    def reset_episode_state(self) -> None:
        self.registry = EvidenceRegistry()
        self.query_history.clear()
        self.episode_summary.clear()
        self.rag_context_cache.clear()
        self.rag_query_cache = ""
        self.rag_called = False

    def compact_query_history(self, limit: int = 12) -> list[dict[str, Any]]:
        return list(self.query_history[-limit:])

    def known_entities(self) -> dict[str, list[str]]:
        return {
            entity_type: self.registry.best_entities(entity_type)
            for entity_type in ("account", "ip", "host", "domain", "url", "sha256", "file", "app_id", "timestamp")
        }


DefenderPolicy = InvestigationPolicy
