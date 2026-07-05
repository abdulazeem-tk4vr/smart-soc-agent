# Ported from soc_defender.
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any


TRUNCATION_RE = re.compile(
    r"^Retrieved\s+(?P<count>\d+)\s+entries\.\s+Displaying\s+first\s+(?P<shown>\d+)\s+entries\.\s*\n",
    re.IGNORECASE,
)
ERROR_RE = re.compile(r"^(?P<kind>[A-Za-z_][A-Za-z0-9_]*Error|[A-Za-z_][A-Za-z0-9_]*Exception):\s*(?P<message>.*)$")


@dataclass(frozen=True)
class ParsedObservation:
    raw: str
    kind: str
    rows: tuple[dict[str, Any], ...] = ()
    row_values: tuple[tuple[Any, ...], ...] = ()
    columns: tuple[str, ...] = ()
    error_type: str | None = None
    error_message: str | None = None
    retrieved_count: int | None = None
    displayed_count: int | None = None
    question: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def failed(self) -> bool:
        return self.kind == "error"

    @property
    def empty(self) -> bool:
        return self.kind == "rows" and not self.row_values


def parse_observation(observation: str | None, columns: list[str] | tuple[str, ...] | None = None) -> ParsedObservation:
    raw = "" if observation is None else str(observation)
    projected_columns = tuple(columns or ())
    stripped = raw.strip()

    if not stripped:
        return ParsedObservation(raw=raw, kind="empty", columns=projected_columns)

    error = ERROR_RE.match(stripped)
    if error:
        return ParsedObservation(
            raw=raw,
            kind="error",
            columns=projected_columns,
            error_type=error.group("kind"),
            error_message=error.group("message"),
        )

    retrieved_count: int | None = None
    displayed_count: int | None = None
    row_text = stripped
    truncation = TRUNCATION_RE.match(raw)
    if truncation:
        retrieved_count = int(truncation.group("count"))
        displayed_count = int(truncation.group("shown"))
        row_text = raw[truncation.end() :].strip()

    parsed_rows = _parse_tuple_rows(row_text)
    if parsed_rows is not None:
        rows = tuple(_row_dict(values, projected_columns) for values in parsed_rows)
        return ParsedObservation(
            raw=raw,
            kind="rows",
            rows=rows,
            row_values=tuple(parsed_rows),
            columns=projected_columns,
            retrieved_count=retrieved_count,
            displayed_count=displayed_count,
        )

    return ParsedObservation(raw=raw, kind="question", columns=projected_columns, question=raw)


def _parse_tuple_rows(text: str) -> tuple[tuple[Any, ...], ...] | None:
    try:
        value = ast.literal_eval(text)
    except (SyntaxError, ValueError):
        return None

    if not isinstance(value, list):
        return None

    rows: list[tuple[Any, ...]] = []
    for item in value:
        if isinstance(item, tuple):
            rows.append(item)
        else:
            rows.append((item,))
    return tuple(rows)


def _row_dict(values: tuple[Any, ...], columns: tuple[str, ...]) -> dict[str, Any]:
    if columns:
        result = {columns[idx] if idx < len(columns) else f"col_{idx}": value for idx, value in enumerate(values)}
    else:
        result = {f"col_{idx}": value for idx, value in enumerate(values)}
    result["_raw_tuple"] = values
    return result
