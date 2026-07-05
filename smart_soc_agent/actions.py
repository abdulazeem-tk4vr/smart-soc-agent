# Ported from soc_defender.
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


READ_ONLY_PREFIXES = ("select", "show", "describe", "desc", "explain")
MUTATING_KEYWORDS = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|replace|grant|revoke|call|load|outfile|infile|set|use)\b",
    re.IGNORECASE,
)
TABLE_REF_RE = re.compile(
    r"\b(?:from|join|describe|desc|table)\s+`?(?P<table>[A-Za-z_][A-Za-z0-9_]*)`?",
    re.IGNORECASE,
)
LIMIT_RE = re.compile(r"\blimit\s+\d+\b", re.IGNORECASE)
STRING_LITERAL_RE = re.compile(r"'(?:[^']|'')*'")
BACKTICK_IDENT_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
COMPARED_IDENT_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!=|<>|>=|<=|<|>|\bLIKE\b|\bIN\b|\bIS\b|\bBETWEEN\b)",
    re.IGNORECASE,
)
SQL_KEYWORDS = frozenset(
    """select from where and or not in like is null limit order by group having asc desc as on
    join inner left right outer cross distinct count sum min max avg between exists case when
    then else end union all any some show describe desc explain true false interval second
    minute hour day week month year date time""".split()
)


@dataclass(frozen=True)
class SQLValidation:
    ok: bool
    sql: str
    reason: str = "ok"
    tables: frozenset[str] = frozenset()
    columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentAction:
    action_type: str
    params: dict[str, Any]


def execute_sql(sql: str, *, table_allowlist: set[str] | None = None, default_limit: int = 15) -> tuple[str, bool]:
    validation = validate_sql(sql, table_allowlist=table_allowlist, default_limit=default_limit)
    if not validation.ok:
        return f"SELECT 'invalid_sql: {validation.reason}' AS error_message LIMIT 1", False
    return validation.sql, False


def submit_answer(answer: str) -> tuple[str, bool]:
    return str(answer).strip(), True


def query_logs(sql: str) -> AgentAction:
    return AgentAction("query_logs", {"sql": validate_sql(sql).sql})


def fetch_email(email_id: str) -> AgentAction:
    return AgentAction("fetch_email", {"email_id": email_id})


def fetch_alert(alert_id: str) -> AgentAction:
    return AgentAction("fetch_alert", {"alert_id": alert_id})


def isolate_host(host_id: str) -> AgentAction:
    return AgentAction("isolate_host", {"host_id": host_id})


def block_domain(domain: str) -> AgentAction:
    return AgentAction("block_domain", {"domain": domain})


def reset_user(user_id: str) -> AgentAction:
    return AgentAction("reset_user", {"user_id": user_id})


def submit_report(summary_json: dict[str, Any]) -> AgentAction:
    return AgentAction("submit_report", {"summary_json": normalize_report(summary_json)})


def normalize_report(report: dict[str, Any] | None) -> dict[str, Any]:
    report = dict(report or {})
    containment = report.get("containment_actions")
    if not isinstance(containment, dict):
        containment = {}
    return {
        "patient_zero_host": str(report.get("patient_zero_host") or "unknown"),
        "compromised_user": str(report.get("compromised_user") or "unknown"),
        "attacker_domain": str(report.get("attacker_domain") or "unknown"),
        "data_target": str(report.get("data_target") or "unknown"),
        "initial_vector": str(report.get("initial_vector") or "phish"),
        "containment_actions": {
            "isolated_hosts": list(containment.get("isolated_hosts") or []),
            "blocked_domains": list(containment.get("blocked_domains") or []),
            "reset_users": list(containment.get("reset_users") or []),
        },
    }


def validate_sql(
    sql: str,
    *,
    table_allowlist: set[str] | None = None,
    column_map: dict[str, tuple[str, ...]] | None = None,
    default_limit: int = 15,
) -> SQLValidation:
    stripped = _strip_one_optional_semicolon(sql)
    if not stripped:
        return SQLValidation(False, "", "empty SQL")

    if _has_multiple_statements(str(sql)):
        return SQLValidation(False, stripped, "multiple SQL statements are not allowed")

    lowered = stripped.lower()
    if not lowered.startswith(READ_ONLY_PREFIXES):
        return SQLValidation(False, stripped, "only read-only SQL is allowed")

    if MUTATING_KEYWORDS.search(stripped):
        return SQLValidation(False, stripped, "mutating SQL keyword is not allowed")

    tables = referenced_tables(stripped)
    if table_allowlist is not None and tables:
        allowed = {table.lower() for table in table_allowlist}
        unknown = {table for table in tables if table.lower() not in allowed}
        if unknown:
            return SQLValidation(False, stripped, f"unknown table(s): {', '.join(sorted(unknown))}", frozenset(tables))

    if column_map and tables and stripped.lower().startswith("select"):
        unknown_columns, known_columns = _unknown_columns(stripped, tables, column_map)
        if unknown_columns:
            hint = ", ".join(sorted(known_columns)[:15])
            return SQLValidation(
                False,
                stripped,
                f"unknown column(s): {', '.join(sorted(unknown_columns))}; valid columns for {', '.join(sorted(tables))}: {hint}",
                frozenset(tables),
            )

    normalized = add_limit(stripped, default_limit=default_limit)
    return SQLValidation(True, normalized, tables=frozenset(tables), columns=projected_columns(normalized))


def _unknown_columns(
    sql: str,
    tables: set[str],
    column_map: dict[str, tuple[str, ...]],
) -> tuple[set[str], set[str]]:
    """Return (unknown, known) column names for SQL against described tables.

    Only enforced when every referenced table has a known column list —
    otherwise the schema is incomplete and we cannot rule columns out.
    """
    known_columns: set[str] = set()
    for table in tables:
        columns = column_map.get(table.lower())
        if not columns:
            return set(), set()
        known_columns.update(columns)
    known_lower = {column.lower() for column in known_columns}
    table_lower = {table.lower() for table in tables}

    scrubbed = STRING_LITERAL_RE.sub("''", sql)
    candidates: set[str] = set()
    candidates.update(BACKTICK_IDENT_RE.findall(scrubbed))
    candidates.update(COMPARED_IDENT_RE.findall(scrubbed))
    for select_match in re.finditer(r"\bselect\s+(.*?)\s+from\b", scrubbed, re.IGNORECASE | re.DOTALL):
        for part in select_match.group(1).split(","):
            token = part.strip().strip("`")
            if not token or token == "*" or "(" in token or "." in token or " " in token:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                candidates.add(token)

    unknown = {
        candidate
        for candidate in candidates
        if candidate.lower() not in known_lower
        and candidate.lower() not in SQL_KEYWORDS
        and candidate.lower() not in table_lower
    }
    return unknown, known_columns


def is_safe_select(sql: str, table_allowlist: set[str] | None = None) -> bool:
    return validate_sql(sql, table_allowlist=table_allowlist).ok


def add_limit(sql: str, *, default_limit: int = 15) -> str:
    stripped = _strip_one_optional_semicolon(sql)
    if not stripped.lower().startswith("select"):
        return stripped
    if LIMIT_RE.search(stripped):
        return stripped
    return f"{stripped} LIMIT {int(default_limit)}"


def referenced_tables(sql: str) -> set[str]:
    return {match.group("table") for match in TABLE_REF_RE.finditer(sql)}


def projected_columns(sql: str) -> tuple[str, ...]:
    match = re.match(r"\s*select\s+(?P<columns>.*?)\s+from\s+", sql, re.IGNORECASE | re.DOTALL)
    if not match:
        return ()
    raw_columns = match.group("columns").strip()
    if raw_columns == "*":
        return ()
    columns: list[str] = []
    for part in _split_columns(raw_columns):
        alias_match = re.search(r"\s+as\s+`?(?P<alias>[A-Za-z_][A-Za-z0-9_]*)`?$", part, re.IGNORECASE)
        if alias_match:
            columns.append(alias_match.group("alias"))
            continue
        token = part.rsplit(".", 1)[-1].strip(" `")
        columns.append(token or f"col_{len(columns)}")
    return tuple(columns)


def _split_columns(raw_columns: str) -> list[str]:
    columns: list[str] = []
    depth = 0
    start = 0
    for idx, char in enumerate(raw_columns):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            columns.append(raw_columns[start:idx].strip())
            start = idx + 1
    columns.append(raw_columns[start:].strip())
    return columns


def _strip_one_optional_semicolon(sql: str) -> str:
    stripped = str(sql or "").strip()
    if stripped.endswith(";"):
        stripped = stripped[:-1].strip()
    return stripped


def _has_multiple_statements(sql: str) -> bool:
    stripped = str(sql or "").strip()
    if not stripped:
        return False
    body = stripped[:-1] if stripped.endswith(";") else stripped
    return ";" in body
