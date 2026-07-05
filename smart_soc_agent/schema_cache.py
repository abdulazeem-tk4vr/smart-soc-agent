# Ported from soc_defender.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DESCRIBE_FIELD_INDEX = 0


@dataclass
class TableSchema:
    name: str
    columns: list[str] = field(default_factory=list)
    described: bool = False
    sampled: bool = False


@dataclass
class SchemaCache:
    tables: dict[str, TableSchema] = field(default_factory=dict)
    incident_key: str | None = None

    def reset_for_incident(self, incident_key: str | None) -> None:
        if incident_key and self.incident_key and self.incident_key != incident_key:
            self.tables.clear()
        if incident_key:
            self.incident_key = incident_key

    def record_tables(self, rows: tuple[tuple[Any, ...], ...]) -> None:
        for row in rows:
            if row and row[0]:
                self.ensure_table(str(row[0]))

    def ensure_table(self, table: str) -> TableSchema:
        key = self._key(table)
        if key not in self.tables:
            self.tables[key] = TableSchema(name=table)
        return self.tables[key]

    def record_describe(self, table: str, rows: tuple[tuple[Any, ...], ...]) -> None:
        schema = self.ensure_table(table)
        columns: list[str] = []
        for row in rows:
            if len(row) > DESCRIBE_FIELD_INDEX and row[DESCRIBE_FIELD_INDEX]:
                columns.append(str(row[DESCRIBE_FIELD_INDEX]))
        if columns:
            schema.columns = columns
        schema.described = True

    def mark_sampled(self, table: str) -> None:
        self.ensure_table(table).sampled = True

    def table_names(self) -> set[str]:
        return {schema.name for schema in self.tables.values()}

    def has_table(self, table: str) -> bool:
        return self._key(table) in self.tables

    def columns_for(self, table: str | None) -> tuple[str, ...]:
        if not table:
            return ()
        schema = self.tables.get(self._key(table))
        return tuple(schema.columns) if schema else ()

    def is_described(self, table: str) -> bool:
        schema = self.tables.get(self._key(table))
        return bool(schema and schema.described)

    def undescribed_preferred(self, preferred: tuple[str, ...], include_others: bool = True) -> str | None:
        for table in preferred:
            schema = self.tables.get(self._key(table))
            if schema and not schema.described:
                return schema.name
        if not include_others:
            return None
        for schema in sorted(self.tables.values(), key=lambda item: item.name.lower()):
            if not schema.described:
                return schema.name
        return None

    def digest(self, limit: int = 20) -> list[dict[str, Any]]:
        return [
            {"table": schema.name, "columns": list(schema.columns), "described": schema.described}
            for schema in sorted(self.tables.values(), key=lambda item: item.name.lower())[:limit]
        ]

    @staticmethod
    def _key(table: str) -> str:
        return table.lower()
