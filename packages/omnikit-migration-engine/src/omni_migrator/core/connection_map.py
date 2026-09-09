"""Programmatic source → Omni connection mapping (plan §7.4, the Map stage).

Omni's `GET /api/v1/connections` returns `{id, name, dialect, database, defaultSchema}`.
We auto-match each distinct source connection to an Omni connection by **dialect** (the
reliable key), disambiguating by database/name similarity. Ambiguous or missing matches
are flagged with a confidence so the user confirms — the rest is automatic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Literal

from omni_migrator.ir.schema import ModelIR, UntranslatableNote

Confidence = Literal["exact", "dialect", "ambiguous", "none"]

# IR/source dialect aliases → Omni connection dialect enum.
_DIALECT_ALIAS = {
    "postgresql": "postgres",
    "sqlserver": "sqlserver",
    "mssql": "sqlserver",
    "redshift": "redshift",
    "bigquery": "bigquery",
    "snowflake": "snowflake",
    "databricks": "databricks",
    "mysql": "mysql",
    "other": "",
}


def _norm_dialect(d: str | None) -> str:
    if not d:
        return ""
    d = d.lower()
    return _DIALECT_ALIAS.get(d, d)


def _sim(a: str | None, b: str | None) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


@dataclass
class SourceConnection:
    name: str | None
    dialect: str
    database: str | None = None
    schema: str | None = None


@dataclass
class ConnectionMatch:
    source: SourceConnection
    omni_connection_id: str | None = None
    omni_connection_name: str | None = None
    omni_default_schema: str | None = None
    omni_database: str | None = None
    confidence: Confidence = "none"
    candidates: list[dict] = field(default_factory=list)
    reason: str = ""


def collect_source_connections(model: ModelIR) -> list[SourceConnection]:
    """Distinct source connections referenced by the model's views."""
    seen: dict[tuple, SourceConnection] = {}
    for v in model.views:
        c = v.connection
        key = (c.source_connection_name, _norm_dialect(c.dialect))
        if key not in seen:
            seen[key] = SourceConnection(
                name=c.source_connection_name,
                dialect=_norm_dialect(c.dialect),
                database=v.source_table and None,  # database not modeled per-view yet
                schema=v.schema_name,
            )
    return list(seen.values())


def suggest_mapping(
    sources: list[SourceConnection],
    omni_connections: list[dict],
    *,
    overrides: dict[str, str] | None = None,
) -> dict[str, ConnectionMatch]:
    """Map each source connection (keyed by its name, or '<dialect>' if unnamed)."""
    overrides = overrides or {}
    by_id = {c["id"]: c for c in omni_connections}
    result: dict[str, ConnectionMatch] = {}

    for src in sources:
        key = src.name or src.dialect or "default"
        match = ConnectionMatch(source=src)

        # explicit override wins
        if key in overrides and overrides[key] in by_id:
            c = by_id[overrides[key]]
            match.omni_connection_id = c["id"]
            match.omni_connection_name = c.get("name")
            match.omni_default_schema = c.get("defaultSchema")
            match.omni_database = c.get("database")
            match.confidence = "exact"
            target_dialect = _norm_dialect(c.get("dialect"))
            match.reason = (
                f"User confirmed an override from '{src.dialect or 'unknown'}' to "
                f"'{target_dialect or 'unknown'}' dialect."
                if src.dialect and target_dialect and target_dialect != src.dialect
                else "User confirmed this destination connection."
            )
            result[key] = match
            continue

        candidates = [c for c in omni_connections if _norm_dialect(c.get("dialect")) == src.dialect]
        match.candidates = candidates

        if not candidates:
            match.confidence = "none"
            match.reason = (
                f"No Omni connection with dialect '{src.dialect}'. Create one, or map manually."
                if src.dialect
                else "Source dialect unknown; map manually."
            )
            result[key] = match
            continue

        # score by database/name similarity to disambiguate
        def score(c: dict) -> float:
            return max(_sim(src.database, c.get("database")), _sim(src.name, c.get("name")))

        ranked = sorted(candidates, key=score, reverse=True)
        best = ranked[0]
        match.omni_connection_id = best["id"]
        match.omni_connection_name = best.get("name")
        match.omni_default_schema = best.get("defaultSchema")
        match.omni_database = best.get("database")

        if len(candidates) == 1:
            match.confidence = "dialect"
            match.reason = f"Only '{src.dialect}' connection in the org."
        elif score(best) >= 0.6 and (len(ranked) < 2 or score(best) - score(ranked[1]) > 0.15):
            match.confidence = "exact"
            match.reason = f"Best name/database match among {len(candidates)} '{src.dialect}' connections."
        else:
            match.confidence = "ambiguous"
            match.reason = (
                f"{len(candidates)} '{src.dialect}' connections; picked '{best.get('name')}' "
                "by weak similarity — confirm."
            )
        result[key] = match
    return result


def apply_mapping(model: ModelIR, mapping: dict[str, ConnectionMatch]) -> list[UntranslatableNote]:
    """Stamp omni_connection_id on each view, fill missing schema from the connection
    default, and warn on unresolved/ambiguous/dialect-mismatch.

    Notes are attached directly to the affected view's `untranslatable` (not just
    returned) — the per-file AI seed prompt and the `ai_policy="notes"` routing decision
    both key off `view.untranslatable`, so a connection problem that only lived in the
    returned list would silently never reach the AI or trigger review for that view. The
    return value still exists for CLI-level reporting.
    """
    notes: list[UntranslatableNote] = []
    for v in model.views:
        key = v.connection.source_connection_name or _norm_dialect(v.connection.dialect) or "default"
        m = mapping.get(key)
        if not m or not m.omni_connection_id:
            note = UntranslatableNote(
                object=f"connection for view {v.name}",
                reason=(m.reason if m else f"No mapping for source connection '{key}'."),
                severity="blocker",
            )
            v.untranslatable.append(note)
            notes.append(note)
            continue
        if m.confidence == "ambiguous":
            note = UntranslatableNote(
                object=f"connection for view {v.name}",
                reason=f"{m.reason} Confirm a destination connection before generating migration files.",
                severity="blocker",
                hint=f"suggested {m.omni_connection_name} ({m.omni_connection_id})",
            )
            v.untranslatable.append(note)
            notes.append(note)
            continue
        v.connection.omni_connection_id = m.omni_connection_id
        if m.omni_database:
            v.connection.database = m.omni_database
        if not v.schema_name and m.omni_default_schema:
            v.schema_name = m.omni_default_schema
    return notes
