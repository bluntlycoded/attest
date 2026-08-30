"""Database access shared by the SQL-backed loaders.

Loaders take any DB-API connection rather than a driver of their own. SQLite is
in the standard library and Postgres is not, so requiring a specific driver
would put a dependency in a package that has none - and a caller who already
holds a connection should not be made to hand over a URL instead.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Iterator, Protocol

__all__ = ["Connection", "connect", "rows"]


class Connection(Protocol):
    """The slice of DB-API 2.0 the loaders use."""

    def cursor(self) -> Any:
        ...


def connect(url: str) -> Connection:
    """Open a connection from a URL.

    Args:
        url: ``sqlite:///path/to.db``, a bare filesystem path, or any
            ``postgresql://`` URL. Postgres needs ``psycopg`` installed; the
            error says so if it is not.
    """
    if url.startswith(("postgresql://", "postgres://")):
        try:
            import psycopg  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ImportError(
                "reading a Postgres corpus needs psycopg: pip install psycopg[binary]"
            ) from exc
        return psycopg.connect(url)

    path = url[len("sqlite:///") :] if url.startswith("sqlite:///") else url
    return sqlite3.connect(path)


def rows(
    connection: Connection, sql: str, params: tuple = ()
) -> Iterator[dict[str, Any]]:
    """Run a query and yield dict rows.

    Placeholders are written as ``?`` and rewritten to ``%s`` for drivers that
    expect the format style, so a loader can be written once for both.
    """
    cursor = connection.cursor()
    if not isinstance(connection, sqlite3.Connection):
        sql = sql.replace("?", "%s")
    cursor.execute(sql, params)
    columns = [description[0] for description in cursor.description]
    try:
        for record in cursor:
            yield dict(zip(columns, record))
    finally:
        cursor.close()


def to_epoch(value: Any) -> float:
    """Coerce a timestamp column to Unix seconds.

    Drivers disagree: SQLite hands back an ISO string, Postgres a datetime,
    and a numeric column comes through as-is.
    """
    if value is None:
        raise ValueError("timestamp column is null")
    if isinstance(value, (int, float)):
        return float(value)
    if hasattr(value, "timestamp"):
        return float(value.timestamp())

    from datetime import datetime

    text = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(text).timestamp()
