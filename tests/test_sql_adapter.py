import sqlite3

import pytest

from simdiff import simdiff
from simdiff.adapters.sql import SqlAdapter


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    c.executemany("INSERT INTO users (name) VALUES (?)", [("a",), ("b",), ("c",)])
    c.commit()
    return c


def _count(conn, table="users"):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_insert_is_write_and_db_unchanged(conn):
    adapter = SqlAdapter(conn)
    delta = simdiff("INSERT INTO users (name) VALUES ('d')", adapter)

    assert delta.fully_classified is True
    wr = [d for d in delta.data_access if d.resource == "users"]
    assert wr[0].mode == "WRITE"
    assert delta.resource_use.rows == 1
    # rollback must have left the DB untouched
    assert _count(conn) == 3


def test_delete_is_delete_and_rolled_back(conn):
    adapter = SqlAdapter(conn)
    delta = simdiff("DELETE FROM users WHERE id = 1", adapter)

    d = [x for x in delta.data_access if x.resource == "users"]
    assert d[0].mode == "DELETE"
    assert delta.resource_use.rows == 1
    assert _count(conn) == 3


def test_update_is_write(conn):
    adapter = SqlAdapter(conn)
    delta = simdiff("UPDATE users SET name = 'z'", adapter)
    d = [x for x in delta.data_access if x.resource == "users"]
    assert d[0].mode == "WRITE"
    assert delta.resource_use.rows == 3


def test_select_is_read_only(conn):
    adapter = SqlAdapter(conn)
    delta = simdiff("SELECT * FROM users", adapter)
    assert delta.fully_classified is True
    modes = {d.mode for d in delta.data_access}
    assert modes <= {"READ"}
    assert all(d.mode != "WRITE" for d in delta.data_access)


def test_select_reports_row_count(conn):
    # guard for the streaming row-count refactor: the count must stay exact
    delta = simdiff("SELECT * FROM users", SqlAdapter(conn))
    assert delta.resource_use.rows == 3


def test_tableless_select_is_classified_read(conn):
    # `SELECT 1` touches no table; it is a harmless read, not an unknown, and must
    # not be reported with a misleading "<unknown-table>" placeholder.
    delta = simdiff("SELECT 1", SqlAdapter(conn))
    assert delta.fully_classified is True
    assert all(d.mode == "READ" for d in delta.data_access)
    assert all("<unknown-table>" not in d.resource for d in delta.data_access)


def test_unresolved_table_for_a_write_is_fail_closed(conn):
    # if a mutating statement's target table cannot be identified, the effect must
    # fail closed rather than be certified against a placeholder table.
    from simdiff.adapters.sql import _SqlEffect

    adapter = SqlAdapter(conn)
    delta = adapter.extract_delta(_SqlEffect(verb="DELETE", table=None, rows=3))
    assert delta.fully_classified is False
    assert delta.unknown


def test_unsupported_statement_is_fail_closed(conn):
    adapter = SqlAdapter(conn)
    delta = simdiff("VACUUM", adapter)
    assert delta.fully_classified is False
    assert delta.unknown


def test_syntax_error_is_fail_closed(conn):
    adapter = SqlAdapter(conn)
    delta = simdiff("INSERT INTO nope_table_xyz VALUES (1)", adapter)
    assert delta.fully_classified is False
    assert _count(conn) == 3
