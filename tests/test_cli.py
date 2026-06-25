import json

from simdiff.cli import main


def test_shell_safe_command_exits_zero(capsys):
    code = main(["shell", "rm a.txt && mkdir b", "--existing", "a.txt", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 0
    assert payload["safe"] is True
    resources = {d["resource"] for d in payload["data_access"]}
    assert {"a.txt", "b"} <= resources


def test_shell_unknown_command_exits_two(capsys):
    code = main(["shell", "frobnicate /etc", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["safe"] is False


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
