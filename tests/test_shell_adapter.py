from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter


def test_rm_existing_file_is_delete():
    adapter = ShellAdapter(existing={"old.txt"})
    delta = simdiff("rm old.txt", adapter)
    assert delta.fully_classified is True
    assert delta.data_access[0].resource == "old.txt"
    assert delta.data_access[0].mode == "DELETE"


def test_mkdir_is_create():
    adapter = ShellAdapter()
    delta = simdiff("mkdir -p build/out", adapter)
    assert delta.data_access[0].mode == "CREATE"
    assert delta.data_access[0].resource == "build/out"


def test_mv_is_delete_source_create_dest():
    adapter = ShellAdapter(existing={"a.txt"})
    delta = simdiff("mv a.txt b.txt", adapter)
    modes = {(d.resource, d.mode) for d in delta.data_access}
    assert ("a.txt", "DELETE") in modes
    assert ("b.txt", "CREATE") in modes


def test_chmod_is_authority_grant():
    adapter = ShellAdapter(existing={"s.txt"})
    delta = simdiff("chmod 777 s.txt", adapter)
    assert delta.authority_grants[0].kind == "mode"
    assert delta.authority_grants[0].new == "777"


def test_redirect_is_write():
    adapter = ShellAdapter()
    delta = simdiff("echo hello > out.txt", adapter)
    wr = [d for d in delta.data_access if d.resource == "out.txt"]
    assert wr[0].mode in {"CREATE", "WRITE"}


def test_unknown_command_is_fail_closed():
    adapter = ShellAdapter()
    delta = simdiff("frobnicate --all /etc", adapter)
    assert delta.fully_classified is False
    assert any("frobnicate" in u for u in delta.unknown)


def test_chained_commands_are_merged():
    adapter = ShellAdapter(existing={"a.txt"})
    delta = simdiff("rm a.txt && mkdir c", adapter)
    resources = {d.resource for d in delta.data_access}
    assert {"a.txt", "c"} <= resources


def test_rm_nonexistent_is_noop():
    adapter = ShellAdapter(existing=set())
    delta = simdiff("rm ghost.txt", adapter)
    # nothing to delete; still safe, no spurious data access
    assert delta.fully_classified is True
    assert delta.data_access == []
