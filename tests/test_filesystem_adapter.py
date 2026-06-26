import os

from simdiff import simdiff
from simdiff.adapters.filesystem import FilesystemAdapter


def _write(path, data):
    with open(path, "w") as f:
        f.write(data)


def test_create_file_is_data_access_create(tmp_path):
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        _write(os.path.join(root, "new.txt"), "hello")

    delta = simdiff(action, adapter)
    assert delta.fully_classified is True
    creates = [d for d in delta.data_access if d.resource == "new.txt"]
    assert len(creates) == 1
    assert creates[0].mode == "CREATE"
    assert creates[0].bytes == 5


def test_original_directory_is_not_mutated(tmp_path):
    _write(str(tmp_path / "keep.txt"), "original")
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        _write(os.path.join(root, "keep.txt"), "TAMPERED")
        os.remove(os.path.join(root, "keep.txt")) if False else None

    simdiff(action, adapter)
    # the real directory must be untouched
    assert (tmp_path / "keep.txt").read_text() == "original"


def test_modify_existing_file_is_write(tmp_path):
    _write(str(tmp_path / "f.txt"), "12345")
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        _write(os.path.join(root, "f.txt"), "123456789")

    delta = simdiff(action, adapter)
    writes = [d for d in delta.data_access if d.resource == "f.txt"]
    assert writes[0].mode == "WRITE"
    assert writes[0].bytes == 4  # 9 - 5


def test_delete_file_is_data_access_delete(tmp_path):
    _write(str(tmp_path / "gone.txt"), "bye")
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        os.remove(os.path.join(root, "gone.txt"))

    delta = simdiff(action, adapter)
    dels = [d for d in delta.data_access if d.resource == "gone.txt"]
    assert dels[0].mode == "DELETE"


def test_chmod_is_authority_grant(tmp_path):
    p = tmp_path / "s.txt"
    _write(str(p), "x")
    os.chmod(p, 0o644)
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        os.chmod(os.path.join(root, "s.txt"), 0o777)

    delta = simdiff(action, adapter)
    grants = [g for g in delta.authority_grants if g.target == "s.txt"]
    assert grants[0].kind == "mode"
    assert grants[0].new.endswith("777")


def test_same_size_content_change_is_still_write(tmp_path):
    # a malicious rewrite that keeps the byte count identical must not slip through
    _write(str(tmp_path / "cfg.txt"), "AAAAA")
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        _write(os.path.join(root, "cfg.txt"), "BBBBB")  # same length, different content

    delta = simdiff(action, adapter)
    writes = [d for d in delta.data_access if d.resource == "cfg.txt"]
    assert len(writes) == 1
    assert writes[0].mode == "WRITE"


def test_empty_directory_creation_is_detected(tmp_path):
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        os.mkdir(os.path.join(root, "newdir"))

    delta = simdiff(action, adapter)
    creates = [d for d in delta.data_access if d.resource == "newdir"]
    assert len(creates) == 1
    assert creates[0].mode == "CREATE"


def test_action_that_raises_is_fail_closed(tmp_path):
    adapter = FilesystemAdapter(str(tmp_path))

    def action(root):
        raise RuntimeError("boom")

    delta = simdiff(action, adapter)
    assert delta.fully_classified is False
    assert any("boom" in u for u in delta.unknown)
