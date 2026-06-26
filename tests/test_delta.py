from simdiff.delta import (
    CanonicalDelta,
    DataAccess,
    AuthorityGrant,
    ValueMove,
)


def test_empty_delta_is_safe():
    d = CanonicalDelta()
    assert d.fully_classified is True
    assert d.unknown == []


def test_delta_with_unknown_is_unsafe():
    d = CanonicalDelta(unknown=["could not parse: frobnicate /etc"])
    assert d.fully_classified is False


def test_data_access_recorded():
    d = CanonicalDelta(
        data_access=[DataAccess(resource="/tmp/x", mode="WRITE", bytes=12, reason="wrote 12 bytes")]
    )
    assert d.fully_classified is True
    assert d.data_access[0].mode == "WRITE"
    assert d.data_access[0].bytes == 12


def test_to_dict_roundtrip():
    d = CanonicalDelta(
        value_moves=[ValueMove(asset="SOL", src="a", dst="b", amount=5, reason="transfer")],
        authority_grants=[AuthorityGrant(target="/tmp/x", kind="mode", old="0644", new="0777", reason="chmod")],
        data_access=[DataAccess(resource="t1", mode="DELETE", bytes=0, reason="dropped rows")],
        unknown=["mystery"],
    )
    out = d.to_dict()
    assert out["fully_classified"] is False
    assert out["value_moves"][0]["asset"] == "SOL"
    assert out["authority_grants"][0]["new"] == "0777"
    assert out["data_access"][0]["mode"] == "DELETE"
    assert out["unknown"] == ["mystery"]


def test_merge_combines_entries_and_fails_closed():
    a = CanonicalDelta(data_access=[DataAccess(resource="r1", mode="WRITE", bytes=1, reason="")])
    b = CanonicalDelta(unknown=["x"])
    merged = a.merge(b)
    assert len(merged.data_access) == 1
    assert merged.unknown == ["x"]
    assert merged.fully_classified is False
