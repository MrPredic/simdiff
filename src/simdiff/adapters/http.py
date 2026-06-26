"""HTTP adapter: classify the *egress* of a request without ever sending it.

Sending the request would be the exact thing we are trying to gate, so the
adapter is purely lexical: it parses the URL, decides whether the destination is
on the egress allowlist, and measures how many bytes would leave. Data
exfiltration is about *where data goes*, not what the payload string looks like —
so base64, encryption, or stuffing the secret in a query parameter changes the
surface text but not the detected effect.

Egress to a non-allowed host is modelled as a value move (``bytes`` leaving
``local`` for the destination host), which any policy that flags value moves will
catch. A request whose host cannot be parsed is fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set
from urllib.parse import urlparse

from ..delta import CanonicalDelta, ValueMove


@dataclass
class HttpRequest:
    method: str
    url: str
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)


class HttpAdapter:
    domain = "http"

    def __init__(self, allowed_hosts: Optional[Set[str]] = None, sensitive_markers: Optional[Set[str]] = None):
        self.allowed_hosts: Set[str] = set(allowed_hosts or ())
        self.sensitive_markers: Set[str] = set(sensitive_markers or ())

    def simulate(self, action: HttpRequest) -> HttpRequest:
        # No network. The request itself is the thing we inspect.
        return action

    def extract_delta(self, effect: HttpRequest, principal: Optional[str] = None) -> CanonicalDelta:
        parsed = urlparse(effect.url)
        host = parsed.hostname
        if not host or " " in effect.url.strip():
            return CanonicalDelta(unknown=[f"could not parse a destination host from URL: {effect.url!r}"])

        if host in self.allowed_hosts:
            return CanonicalDelta()  # allowed egress, nothing to flag

        header_bytes = sum(len(str(v)) for v in effect.headers.values())
        egress_bytes = len(effect.body) + len(parsed.query) + header_bytes

        carried = effect.body + parsed.query + "".join(str(v) for v in effect.headers.values())
        hits = [m for m in self.sensitive_markers if m in carried]
        reason = f"data egress to external host {host}"
        if hits:
            reason += f" (contains sensitive data: {', '.join(sorted(hits))})"

        return CanonicalDelta(
            value_moves=[ValueMove(asset="bytes", src="local", dst=host, amount=egress_bytes, reason=reason)]
        )
