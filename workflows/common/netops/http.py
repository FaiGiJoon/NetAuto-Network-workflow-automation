"""JSON over HTTP with the standard library: auth headers, TLS and errors."""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request


class HttpError(Exception):
    def __init__(self, status: int, body: str, url: str = ""):
        super().__init__(f"HTTP {status} from {url}: {body[:300]}")
        self.status = status
        self.body = body


def basic_auth(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def tls_context(verify: bool = True, ca_file: str | None = None) -> ssl.SSLContext:
    """verify=False is only for lab devices with self-signed certificates."""
    ca_file = ca_file or os.environ.get("NETOPS_CA_FILE") or None
    ctx = ssl.create_default_context(cafile=ca_file)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(method: str, url: str, *, headers: dict | None = None, body=None, params: dict | None = None,
            timeout: int = 20, context: ssl.SSLContext | None = None, form: bool = False):
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    data = None
    req_headers = {"Accept": "application/json"}
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            req_headers["Content-Type"] = "application/json"
    req_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            raw = resp.read().decode() or "null"
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code, exc.read().decode(errors="replace"), url) from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw
