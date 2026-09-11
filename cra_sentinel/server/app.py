"""Local compliance dashboard.

A read-mostly HTTP surface over the same scan engine, so a compliance officer
who will never open a terminal can still pull the current report, re-run a scan,
and record a triage decision. Binds to loopback by default: this exposes an
organisation's vulnerability posture and is not meant for public networks.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import __version__, term
from ..evidence.ledger import Ledger
from ..exporters import cyclonedx
from ..report import html as html_report
from ..scanner.core import scan as run_scan

_lock = threading.Lock()
_state: dict = {"scan": None, "root": None, "supplier": "", "offline": False}


def _refresh() -> None:
    with _lock:
        _state["scan"] = run_scan(_state["root"], offline=_state["offline"],
                                  log=lambda *_: None)


def _current():
    if _state["scan"] is None:
        _refresh()
    return _state["scan"]


class Handler(BaseHTTPRequestHandler):
    server_version = f"CRASentinel/{__version__}"

    def log_message(self, fmt, *args):  # quieter than the stdlib default
        print(term.grey(f"  · {self.address_string()} {fmt % args}"))

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, indent=2).encode(), "application/json")

    def do_GET(self) -> None:
        route = urlparse(self.path)
        path = route.path

        if path in ("/", "/index.html"):
            scan = _current()
            triage = Ledger(_state["root"]).current()
            page = html_report.render(scan, supplier=_state["supplier"], triage=triage)
            page = page.replace("</body>", _CONTROLS + "</body>")
            self._send(200, page.encode(), "text/html; charset=utf-8")

        elif path == "/api/scan":
            scan = _current()
            self._json(200, scan.to_dict())

        elif path == "/api/rescan":
            _refresh()
            scan = _current()
            self._json(200, {"scan_id": scan.scan_id,
                             "readiness_score": scan.readiness_score,
                             "components": len(scan.components),
                             "findings": len(scan.unique_vulns),
                             "actively_exploited": len(scan.kev_vulns)})

        elif path == "/api/sbom":
            scan = _current()
            triage = Ledger(_state["root"]).current()
            doc = cyclonedx.build(scan, supplier=_state["supplier"], triage=triage)
            self._send(200, json.dumps(doc, indent=2).encode(), "application/json")

        elif path == "/api/ledger":
            entries = Ledger(_state["root"]).all_entries()
            self._json(200, {"entries": [e.__dict__ for e in entries]})

        elif path == "/api/health":
            self._json(200, {"status": "ok", "version": __version__,
                             "root": str(_state["root"])})

        else:
            self._json(404, {"error": "not found",
                             "routes": ["/", "/api/scan", "/api/rescan", "/api/sbom",
                                        "/api/ledger", "/api/health"]})

    def do_POST(self) -> None:
        route = urlparse(self.path)
        if route.path != "/api/triage":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            data = json.loads(raw) if raw.lstrip().startswith("{") else \
                {k: v[0] for k, v in parse_qs(raw).items()}
            entry = Ledger(_state["root"]).record(
                vuln_id=data["vuln_id"], status=data["status"],
                rationale=data.get("rationale", ""),
                justification=data.get("justification", ""),
                component=data.get("component", ""),
                remediation_plan=data.get("plan", ""),
                author=data.get("author", "dashboard"))
            self._json(201, {"recorded": entry.vuln_id, "hash": entry.entry_hash})
        except (KeyError, ValueError) as exc:
            self._json(400, {"error": str(exc)})


_CONTROLS = """
<div style="position:fixed;right:18px;bottom:18px;display:flex;gap:8px;z-index:99">
  <a href="/api/sbom" download="sbom.cdx.json"
     style="font:590 13px system-ui;padding:9px 14px;border-radius:8px;
     background:var(--surface);border:1px solid var(--line);color:var(--ink-2);
     box-shadow:var(--shadow);text-decoration:none">Download SBOM</a>
  <button onclick="this.textContent='Scanning…';this.disabled=true;
     fetch('/api/rescan').then(function(){location.reload()})"
     style="font:590 13px system-ui;padding:9px 14px;border-radius:8px;
     background:var(--accent);border:1px solid var(--accent);color:var(--surface);
     box-shadow:var(--shadow);cursor:pointer">Re-scan</button>
</div>
"""


def serve(root: Path, host: str = "127.0.0.1", port: int = 8787,
          supplier: str = "", offline: bool = False) -> int:
    _state.update({"root": root, "supplier": supplier, "offline": offline})

    print(term.header("Compliance dashboard", str(root)))
    print(term.grey("  performing initial scan…"))
    _refresh()
    scan = _current()
    print(term.kv("Readiness", f"{scan.readiness_score}/100"))
    print(term.kv("Actively exploited", term.red(str(len(scan.kev_vulns)))
                  if scan.kev_vulns else "0"))
    print()
    url = f"http://{host}:{port}/"
    print(term.kv("Dashboard", term.cyan(url)))
    print(term.kv("API", term.grey("/api/scan · /api/rescan · /api/sbom · /api/ledger")))
    print()
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(term.yellow("  Warning: bound to a non-loopback address. This dashboard "
                          "exposes\n  your vulnerability posture and has no "
                          "authentication."))
        print()
    print(term.grey("  Ctrl-C to stop."))
    print()

    httpd = ThreadingHTTPServer((host, port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n" + term.grey("  stopped"))
    finally:
        httpd.server_close()
    return 0
