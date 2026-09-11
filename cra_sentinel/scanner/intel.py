"""Vulnerability intelligence: OSV.dev + CISA KEV.

OSV tells us *what* is vulnerable. CISA KEV tells us what is *actively
exploited* — which is the precise legal trigger for CRA Article 14(1)(a), the
24-hour early-warning obligation. Keeping the two separate matters: only the
KEV intersection starts a reporting clock.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

from ..model import Component, Vulnerability
from . import cvss

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

USER_AGENT = "CRA-Sentinel/1.0 (+compliance scanner)"
BATCH_SIZE = 100
WORKERS = 12
CACHE_TTL = 6 * 3600


@lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext:
    """TLS context with a usable CA bundle.

    Python installed from python.org on macOS ships without a populated system
    trust store until `Install Certificates.command` is run, so every HTTPS call
    fails with CERTIFICATE_VERIFY_FAILED. Falling back to certifi keeps the
    scanner working on a stock install instead of silently producing an
    unverified report. Verification stays on either way.
    """
    context = ssl.create_default_context()
    if ssl.get_default_verify_paths().cafile is None:
        try:
            import certifi
            context = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            pass
    return context


def _sort_versions(versions) -> list[str]:
    """Order version strings newest-first, tolerating non-numeric segments."""
    def key(value: str):
        parts = re.split(r"[.\-+]", value)
        return [(0, int(p)) if p.isdigit() else (1, p) for p in parts]

    try:
        return sorted(versions, key=key, reverse=True)
    except TypeError:
        return sorted(versions, reverse=True)


class Intel:
    """Fetches and caches vulnerability data. Degrades to offline gracefully."""

    def __init__(self, cache_dir: Path, offline: bool = False, timeout: int = 30,
                 log=lambda *_: None):
        self.cache_dir = cache_dir
        self.offline = offline
        self.timeout = timeout
        self.log = log
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._kev: dict[str, dict] | None = None
        self.advisory_data_available = False   # set once a query actually succeeds
        self._detail_cache = self.cache_dir / "osv-details.json"
        self._details: dict[str, dict] = self._load_json(self._detail_cache, {})

    # -- plumbing ---------------------------------------------------------

    def _load_json(self, path: Path, default):
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return default

    def _post(self, url: str, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout,
                                    context=_ssl_context()) as resp:
            return json.loads(resp.read())

    def _get(self, url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout,
                                    context=_ssl_context()) as resp:
            return json.loads(resp.read())

    def _explain(self, exc: Exception) -> str:
        """Turn a transport failure into something the user can act on."""
        text = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in text:
            return ("TLS certificate verification failed. On a python.org install "
                    "for macOS, run:  /Applications/Python\\ 3.x/Install\\ "
                    "Certificates.command   (or: pip install certifi)")
        if isinstance(exc, TimeoutError) or "timed out" in text:
            return f"network timeout after {self.timeout}s"
        return text

    # -- CISA KEV ---------------------------------------------------------

    @property
    def kev(self) -> dict[str, dict]:
        """CVE id -> KEV entry. Cached on disk for CACHE_TTL."""
        if self._kev is not None:
            return self._kev

        cache = self.cache_dir / "cisa-kev.json"
        if cache.exists() and (time.time() - cache.stat().st_mtime) < CACHE_TTL:
            self._kev = self._load_json(cache, {})
            if self._kev:
                return self._kev

        if self.offline:
            self._kev = self._load_json(cache, {})
            return self._kev

        try:
            self.log("fetching CISA Known Exploited Vulnerabilities catalog")
            raw = self._get(KEV_URL)
            self._kev = {
                e["cveID"]: {
                    "due": e.get("dueDate", ""),
                    "ransomware": e.get("knownRansomwareCampaignUse", "").lower() == "known",
                    "added": e.get("dateAdded", ""),
                    "name": e.get("vulnerabilityName", ""),
                    "action": e.get("requiredAction", ""),
                }
                for e in raw.get("vulnerabilities", [])
            }
            cache.write_text(json.dumps(self._kev))
            self.log(f"KEV catalog: {len(self._kev)} actively exploited CVEs")
        except (urllib.error.URLError, ssl.SSLError, ValueError, KeyError,
                TimeoutError, OSError) as exc:
            self.log(f"KEV fetch failed: {self._explain(exc)}")
            self.log("falling back to cached catalogue")
            self._kev = self._load_json(cache, {})
        return self._kev

    # -- OSV --------------------------------------------------------------

    def _osv_details(self, vuln_ids: list[str]) -> dict[str, dict]:
        missing = [v for v in vuln_ids if v not in self._details]
        if missing and not self.offline:
            self.log(f"fetching {len(missing)} advisory records from OSV")

            def fetch(vid: str) -> tuple[str, dict]:
                try:
                    return vid, self._get(OSV_VULN_URL + vid)
                except (urllib.error.URLError, ssl.SSLError, ValueError,
                        TimeoutError, OSError):
                    return vid, {}

            done = 0
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                for vid, raw in pool.map(fetch, missing):
                    self._details[vid] = raw
                    done += 1
                    if done % 50 == 0 or done == len(missing):
                        self.log(f"  {done}/{len(missing)}")
            try:
                self._detail_cache.write_text(json.dumps(self._details))
            except OSError:
                pass
        return self._details

    def enrich(self, components: list[Component]) -> int:
        """Attach vulnerabilities to components. Returns count of findings."""
        queryable = [c for c in components if c.osv_ecosystem]
        if not queryable:
            return 0

        id_map: dict[int, list[str]] = {}
        if not self.offline:
            for start in range(0, len(queryable), BATCH_SIZE):
                chunk = queryable[start:start + BATCH_SIZE]
                payload = {"queries": [
                    {"package": {"name": c.full_name, "ecosystem": c.osv_ecosystem},
                     "version": c.version}
                    for c in chunk
                ]}
                try:
                    result = self._post(OSV_BATCH_URL, payload)
                except (urllib.error.URLError, ssl.SSLError, ValueError,
                        TimeoutError, OSError) as exc:
                    self.log(f"OSV query failed: {self._explain(exc)}")
                    continue
                self.advisory_data_available = True
                for offset, entry in enumerate(result.get("results", [])):
                    ids = [v["id"] for v in (entry.get("vulns") or [])]
                    if ids:
                        id_map[start + offset] = ids
                self.log(f"queried {min(start + BATCH_SIZE, len(queryable))}/{len(queryable)} components")

        all_ids = sorted({vid for ids in id_map.values() for vid in ids})
        details = self._osv_details(all_ids)
        kev = self.kev

        found = 0
        for index, ids in id_map.items():
            component = queryable[index]
            for vid in ids:
                vuln = self._build(vid, details.get(vid, {}), component, kev)
                component.vulnerabilities.append(vuln)
                found += 1
            component.vulnerabilities.sort(
                key=lambda v: (not v.kev, -(v.cvss_score or 0)))
        return found

    def _build(self, vid: str, raw: dict, component: Component,
               kev: dict[str, dict]) -> Vulnerability:
        aliases = raw.get("aliases", []) or []

        vector, score, severity = "", None, "UNKNOWN"
        for entry in raw.get("severity", []) or []:
            candidate = entry.get("score", "")
            if candidate.startswith("CVSS:"):
                s, b = cvss.evaluate(candidate)
                if s is not None and (score is None or s > score):
                    vector, score, severity = candidate, s, b
        if severity == "UNKNOWN":
            declared = (raw.get("database_specific") or {}).get("severity")
            if isinstance(declared, str) and declared.upper() in (
                    "CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
                severity = "MEDIUM" if declared.upper() == "MODERATE" else declared.upper()

        # Only collect fixed versions from the `affected` entry that actually
        # describes THIS package. A single advisory often covers several
        # packages (log4j-core and log4j:log4j, for example) with different
        # fix versions — mixing them yields wrong remediation advice.
        fixed = []
        for affected in raw.get("affected", []) or []:
            pkg = affected.get("package") or {}
            if pkg.get("ecosystem") and pkg["ecosystem"] != component.osv_ecosystem:
                continue
            if pkg.get("name") and pkg["name"].lower() != component.full_name.lower():
                continue
            for rng in affected.get("ranges", []) or []:
                for event in rng.get("events", []) or []:
                    if event.get("fixed"):
                        fixed.append(event["fixed"])

        cwes = [c for c in ((raw.get("database_specific") or {}).get("cwe_ids") or [])]

        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        if vid.startswith("CVE-"):
            cve_ids.append(vid)
        kev_entry = next((kev[c] for c in cve_ids if c in kev), None)

        return Vulnerability(
            id=vid,
            summary=raw.get("summary", "") or (raw.get("details", "")[:140]),
            details=raw.get("details", "")[:2000],
            aliases=aliases,
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            published=raw.get("published", ""),
            modified=raw.get("modified", ""),
            fixed_versions=_sort_versions(set(fixed))[:5],
            references=[r.get("url", "") for r in (raw.get("references") or [])][:6],
            cwe_ids=cwes,
            kev=kev_entry is not None,
            kev_due_date=(kev_entry or {}).get("due", ""),
            kev_ransomware=(kev_entry or {}).get("ransomware", False),
            component_key=component.key,
        )
