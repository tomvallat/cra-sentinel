"""Core data model for CRA Sentinel.

Everything downstream (SBOM export, OSV enrichment, Article 14 assessment,
CSAF/VEX advisories) is built on these three structures.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

# purl type  ->  OSV ecosystem name
OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "composer": "Packagist",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "hex": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# purl spec: only unreserved characters survive unencoded in a segment. "@" in
# particular MUST be encoded, or a scoped npm namespace becomes ambiguous with
# the version separator (pkg:npm/@scope/pkg@1.0 has two readings).
_PURL_UNRESERVED = re.compile(r"[^A-Za-z0-9._~+-]")


def _purl_encode(value: str) -> str:
    """Percent-encode one purl segment."""
    return _PURL_UNRESERVED.sub(
        lambda m: "".join("%%%02X" % b for b in m.group().encode("utf-8")), value)


def _purl_encode_path(value: str) -> str:
    """Encode a namespace, preserving "/" as the segment separator."""
    return "/".join(_purl_encode(part) for part in value.split("/") if part)


@dataclass
class Component:
    """One software component discovered in the product."""

    name: str
    version: str
    ecosystem: str                    # purl type: npm, pypi, golang, ...
    namespace: str | None = None      # maven groupId, npm scope, go module prefix
    direct: bool = True               # direct dependency vs transitive
    scope: str = "required"           # required | optional | dev
    licenses: list[str] = field(default_factory=list)
    source: str = ""                  # manifest file it was found in
    vulnerabilities: list["Vulnerability"] = field(default_factory=list)

    @property
    def purl(self) -> str:
        ns = f"{_purl_encode_path(self.namespace)}/" if self.namespace else ""
        return f"pkg:{self.ecosystem}/{ns}{_purl_encode(self.name)}@{_purl_encode(self.version)}"

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{self.full_name}|{self.version}"

    @property
    def full_name(self) -> str:
        if self.namespace and self.ecosystem == "maven":
            return f"{self.namespace}:{self.name}"
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name

    @property
    def bom_ref(self) -> str:
        return self.purl

    @property
    def osv_ecosystem(self) -> str | None:
        return OSV_ECOSYSTEM.get(self.ecosystem)

    @property
    def max_severity(self) -> str:
        if not self.vulnerabilities:
            return "NONE"
        return max((v.severity for v in self.vulnerabilities), key=lambda s: SEVERITY_ORDER.get(s, 0))

    @property
    def kev_hits(self) -> list["Vulnerability"]:
        return [v for v in self.vulnerabilities if v.kev]


@dataclass
class Vulnerability:
    """A vulnerability affecting a component, as reported by OSV."""

    id: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str = ""
    published: str = ""
    modified: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    kev: bool = False                 # listed in CISA Known Exploited Vulnerabilities
    kev_due_date: str = ""
    kev_ransomware: bool = False
    component_key: str = ""

    @property
    def cve(self) -> str:
        if self.id.startswith("CVE-"):
            return self.id
        for a in self.aliases:
            if a.startswith("CVE-"):
                return a
        return self.id

    @property
    def article14_reportable(self) -> bool:
        """CRA Art. 14(1): actively exploited vulnerabilities must be reported."""
        return self.kev


@dataclass
class ScanResult:
    """Complete output of one scan — the unit of evidence under the CRA."""

    project_name: str
    project_version: str
    project_path: str
    scanned_at: str = field(default_factory=utcnow)
    components: list[Component] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    checks: list[Any] = field(default_factory=list)      # assess.Check
    readiness_score: int = 0
    offline: bool = False
    advisory_data_available: bool = True
    tool_version: str = ""

    @property
    def unverified(self) -> bool:
        """True when no advisory source could be consulted. A zero-finding
        result then means 'not checked', never 'clean' — and a compliance tool
        must never let those two be confused."""
        return not self.advisory_data_available and bool(self.components)

    @property
    def scan_id(self) -> str:
        seed = f"{self.project_path}|{self.scanned_at}"
        return "cras-" + hashlib.sha256(seed.encode()).hexdigest()[:16]

    @property
    def all_vulns(self) -> list[Vulnerability]:
        return [v for c in self.components for v in c.vulnerabilities]

    @property
    def unique_vulns(self) -> list[Vulnerability]:
        seen, out = set(), []
        for v in self.all_vulns:
            if v.id not in seen:
                seen.add(v.id)
                out.append(v)
        return out

    @property
    def kev_vulns(self) -> list[Vulnerability]:
        return [v for v in self.unique_vulns if v.kev]

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for v in self.unique_vulns:
            counts[v.severity if v.severity in counts else "UNKNOWN"] += 1
        return counts

    def to_dict(self) -> dict:
        d = asdict(self)
        d["scan_id"] = self.scan_id
        d["severity_counts"] = self.severity_counts()
        for c, cd in zip(self.components, d["components"]):
            cd["purl"] = c.purl
        return d
