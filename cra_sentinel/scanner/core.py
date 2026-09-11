"""Scan orchestration: manifests -> components -> vulnerabilities -> assessment."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .. import __version__
from ..assess import article14
from ..evidence.ledger import Ledger
from ..model import Component, ScanResult
from . import detectors
from .intel import Intel


def _project_identity(root: Path, override_name: str = "",
                      override_version: str = "") -> tuple[str, str]:
    """Best-effort product name and version from the repository itself."""
    name, version = override_name, override_version

    candidates = [
        ("package.json", lambda t: (json.loads(t).get("name"), json.loads(t).get("version"))),
        ("pyproject.toml", lambda t: (
            (re.search(r'^\s*name\s*=\s*"([^"]+)"', t, re.M) or [None, None])[1],
            (re.search(r'^\s*version\s*=\s*"([^"]+)"', t, re.M) or [None, None])[1])),
        ("Cargo.toml", lambda t: (
            (re.search(r'^\s*name\s*=\s*"([^"]+)"', t, re.M) or [None, None])[1],
            (re.search(r'^\s*version\s*=\s*"([^"]+)"', t, re.M) or [None, None])[1])),
        ("composer.json", lambda t: (json.loads(t).get("name"), json.loads(t).get("version"))),
    ]
    for filename, extract in candidates:
        if name and version:
            break
        path = root / filename
        if not path.is_file():
            continue
        try:
            found_name, found_version = extract(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        name = name or (found_name or "")
        version = version or (found_version or "")

    return (name or root.resolve().name, version or "0.0.0")


def _dedupe(components: list[Component]) -> list[Component]:
    """Same package resolved from several manifests is one component."""
    merged: dict[str, Component] = {}
    for component in components:
        existing = merged.get(component.key)
        if existing is None:
            merged[component.key] = component
            continue
        existing.direct = existing.direct or component.direct
        if component.scope == "required":
            existing.scope = "required"
        if component.licenses and not existing.licenses:
            existing.licenses = component.licenses
        if component.source not in existing.source:
            existing.source = f"{existing.source}, {component.source}"
    return sorted(merged.values(), key=lambda c: (c.ecosystem, c.full_name.lower(), c.version))


def scan(root: Path, offline: bool = False, include_dev: bool = False,
         name: str = "", version: str = "", cache_dir: Path | None = None,
         log=lambda *_: None) -> ScanResult:
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"{root} is not a directory")

    project_name, project_version = _project_identity(root, name, version)
    log(f"scanning {root}")

    manifests = detectors.discover_manifests(root)
    log(f"found {len(manifests)} manifest(s)")

    components: list[Component] = []
    for manifest in manifests:
        parsed = detectors.parse(manifest, root)
        rel = str(manifest.relative_to(root))
        log(f"  {rel}: {len(parsed)} component(s)")
        components.extend(parsed)

    components = _dedupe(components)
    if not include_dev:
        shipped = [c for c in components if c.scope != "dev"]
        if len(shipped) != len(components):
            log(f"excluding {len(components)-len(shipped)} dev-only component(s) "
                f"(use --include-dev to keep them)")
        components = shipped

    result = ScanResult(
        project_name=project_name,
        project_version=project_version,
        project_path=str(root),
        components=components,
        manifests=[str(m.relative_to(root)) for m in manifests],
        offline=offline,
        tool_version=__version__,
    )

    intel = Intel(cache_dir or (root / ".cra-sentinel" / "cache"),
                  offline=offline, log=log)
    if components:
        findings = intel.enrich(components)
        result.advisory_data_available = intel.advisory_data_available or bool(intel.kev)
        log(f"{findings} finding(s) across {len(result.unique_vulns)} unique advisories")
        if result.kev_vulns:
            log(f"{len(result.kev_vulns)} actively exploited (CISA KEV)")

    triage = Ledger(root).current()
    result.checks = article14.run_checks(result, root, triage_count=len(triage))
    result.readiness_score = article14.score(result.checks)
    log(f"readiness score: {result.readiness_score}/100")

    return result
