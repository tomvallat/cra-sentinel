"""CRA readiness assessment.

Each check maps to a specific obligation in Regulation (EU) 2024/2847. A check
never guesses: it either finds evidence in the repository, finds a finding in
the scan, or reports MANUAL so the manufacturer knows a human must attest it.
That distinction is the whole point — an auditor accepts evidence, not a score.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

PASS, FAIL, WARN, MANUAL = "pass", "fail", "warn", "manual"

# Regulation (EU) 2024/2847 milestones
DEADLINES = [
    ("2026-09-11", "Article 14 — reporting of actively exploited vulnerabilities "
                   "and severe incidents becomes applicable"),
    ("2027-06-11", "Notified-body / conformity-assessment provisions apply"),
    ("2027-12-11", "Full application: all essential requirements (Annex I) and "
                   "CE marking obligations"),
]


@dataclass
class Check:
    id: str
    title: str
    cra_ref: str
    status: str
    weight: int
    evidence: str = ""
    remediation: str = ""
    category: str = "process"
    artifacts: list[str] = field(default_factory=list)

    def __post_init__(self):
        # A passing control has nothing to remediate. Enforced here rather than
        # at each call site so a new check cannot reintroduce the mismatch.
        if self.status == PASS:
            self.remediation = ""

    @property
    def points(self) -> int:
        return {PASS: self.weight, WARN: self.weight // 2}.get(self.status, 0)


def _find(root: Path, *names: str) -> Path | None:
    """Case-insensitive lookup at repo root, .github/ and docs/."""
    targets = {n.lower() for n in names}
    for directory in (root, root / ".github", root / "docs", root / ".well-known"):
        if not directory.is_dir():
            continue
        try:
            for entry in directory.iterdir():
                if entry.is_file() and entry.name.lower() in targets:
                    return entry
        except OSError:
            continue
    return None


def _read(path: Path | None, limit: int = 20000) -> str:
    if not path:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)) if path.is_relative_to(root) else str(path)


def run_checks(scan, root: Path, triage_count: int = 0) -> list[Check]:
    checks: list[Check] = []
    add = checks.append

    security_file = _find(root, "SECURITY.md", "SECURITY.txt", "security.txt", "SECURITY")
    security_text = _read(security_file)
    security_lower = security_text.lower()
    readme_text = _read(_find(root, "README.md", "README.rst", "README.txt", "README")).lower()

    # -- Annex I Part II(1): identify and document components -------------
    sbom_file = _find(root, "sbom.json", "bom.json", "sbom.cdx.json", "sbom.spdx.json")
    if sbom_file:
        add(Check("SBOM-01", "Machine-readable SBOM present in the repository",
                  "Annex I, Part II(1)", PASS, 10, category="sbom",
                  evidence=f"Found {_rel(sbom_file, root)}",
                  artifacts=[_rel(sbom_file, root)]))
    elif scan.components:
        add(Check("SBOM-01", "Machine-readable SBOM present in the repository",
                  "Annex I, Part II(1)", WARN, 10, category="sbom",
                  evidence=f"No committed SBOM found, but {len(scan.components)} components "
                           f"were resolved from {len(scan.manifests)} manifest(s).",
                  remediation="Run `cra scan --sbom sbom.json` and commit the result. "
                              "CycloneDX 1.6 and SPDX 2.3 are both accepted."))
    else:
        add(Check("SBOM-01", "Machine-readable SBOM present in the repository",
                  "Annex I, Part II(1)", FAIL, 10, category="sbom",
                  evidence="No dependency manifest and no SBOM detected.",
                  remediation="The CRA requires at minimum the top-level dependencies "
                              "in a machine-readable format."))

    depth = "top-level and transitive" if any(not c.direct for c in scan.components) \
        else "top-level only"
    add(Check("SBOM-02", "SBOM covers at least top-level dependencies",
              "Annex I, Part II(1)", PASS if scan.components else FAIL, 5, category="sbom",
              evidence=f"{len(scan.components)} components resolved ({depth}) across "
                       f"{len({c.ecosystem for c in scan.components})} ecosystem(s).",
              remediation="" if scan.components else
                          "Commit a lockfile so shipped versions are resolvable."))

    lockfiles = [m for m in scan.manifests if any(
        k in m for k in ("lock", "go.sum"))]
    add(Check("SBOM-03", "Shipped versions are pinned and reproducible",
              "Annex I, Part II(1)", PASS if lockfiles else WARN, 4, category="sbom",
              evidence=f"Lockfiles: {', '.join(lockfiles)}" if lockfiles else
                       "No lockfile found; versions resolved from loose manifests.",
              remediation="" if lockfiles else
                          "Commit lockfiles. Without them the SBOM describes what was "
                          "requested, not what ships — auditors reject this."))

    # -- Article 14: actively exploited vulnerabilities --------------------
    kev = scan.kev_vulns
    if kev:
        names = ", ".join(v.cve for v in kev[:4]) + (" …" if len(kev) > 4 else "")
        ransom = sum(1 for v in kev if v.kev_ransomware)
        add(Check("ART14-01", "No actively exploited vulnerability in shipped components",
                  "Article 14(1)(a)", FAIL, 25, category="article14",
                  evidence=f"{len(kev)} component vulnerabilit{'y' if len(kev) == 1 else 'ies'} "
                           f"appear in the CISA KEV catalogue: {names}"
                           + (f" — {ransom} linked to known ransomware campaigns." if ransom else ""),
                  remediation="If any of these is exploited in a product you have placed on "
                              "the EU market, Article 14 requires an early warning to ENISA "
                              "and your national CSIRT within 24 hours of becoming aware, a "
                              "full notification within 72 hours, and a final report within "
                              "14 days of a corrective measure. Remediate or file a "
                              "documented VEX justification."))
    elif getattr(scan, "unverified", False):
        add(Check("ART14-01", "No actively exploited vulnerability in shipped components",
                  "Article 14(1)(a)", MANUAL, 25, category="article14",
                  evidence="NOT VERIFIED — no advisory source could be consulted. "
                           "Zero findings here means 'not checked', not 'clean'.",
                  remediation="Re-run with network access, or seed the cache on a "
                              "connected machine and copy .cra-sentinel/cache/ across. "
                              "Do not file this report as evidence in its current state."))
    else:
        add(Check("ART14-01", "No actively exploited vulnerability in shipped components",
                  "Article 14(1)(a)", PASS, 25, category="article14",
                  evidence=f"No component matches the CISA KEV catalogue "
                           f"({len(scan.components)} components checked)."))

    proc_terms = ("24 hour", "24-hour", "24h", "enisa", "csirt", "single reporting platform")
    has_procedure = any(t in security_lower for t in proc_terms)
    add(Check("ART14-02", "Documented 24h/72h/14d reporting procedure",
              "Article 14(2)-(4)", PASS if has_procedure else FAIL, 12, category="article14",
              evidence="Reporting timeline referenced in "
                       f"{_rel(security_file, root)}" if has_procedure else
                       "No document describes who files the early warning, through which "
                       "channel, or within what deadline.",
              remediation="" if has_procedure else
                          "Write the runbook: named owner, deputy, the ENISA Single Reporting "
                          "Platform as channel, and the 24h/72h/14d clocks. Run `cra init` "
                          "to generate a compliant template."))

    has_contact = bool(security_file and re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", security_text))
    add(Check("ART14-03", "Named point of contact for vulnerability reports",
              "Article 13(19)", PASS if has_contact else FAIL, 8, category="article14",
              evidence=f"Contact address published in {_rel(security_file, root)}"
                       if has_contact else
                       "No monitored contact address published for security reports.",
              remediation="" if has_contact else
                          "Publish a single monitored address (security@…) in SECURITY.md "
                          "and /.well-known/security.txt."))

    # -- Annex I Part II(2)(5): vulnerability handling & disclosure --------
    add(Check("VULN-01", "Coordinated vulnerability disclosure policy published",
              "Annex I, Part II(5)", PASS if security_file else FAIL, 10,
              category="process",
              evidence=f"Found {_rel(security_file, root)} ({len(security_text)} bytes)"
                       if security_file else "No SECURITY.md or security.txt found.",
              remediation="" if security_file else
                          "Publish a disclosure policy stating scope, contact, and expected "
                          "response times. `cra init` scaffolds one."))

    counts = scan.severity_counts()
    unfixed = counts["CRITICAL"] + counts["HIGH"]
    if getattr(scan, "unverified", False):
        status = MANUAL
        evidence = ("NOT VERIFIED — no advisory source could be consulted for the "
                    f"{len(scan.components)} resolved components.")
    elif unfixed == 0:
        status, evidence = PASS, "No critical or high-severity vulnerability outstanding."
    elif unfixed <= 5:
        status = WARN
        evidence = f"{counts['CRITICAL']} critical and {counts['HIGH']} high-severity findings."
    else:
        status = FAIL
        evidence = f"{counts['CRITICAL']} critical and {counts['HIGH']} high-severity findings."
    add(Check("VULN-02", "Critical and high-severity vulnerabilities remediated",
              "Annex I, Part II(2)", status, 15, category="vulnerability",
              evidence=evidence,
              remediation="Re-run with network access before relying on this result."
                          if status == MANUAL else "" if status == PASS else
                          "Annex I requires vulnerabilities to be addressed and remediated "
                          "without delay. Upgrade, or record a VEX justification with "
                          "`cra triage` — an undocumented decision is a compliance gap."))

    fixable = [v for v in scan.unique_vulns if v.fixed_versions]
    add(Check("VULN-03", "No findings left unaddressed where a fix already exists",
              "Annex I, Part II(2)", PASS if not fixable else WARN, 8,
              category="vulnerability",
              evidence=f"{len(fixable)} of {len(scan.unique_vulns)} findings have a published "
                       f"fixed version available." if fixable else
                       "Every finding is either fixed or has no upstream fix.",
              remediation="" if not fixable else
                          "Upgrading these is the cheapest compliance win available."))

    add(Check("VULN-04", "Triage decisions recorded with a written rationale",
              "Annex I, Part II(2)", PASS if triage_count else
              (MANUAL if not scan.unique_vulns else FAIL), 10, category="evidence",
              evidence=f"{triage_count} triage decision(s) recorded in the evidence ledger."
                       if triage_count else
                       "No triage ledger. Findings exist with no recorded decision.",
              remediation="" if triage_count else
                          "Record a decision per finding with `cra triage <ID> --status ...`. "
                          "Auditors accept 'not affected' — they do not accept silence."))

    # -- Annex I Part II(7)(8): secure updates -----------------------------
    update_terms = ("automatic update", "security update", "ota", "firmware update",
                    "auto-update", "update mechanism", "signed update")
    has_update = any(t in security_lower or t in readme_text for t in update_terms)
    add(Check("UPD-01", "Secure update mechanism documented",
              "Annex I, Part II(7)-(8)", PASS if has_update else MANUAL, 8,
              category="process",
              evidence="Update mechanism described in project documentation."
                       if has_update else
                       "No documented update or patch-delivery mechanism found.",
              remediation="" if has_update else
                          "Annex I requires security updates to be distributed without delay "
                          "and, where applicable, automatically. Document the channel and "
                          "how update integrity is verified (signing)."))

    support_match = re.search(r"support(?:ed)?\s+(?:period|until|through)|end[- ]of[- ]life|EOL",
                              security_text + readme_text, re.I)
    add(Check("UPD-02", "Support period declared to users",
              "Article 13(8)", PASS if support_match else FAIL, 8, category="process",
              evidence="Support period / EOL policy referenced in documentation."
                       if support_match else
                       "No declared support period. The CRA presumes 5 years unless the "
                       "expected product lifetime is shorter and justified.",
              remediation="" if support_match else
                          "State the support period explicitly and publish it with the "
                          "product. It is a hard obligation, not a courtesy."))

    # -- CE marking / technical documentation ------------------------------
    add(Check("DOC-01", "Technical documentation and EU declaration of conformity",
              "Article 13(12), Annex VII", MANUAL, 10, category="conformity",
              evidence="Requires human attestation — cannot be inferred from source code.",
              remediation="Assemble the Annex VII technical file: product description, "
                          "risk assessment, applied standards, SBOM, vulnerability-handling "
                          "evidence. Required from 11 December 2027."))

    licensed = sum(1 for c in scan.components if c.licenses)
    ratio = licensed / len(scan.components) if scan.components else 0
    add(Check("DOC-02", "Component licence inventory captured",
              "Annex I, Part II(1)", PASS if ratio > 0.5 else WARN, 3, category="sbom",
              evidence=f"Licence metadata resolved for {licensed}/{len(scan.components)} "
                       f"components ({ratio:.0%}).",
              remediation="" if ratio > 0.5 else
                          "Not a CRA requirement in itself, but licence data belongs in the "
                          "same SBOM an auditor will read."))

    return checks


def score(checks: list[Check]) -> int:
    """Weighted readiness score, 0-100. MANUAL checks are excluded from the
    denominator: we do not penalise what a tool cannot verify."""
    scored = [c for c in checks if c.status != MANUAL]
    total = sum(c.weight for c in scored)
    if not total:
        return 0
    return round(100 * sum(c.points for c in scored) / total)


def grade(value: int) -> tuple[str, str]:
    if value >= 90:
        return "A", "Audit-ready"
    if value >= 75:
        return "B", "Substantially compliant"
    if value >= 55:
        return "C", "Material gaps"
    if value >= 35:
        return "D", "Non-compliant"
    return "E", "Critical exposure"


def days_until(deadline: str) -> int:
    target = datetime.strptime(deadline, "%Y-%m-%d").date()
    return (target - date.today()).days


def deadline_status() -> list[dict]:
    out = []
    for iso, label in DEADLINES:
        days = days_until(iso)
        out.append({"date": iso, "label": label, "days": days,
                    "state": "active" if days <= 0 else ("imminent" if days < 180 else "upcoming")})
    return out
