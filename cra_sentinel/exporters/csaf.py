"""CSAF 2.0 security advisory export.

CSAF is the machine-readable advisory format the CRA ecosystem is standardising
on. Two profiles are produced:
  - "csaf_vex"             : your impact statement per vulnerability
  - "csaf_security_advisory": a published advisory for your own product
"""
from __future__ import annotations

from ..model import utcnow

_CSAF_STATUS = {
    "affected": "known_affected",
    "not_affected": "known_not_affected",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
    "false_positive": "known_not_affected",
}

_CSAF_FLAG = {
    "component_not_present": "component_not_present",
    "vulnerable_code_not_present": "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary":
        "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}


def build(scan, supplier: str = "", tracking_id: str = "",
          profile: str = "csaf_vex", triage: dict | None = None,
          only_kev: bool = False) -> dict:
    triage = triage or {}
    publisher_name = supplier or scan.project_name
    tracking_id = tracking_id or f"{scan.project_name.upper()}-{scan.scanned_at[:10]}"

    product_id = "PRODUCT-0001"
    product_full = f"{scan.project_name} {scan.project_version}"

    vulns = scan.kev_vulns if only_kev else scan.unique_vulns
    title = (f"Actively exploited vulnerabilities in {product_full}" if only_kev
             else f"Vulnerability assessment for {product_full}")

    doc = {
        "document": {
            "category": profile,
            "csaf_version": "2.0",
            "title": title,
            "lang": "en",
            "publisher": {
                "category": "vendor",
                "name": publisher_name,
                "namespace": f"https://{_slug(publisher_name)}.example",
            },
            "tracking": {
                "id": tracking_id,
                "status": "final",
                "version": "1",
                "initial_release_date": scan.scanned_at,
                "current_release_date": utcnow(),
                "generator": {
                    "engine": {"name": "CRA Sentinel", "version": scan.tool_version},
                    "date": utcnow(),
                },
                "revision_history": [{
                    "number": "1",
                    "date": scan.scanned_at,
                    "summary": "Initial machine-generated assessment.",
                }],
            },
            "notes": [{
                "category": "legal_disclaimer",
                "title": "Scope",
                "text": ("Generated from a dependency analysis under Regulation (EU) "
                         "2024/2847. Automated findings require review by the "
                         "manufacturer before publication."),
            }],
        },
        "product_tree": {
            "branches": [{
                "category": "vendor",
                "name": publisher_name,
                "branches": [{
                    "category": "product_name",
                    "name": scan.project_name,
                    "branches": [{
                        "category": "product_version",
                        "name": scan.project_version,
                        "product": {
                            "product_id": product_id,
                            "name": product_full,
                        },
                    }],
                }],
            }],
        },
        "vulnerabilities": [],
    }

    for vuln in vulns:
        decision = triage.get(vuln.id)
        status = _CSAF_STATUS.get(decision.status, "under_investigation") if decision \
            else "under_investigation"

        entry: dict = {
            "cve": vuln.cve if vuln.cve.startswith("CVE-") else None,
            "title": vuln.summary or vuln.id,
            "notes": [{
                "category": "description",
                "title": "Description",
                "text": (vuln.details or vuln.summary or "No description available.")[:1500],
            }],
            "product_status": {status: [product_id]},
            "references": [{"category": "external", "summary": "OSV record",
                            "url": f"https://osv.dev/vulnerability/{vuln.id}"}]
                          + [{"category": "external", "summary": "Reference", "url": u}
                             for u in vuln.references[:3] if u],
        }
        if entry["cve"] is None:
            del entry["cve"]
            entry["ids"] = [{"system_name": "OSV", "text": vuln.id}]

        if vuln.cvss_vector and vuln.cvss_score is not None:
            entry["scores"] = [{
                "products": [product_id],
                "cvss_v3": {
                    "version": "3.1",
                    "vectorString": vuln.cvss_vector,
                    "baseScore": vuln.cvss_score,
                    "baseSeverity": vuln.severity,
                },
            }] if vuln.cvss_vector.startswith("CVSS:3") else []
            if not entry["scores"]:
                del entry["scores"]

        if vuln.cwe_ids:
            entry["cwe"] = {"id": vuln.cwe_ids[0], "name": vuln.cwe_ids[0]}

        if decision and decision.justification and status == "known_not_affected":
            entry["flags"] = [{
                "label": _CSAF_FLAG.get(decision.justification, "vulnerable_code_not_present"),
                "product_ids": [product_id],
            }]
        if decision:
            entry["notes"].append({
                "category": "other",
                "title": "Manufacturer assessment",
                "text": f"{decision.rationale} (recorded {decision.recorded_at} "
                        f"by {decision.author})",
            })

        remediations = []
        if vuln.fixed_versions:
            remediations.append({
                "category": "vendor_fix",
                "details": f"Upgrade the affected component to {vuln.fixed_versions[0]} or later.",
                "product_ids": [product_id],
            })
        if decision and decision.remediation_plan:
            remediations.append({
                "category": "workaround" if status == "known_affected" else "none_available",
                "details": decision.remediation_plan,
                "product_ids": [product_id],
            })
        if remediations:
            entry["remediations"] = remediations

        if vuln.kev:
            entry.setdefault("notes", []).append({
                "category": "general",
                "title": "Active exploitation",
                "text": ("Listed in the CISA Known Exploited Vulnerabilities catalogue. "
                         "If this product is affected and placed on the EU market, "
                         "Article 14(1)(a) of Regulation (EU) 2024/2847 requires an early "
                         "warning to ENISA and the relevant CSIRT within 24 hours of "
                         "becoming aware."),
            })

        doc["vulnerabilities"].append(entry)

    return doc


def _slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-") or "vendor"
