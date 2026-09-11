"""CycloneDX 1.6 SBOM + VEX export.

CycloneDX 1.6 is one of the two formats the CRA guidance points to (the other
being SPDX 2.3). We emit the SBOM and the VEX analysis in the same document so
a single file answers both "what is in it" and "what did you decide about it".
"""
from __future__ import annotations

import uuid

SPEC_VERSION = "1.6"

_ANALYSIS_STATE = {
    "affected": "exploitable",
    "not_affected": "not_affected",
    "fixed": "resolved",
    "under_investigation": "in_triage",
    "false_positive": "false_positive",
}

_ANALYSIS_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}

_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
             "LOW": "low", "UNKNOWN": "unknown", "NONE": "none"}


def build(scan, supplier: str = "", include_vex: bool = True,
          triage: dict | None = None) -> dict:
    triage = triage or {}
    root_ref = f"pkg:generic/{scan.project_name}@{scan.project_version}"

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": scan.scanned_at,
            "tools": {"components": [{
                "type": "application",
                "name": "CRA Sentinel",
                "version": scan.tool_version,
                "description": "EU Cyber Resilience Act compliance scanner",
            }]},
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": scan.project_name,
                "version": scan.project_version,
            },
            "properties": [
                {"name": "cra:scanId", "value": scan.scan_id},
                {"name": "cra:readinessScore", "value": str(scan.readiness_score)},
                {"name": "cra:regulation", "value": "Regulation (EU) 2024/2847"},
            ],
        },
        "components": [],
    }

    if supplier:
        doc["metadata"]["supplier"] = {"name": supplier}
        doc["metadata"]["component"]["publisher"] = supplier

    for component in scan.components:
        entry = {
            "bom-ref": component.bom_ref,
            "type": "library",
            "name": component.full_name,
            "version": component.version,
            "purl": component.purl,
            "scope": "excluded" if component.scope == "dev" else "required",
        }
        if component.licenses:
            entry["licenses"] = [{"license": {"id" if _looks_like_spdx_id(lic) else "name": lic}}
                                 for lic in component.licenses if lic]
        entry["properties"] = [
            {"name": "cra:manifest", "value": component.source},
            {"name": "cra:dependencyDepth",
             "value": "direct" if component.direct else "transitive"},
        ]
        doc["components"].append(entry)

    doc["dependencies"] = [{
        "ref": root_ref,
        "dependsOn": [c.bom_ref for c in scan.components if c.direct],
    }]

    if include_vex:
        doc["vulnerabilities"] = _vulnerabilities(scan, triage)

    return doc


def _looks_like_spdx_id(value: str) -> bool:
    return bool(value) and " " not in value and value.upper() != "UNKNOWN"


def _vulnerabilities(scan, triage: dict) -> list[dict]:
    by_id: dict[str, dict] = {}
    for component in scan.components:
        for vuln in component.vulnerabilities:
            record = by_id.get(vuln.id)
            if record is None:
                record = {
                    "bom-ref": vuln.id,
                    "id": vuln.id,
                    "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"},
                    "description": vuln.summary or vuln.details[:300],
                    "affects": [],
                }
                if vuln.aliases:
                    record["references"] = [
                        {"id": alias, "source": {"name": "CVE" if alias.startswith("CVE-") else "OSV"}}
                        for alias in vuln.aliases[:5]
                    ]
                if vuln.cvss_vector:
                    record["ratings"] = [{
                        "source": {"name": "CRA Sentinel (computed)"},
                        "score": vuln.cvss_score,
                        "severity": _SEVERITY.get(vuln.severity, "unknown"),
                        "method": "CVSSv31" if vuln.cvss_vector.startswith("CVSS:3.1")
                                  else ("CVSSv4" if vuln.cvss_vector.startswith("CVSS:4")
                                        else "CVSSv3"),
                        "vector": vuln.cvss_vector,
                    }]
                if vuln.cwe_ids:
                    cwes = [int(c.replace("CWE-", "")) for c in vuln.cwe_ids
                            if c.replace("CWE-", "").isdigit()]
                    if cwes:
                        record["cwes"] = cwes
                if vuln.published:
                    record["published"] = vuln.published
                if vuln.kev:
                    record.setdefault("properties", []).append(
                        {"name": "cra:activelyExploited", "value": "true"})
                    record.setdefault("properties", []).append(
                        {"name": "cra:article14Reportable", "value": "true"})

                decision = triage.get(vuln.id)
                if decision:
                    analysis = {
                        "state": _ANALYSIS_STATE.get(decision.status, "in_triage"),
                        "detail": decision.rationale,
                    }
                    if decision.justification:
                        analysis["justification"] = _ANALYSIS_JUSTIFICATION.get(
                            decision.justification, "code_not_present")
                    if decision.remediation_plan:
                        analysis["response"] = ["update"]
                    record["analysis"] = analysis
                else:
                    record["analysis"] = {"state": "in_triage"}

                by_id[vuln.id] = record

            record["affects"].append({
                "ref": component.bom_ref,
                "versions": [{"version": component.version, "status": "affected"}],
            })
    return list(by_id.values())
