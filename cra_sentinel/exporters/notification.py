"""Article 14 early-warning notification draft.

When a vulnerability in your product is actively exploited, the clock starts:
24h early warning, 72h full notification, 14 days after a corrective measure is
available for the final report. Reporting goes through the single reporting
platform to ENISA and the CSIRT designated as coordinator.

This module drafts that submission so the 24h window is spent deciding, not
formatting.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..model import utcnow


def _plus(hours: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def build(scan, vuln, supplier: str = "", contact: str = "",
          member_state: str = "", stage: str = "early_warning") -> dict:
    """stage: early_warning (24h) | notification (72h) | final (14d)"""
    awareness = utcnow()
    return {
        "$schema": "cra-sentinel/article14-notification/v1",
        "regulation": "Regulation (EU) 2024/2847 (Cyber Resilience Act)",
        "legal_basis": {
            "early_warning": "Article 14(2) — within 24 hours of becoming aware",
            "notification": "Article 14(4) — within 72 hours of becoming aware",
            "final_report": "Article 14(6) — within 14 days of a corrective measure "
                            "being available",
        }[stage],
        "submission_stage": stage,
        "submission_channel": "CRA Single Reporting Platform (ENISA + designated CSIRT)",
        "deadlines": {
            "became_aware_at": awareness,
            "early_warning_due": _plus(24),
            "full_notification_due": _plus(72),
            "final_report_due": "14 days after a corrective measure is available",
        },
        "manufacturer": {
            "name": supplier or "« to complete »",
            "contact_point": contact or "« monitored security contact »",
            "member_state_of_main_establishment": member_state or "« to complete »",
        },
        "product": {
            "name": scan.project_name,
            "version": scan.project_version,
            "category": "« product with digital elements — specify Annex III/IV class if applicable »",
            "placed_on_eu_market": True,
        },
        "vulnerability": {
            "identifier": vuln.cve,
            "aliases": vuln.aliases,
            "summary": vuln.summary,
            "severity": vuln.severity,
            "cvss_score": vuln.cvss_score,
            "cvss_vector": vuln.cvss_vector,
            "cwe": vuln.cwe_ids,
            "actively_exploited": vuln.kev,
            "known_ransomware_use": vuln.kev_ransomware,
            "affected_component": vuln.component_key,
            "available_fix": vuln.fixed_versions[0] if vuln.fixed_versions else None,
        },
        "assessment": {
            "nature_of_exploitation": "« describe how the vulnerability is being exploited »",
            "estimated_number_of_affected_users": "« to complete »",
            "geographical_spread": "« Member States affected »",
            "corrective_measures_taken": "« describe mitigation or patch status »",
            "corrective_measures_planned": vuln.fixed_versions[0] if vuln.fixed_versions
                                           else "« to complete »",
        },
        "attachments_expected": [
            "SBOM (CycloneDX 1.6 or SPDX 2.3)",
            "CSAF 2.0 advisory",
            "Triage ledger extract with rationale",
        ],
        "generated_by": {"tool": "CRA Sentinel", "version": scan.tool_version,
                         "scan_id": scan.scan_id, "generated_at": awareness},
        "disclaimer": ("Draft prepared automatically from dependency analysis. The "
                       "manufacturer remains solely responsible for the accuracy and "
                       "timeliness of the submission."),
    }
