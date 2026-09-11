"""Scaffolding templates written by `cra init`.

These are the documents the assessment looks for. Generating them is not
cosmetic: SECURITY.md and the incident runbook are the artefacts that turn
three failing checks into passing ones, and they are what an auditor asks for.
"""
from __future__ import annotations

SECURITY_MD = """# Security Policy

## Reporting a vulnerability

Report security issues to **{contact}**. We acknowledge receipt within
{ack_hours} hours and aim to provide an initial assessment within 5 working days.

Please do not open a public issue for security reports. If you need encrypted
transport, request our PGP key at the address above.

We follow coordinated vulnerability disclosure: we ask for {embargo_days} days
before public disclosure, and we will credit reporters who wish to be named.

## Scope

This policy covers **{product}** and the components distributed with it.

## Supported versions and support period

| Version | Supported until |
|---------|-----------------|
| {version} | {support_until} |

The support period is declared in accordance with Article 13(8) of Regulation
(EU) 2024/2847. Security updates are provided for the duration stated above.

## Security updates

Security updates are distributed through {update_channel}. Update integrity is
verified by {update_integrity}. Where technically feasible, security updates are
applied automatically and separately from feature updates, in accordance with
Annex I, Part II(7)-(8).

## Vulnerability handling

We maintain a machine-readable SBOM (CycloneDX 1.6) for every release, monitor
our components continuously against public advisory databases, and record a
documented decision for every finding. Advisories are published in CSAF 2.0
format.

## Regulatory reporting

For vulnerabilities in this product that are **actively exploited**, we notify
ENISA and the CSIRT designated as coordinator through the single reporting
platform, in accordance with Article 14 of Regulation (EU) 2024/2847:

- **Early warning** within 24 hours of becoming aware
- **Full notification** within 72 hours of becoming aware
- **Final report** within 14 days of a corrective measure becoming available

The internal runbook for this process is at `docs/cra-incident-runbook.md`.
"""

RUNBOOK_MD = """# CRA Article 14 — Incident and vulnerability reporting runbook

**Product:** {product} {version}
**Manufacturer:** {supplier}
**Member State of main establishment:** {member_state}
**Reporting channel:** CRA single reporting platform (ENISA + designated CSIRT)

> Article 14 of Regulation (EU) 2024/2847 applies from **11 September 2026**.
> The clock starts when the manufacturer *becomes aware* — not when it is
> confirmed, not when a fix exists. Record that timestamp first.

## Roles

| Role | Name | Contact | Deputy |
|------|------|---------|--------|
| Incident owner | « to complete » | {contact} | « to complete » |
| Technical lead | « to complete » | | « to complete » |
| Regulatory contact | « to complete » | | « to complete » |
| Communications | « to complete » | | « to complete » |

## Trigger

Open this runbook when **either** condition holds:

1. A vulnerability in {product} is **actively exploited** (Article 14(1)(a)), or
2. A **severe incident** affects the security of the product (Article 14(1)(b)).

A vulnerability appearing in the CISA KEV catalogue, in a vendor advisory noting
in-the-wild exploitation, or reported as exploited by a researcher, all qualify
as grounds for awareness. `cra scan` flags the first category automatically.

## T+0 — Record awareness

- [ ] Log the exact UTC timestamp of awareness. This is the legal reference point.
- [ ] Record the source of the information.
- [ ] Open an incident record and assign the incident owner.

## T+24h — Early warning (Article 14(2))

- [ ] Generate the draft: `cra notify <CVE-ID> --stage early_warning`
- [ ] State whether exploitation is suspected to be by malicious actors.
- [ ] State the Member States concerned, to the extent known.
- [ ] Submit through the single reporting platform.
- [ ] Archive the submission receipt in the evidence folder.

An early warning is allowed to be incomplete. Late is the failure mode; partial
is not.

## T+72h — Full notification (Article 14(4))

- [ ] Generate: `cra notify <CVE-ID> --stage notification`
- [ ] General information on the product and the nature of the vulnerability.
- [ ] Severity and impact assessment (CVSS vector and justification).
- [ ] Corrective or mitigating measures available or in progress.
- [ ] Attach the SBOM and the CSAF advisory.
- [ ] Submit and archive the receipt.

## Post-fix — Final report (Article 14(6))

Within **14 days** of a corrective measure becoming available:

- [ ] Generate: `cra notify <CVE-ID> --stage final`
- [ ] Description of the vulnerability, its severity and impact.
- [ ] Information on any threat actor, where available.
- [ ] Details of the security update or corrective measure.
- [ ] Submit and archive.

## User notification (Article 14(8))

Without undue delay after a corrective measure is available, inform affected
users of the incident, the measure, and any action they must take. Publish the
CSAF advisory: `cra advisory --only-exploited -o advisories/`.

## Evidence to retain

Retain for the support period plus 10 years:

- Awareness timestamp and its source
- Each submission and its receipt
- SBOM of the affected release
- Triage ledger extract (`.cra-sentinel/triage.jsonl`)
- Published advisory
- Communications sent to users

## Rehearsal

Run this runbook as a tabletop exercise at least annually. An untested runbook
is not a process — record the date of the last rehearsal here: « ______ ».
"""

SECURITY_TXT = """Contact: mailto:{contact}
Expires: {expires}
Preferred-Languages: en
Policy: {policy_url}
# Published under Article 13(19) of Regulation (EU) 2024/2847
"""

CI_WORKFLOW = """name: CRA compliance

# Article 14 applies from 11 September 2026. Fail the build when a component
# with a known-exploited vulnerability reaches a release branch.

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'   # weekly: new advisories land after your last commit

jobs:
  cra-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install CRA Sentinel
        run: pip install cra-sentinel

      - name: Scan and produce evidence
        run: |
          cra scan . \\
            --report cra-report.html \\
            --sbom sbom.cdx.json \\
            --csaf advisory.json \\
            --json scan.json \\
            --fail-on exploited

      - name: Upload compliance evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cra-evidence
          path: |
            cra-report.html
            sbom.cdx.json
            advisory.json
            scan.json
          retention-days: 90
"""
