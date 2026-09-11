# CRA Article 14 — Incident and vulnerability reporting runbook

**Product:** gateway-firmware-ui 1.0.0
**Manufacturer:** Acme Industrial GmbH
**Member State of main establishment:** Germany
**Reporting channel:** CRA single reporting platform (ENISA + designated CSIRT)

> Article 14 of Regulation (EU) 2024/2847 applies from **11 September 2026**.
> The clock starts when the manufacturer *becomes aware* — not when it is
> confirmed, not when a fix exists. Record that timestamp first.

## Roles

| Role | Name | Contact | Deputy |
|------|------|---------|--------|
| Incident owner | « to complete » | security@acme-industrial.eu | « to complete » |
| Technical lead | « to complete » | | « to complete » |
| Regulatory contact | « to complete » | | « to complete » |
| Communications | « to complete » | | « to complete » |

## Trigger

Open this runbook when **either** condition holds:

1. A vulnerability in gateway-firmware-ui is **actively exploited** (Article 14(1)(a)), or
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
