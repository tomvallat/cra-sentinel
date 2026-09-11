# CRA Sentinel

**Cyber Resilience Act compliance for products with digital elements.**
Zero dependencies. One command. Evidence an auditor will accept.

```
pip install cra-sentinel
cra scan . --report cra-report.html --sbom sbom.cdx.json
```

---

## Why this exists

Regulation (EU) 2024/2847 applies to every manufacturer placing a product with
digital elements on the EU market — including manufacturers established outside
the EU, and including products already on the market.

| Date | Obligation |
|------|------------|
| **11 September 2026** | Article 14: report actively exploited vulnerabilities within **24 hours** to ENISA and the national CSIRT, full notification within 72 hours, final report within 14 days of a corrective measure |
| 11 June 2027 | Conformity assessment provisions |
| **11 December 2027** | Full application: Annex I essential requirements, CE marking |

Most manufacturers cannot comply, for a mundane reason: they have no SBOM, no
vulnerability-monitoring process, and no record of the decisions they have made.
The regulation does not require you to be free of vulnerabilities. It requires
you to **know what is in your product, watch it, decide, and be able to show the
decision.**

That last part is what tools usually skip. A vulnerability scan is not evidence.
A documented triage decision is.

## What it does

**Builds the inventory.** Resolves components from npm, PyPI, Go, Cargo, Maven,
Composer, RubyGems, NuGet — lockfiles preferred over manifests, because the SBOM
must describe what ships, not what was requested.

**Separates "vulnerable" from "actively exploited".** Every finding is enriched
from OSV.dev, then intersected with the CISA Known Exploited Vulnerabilities
catalogue. Only that intersection starts an Article 14 clock, and the tool says
so explicitly rather than drowning you in 200 undifferentiated CVEs.

**Computes its own severity.** CVSS v3.1 base scores are calculated locally from
the vector, validated against the published reference values, because under
Annex I you must be able to justify your own severity assessment.

**Assesses 14 controls against the actual text.** Each one names its article —
Article 14(1)(a), Annex I Part II(2), Article 13(8) — and reports Pass, Partial,
Fail, or *Attest* for what no tool can verify. Manual checks are excluded from
the score rather than silently counted as failures.

**Keeps an append-only evidence ledger.** Every triage decision is recorded with
its rationale, author and timestamp. A `not_affected` verdict is refused without
a CSAF justification, because an auditor will ask for one.

**Exports the four formats that matter.** CycloneDX 1.6 (with VEX analysis
inline), SPDX 2.3, CSAF 2.0 advisories, and a pre-filled Article 14 notification
draft so the 24-hour window is spent deciding, not formatting.

## Commands

```bash
cra scan .                        # scan and assess
cra scan . --report r.html --sbom sbom.cdx.json --csaf advisory.json
cra scan . --fail-on exploited    # CI gate: non-zero if a KEV component ships
cra scan . --fail-on score --min-score 75

cra init --contact security@acme.eu --ci
                                  # scaffold SECURITY.md, the Article 14 runbook,
                                  # security.txt and a CI workflow

cra triage CVE-2021-44228 --status affected \
  -r "log4j-core is bundled in the firmware; JNDI reachable from the syslog parser" \
  --plan "Upgrade to 2.17.1 in 3.2.2" --target-date 2026-09-24

cra triage CVE-2021-45046 --status not_affected \
  --justification vulnerable_code_not_in_execute_path \
  -r "Lookups disabled at build time via log4j2.formatMsgNoLookups"

cra ledger --history             # the audit trail
cra notify CVE-2021-44228        # Article 14 early-warning draft
cra advisory --only-exploited    # CSAF 2.0 advisory to publish
cra watch --fail-on-new          # diff against baseline; alert on new exploitation
cra serve                        # local dashboard for non-terminal colleagues
cra deadlines                    # where you are in the timeline
```

## Exit codes

`0` clean · `1` threshold breached · `2` error. Use `--fail-on` to turn a scan
into a release gate.

## Design decisions worth knowing

**Zero dependencies.** Standard library only. It installs inside an air-gapped
build environment and it will still run in 2031, which matters when the support
period you declared is five years.

**`--offline` is real.** Advisory data is cached to `.cra-sentinel/cache/`. On a
network failure the scan degrades to the cache and says so in the report rather
than silently reporting zero findings.

**A malformed manifest never aborts a scan.** A compliance scan that crashes on
one bad `pom.xml` is worse than useless in CI.

**The HTML report is one self-contained file.** No CDN, no fonts, no tracking.
It survives being emailed to a notified body and printed to PDF. Dark and light
themes, readable at 400px.

**Nothing leaves your machine except package coordinates.** Component names and
versions are sent to OSV.dev to query advisories. No source code, no telemetry,
no account.

## Continuous monitoring

A scan you run by hand is not monitoring. `cra watchtower` sweeps a portfolio
of products on a schedule, records the **moment of awareness** when a component
becomes actively exploited — the fact from which every Article 14 deadline runs
— and alerts by email or webhook, escalating until someone acknowledges.

```bash
cra watchtower init
cra watchtower add "Acme — Gateway 3.2.1" --source https://github.com/acme/gw.git
cra watchtower run                       # put this on a timer
cra watchtower status                    # what is on the clock right now
cra watchtower ack acme-gateway-321 CVE-2021-44228 --by tom --note "not affected"
cra watchtower dashboard                 # portfolio view
```

The awareness timestamp is written **before** delivery is attempted: if SMTP is
down the alert does not arrive, but the evidence still exists. Deployment units
for systemd and cron are in `deploy/`.

## Troubleshooting

**`TLS certificate verification failed` on macOS.** Python installed from
python.org ships without a populated system trust store. CRA Sentinel falls back
to `certifi` automatically when it is importable; otherwise run the installer's
one-time fix:

```bash
/Applications/Python\ 3.x/Install\ Certificates.command
# or
pip install certifi
```

The scanner never reports a clean result it could not verify — a scan with no
reachable advisory source is marked **Unverified** in both the terminal and the
report, and the affected controls report *Attest* rather than *Pass*.

**Python version.** Requires 3.10 or later. Tested on 3.10 and 3.14.

## Scope and limitations

This covers third-party component risk — the part of Annex I that is mechanically
checkable. It does **not** assess first-party source code, hardware, cryptographic
implementation, or the organisational measures in Annex I Part I. Checks marked
*Attest* remain the manufacturer's responsibility, and the tool says so in the
report rather than implying coverage it does not have.

Automated output supports, and does not replace, the technical documentation
required under Annex VII. It is not legal advice.

## Development

```bash
python3 tests/test_suite.py      # 33 tests, offline, no network required
```

## Licence

MIT.
