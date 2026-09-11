# Security Policy

## Reporting a vulnerability

Report security issues to **security@acme-industrial.eu**. We acknowledge receipt within
72 hours and aim to provide an initial assessment within 5 working days.

Please do not open a public issue for security reports. If you need encrypted
transport, request our PGP key at the address above.

We follow coordinated vulnerability disclosure: we ask for 90 days
before public disclosure, and we will credit reporters who wish to be named.

## Scope

This policy covers **gateway-firmware-ui** and the components distributed with it.

## Supported versions and support period

| Version | Supported until |
|---------|-----------------|
| 1.0.0 | 2031-09-09 |

The support period is declared in accordance with Article 13(8) of Regulation
(EU) 2024/2847. Security updates are provided for the duration stated above.

## Security updates

Security updates are distributed through « signed release artefacts / OTA channel ». Update integrity is
verified by « detached signature verified against the vendor public key ». Where technically feasible, security updates are
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
