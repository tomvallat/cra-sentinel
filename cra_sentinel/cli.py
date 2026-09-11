"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

from . import __version__, term
from .assess import article14
from .evidence.ledger import JUSTIFICATIONS, STATES, Ledger
from .exporters import csaf as csaf_export
from .exporters import cyclonedx, notification, spdx
from .report import html as html_report
from .scanner.core import scan as run_scan

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


def _plural_days(days: int) -> str:
    return f"in {days} day" if days == 1 else f"in {days} days"


def _logger(quiet: bool):
    def log(message: str) -> None:
        if not quiet:
            print(term.grey(f"  · {message}"), file=sys.stderr)
    return log


def _write(path: Path, payload, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    size = path.stat().st_size
    unit = f"{size/1024:.0f} KB" if size >= 1024 else f"{size} B"
    print(term.kv(label, f"{term.cyan(str(path))} {term.grey(f'({unit})')}"))


# --------------------------------------------------------------------------
# cra scan
# --------------------------------------------------------------------------

def cmd_scan(args) -> int:
    root = Path(args.path).resolve()
    log = _logger(args.quiet)

    print(term.header(f"Scanning {root.name}", str(root)))
    try:
        result = run_scan(root, offline=args.offline, include_dev=args.include_dev,
                          name=args.name, version=args.product_version, log=log)
    except (NotADirectoryError, OSError) as exc:
        print(term.red(f"  error: {exc}"), file=sys.stderr)
        return EXIT_ERROR

    triage = Ledger(root).current()
    counts = result.severity_counts()
    kev = result.kev_vulns
    grade, grade_label = article14.grade(result.readiness_score)

    print()
    print(term.rule())
    print()
    color = term.green if result.readiness_score >= 75 else \
        term.yellow if result.readiness_score >= 55 else term.red
    print(f"  {term.gauge(result.readiness_score)}  "
          f"{term.bold(color(str(result.readiness_score) + '/100'))}  "
          f"{term.bold('Grade ' + grade)} {term.grey('· ' + grade_label)}")
    print()
    print(term.kv("Product", f"{term.bold(result.project_name)} {result.project_version}"))
    origin = f"from {len(result.manifests)} manifest(s)"
    print(term.kv("Components", f"{len(result.components)} {term.grey(origin)}"))
    breakdown = f"({counts['CRITICAL']} critical, {counts['HIGH']} high)"
    print(term.kv("Findings", f"{len(result.unique_vulns)} unique {term.grey(breakdown)}"))
    print(term.kv("Triage recorded", f"{len(triage)}/{len(result.unique_vulns)}"))
    print(term.kv("Scan id", term.grey(result.scan_id)))

    if result.unverified:
        print()
        print("  " + term.on_red(" UNVERIFIED ") + "  " +
              term.bold(term.yellow("no advisory source could be consulted")))
        print()
        print(term.grey("    0 findings here means NOT CHECKED, not clean. Re-run with "
                        "network\n    access before treating this report as evidence."))

    if kev:
        print()
        print("  " + term.on_red(" ARTICLE 14 EXPOSURE ") + "  " +
              term.bold(term.red(f"{len(kev)} actively exploited vulnerabilit"
                                 f"{'y' if len(kev) == 1 else 'ies'}")))
        print()
        for vuln in kev[:10]:
            flag = term.red(" ransomware") if vuln.kev_ransomware else ""
            fix = (term.green(f"fix: {vuln.fixed_versions[0]}")
                   if vuln.fixed_versions else term.grey("no fix published"))
            print(f"    {term.bold(vuln.cve):<26} "
                  f"{term.red(vuln.severity):<9} "
                  f"{(str(vuln.cvss_score) if vuln.cvss_score else '—'):>4}  "
                  f"{term.grey(term.truncate(vuln.component_key.split('|')[1], 28)):<30}{fix}{flag}")
        if len(kev) > 10:
            print(term.grey(f"    … and {len(kev)-10} more"))
        print()
        print(term.grey("    24h early warning · 72h notification · 14d final report"))
        print(term.grey("    Draft one with: ") + term.cyan(f"cra notify {kev[0].cve}"))
    else:
        print()
        print("  " + term.on_green(" NO ACTIVE EXPLOITATION ") +
              term.grey("  no component matches the CISA KEV catalogue"))

    failing = [c for c in result.checks if c.status == "fail"]
    if failing:
        print()
        print(f"  {term.bold('Failing controls')}")
        print()
        for check in failing:
            print(f"    {term.red('✕')} {term.bold(check.title)}")
            print(f"      {term.grey(check.id + ' · ' + check.cra_ref)}")
            print(f"      {term.truncate(check.evidence, term.width() - 8)}")
        print()
        print(term.grey("  Full detail in the HTML report; scaffold the missing documents "
                        "with ") + term.cyan("cra init"))

    outputs = [args.report, args.sbom, args.spdx, args.csaf, args.json_out]
    if any(outputs):
        print()
        print(term.rule())
        print()
    if args.report:
        _write(Path(args.report),
               html_report.render(result, supplier=args.supplier, triage=triage),
               "HTML report")
    if args.sbom:
        _write(Path(args.sbom),
               cyclonedx.build(result, supplier=args.supplier, triage=triage),
               "CycloneDX 1.6 SBOM")
    if args.spdx:
        _write(Path(args.spdx), spdx.build(result, supplier=args.supplier), "SPDX 2.3 SBOM")
    if args.csaf:
        _write(Path(args.csaf),
               csaf_export.build(result, supplier=args.supplier, triage=triage),
               "CSAF 2.0 advisory")
    if args.json_out:
        _write(Path(args.json_out), result.to_dict(), "Raw scan data")

    print()

    threshold = args.fail_on
    breached = (
        (threshold == "exploited" and kev) or
        (threshold == "critical" and counts["CRITICAL"]) or
        (threshold == "high" and (counts["CRITICAL"] or counts["HIGH"])) or
        (threshold == "any" and result.unique_vulns) or
        (threshold == "score" and result.readiness_score < args.min_score)
    )
    if breached:
        reason = {"exploited": "actively exploited vulnerabilities present",
                  "critical": "critical vulnerabilities present",
                  "high": "high or critical vulnerabilities present",
                  "any": "vulnerabilities present",
                  "score": f"readiness score below {args.min_score}"}[threshold]
        print(term.red(f"  ✕ threshold breached: {reason}"))
        print()
        return EXIT_THRESHOLD
    return EXIT_OK


# --------------------------------------------------------------------------
# cra init
# --------------------------------------------------------------------------

def cmd_init(args) -> int:
    from . import templates

    root = Path(args.path).resolve()
    print(term.header("Scaffolding CRA documentation", str(root)))

    support_until = (date.today() + timedelta(days=365 * args.support_years)).isoformat()
    fields = {
        "product": args.name or root.name,
        "version": args.product_version or "1.0.0",
        "supplier": args.supplier or "« manufacturer legal name »",
        "contact": args.contact,
        "member_state": args.member_state or "« Member State »",
        "ack_hours": "72",
        "embargo_days": "90",
        "support_until": support_until,
        "update_channel": "« signed release artefacts / OTA channel »",
        "update_integrity": "« detached signature verified against the vendor public key »",
    }

    targets = [
        (root / "SECURITY.md", templates.SECURITY_MD.format(**fields)),
        (root / "docs" / "cra-incident-runbook.md", templates.RUNBOOK_MD.format(**fields)),
        (root / ".well-known" / "security.txt", templates.SECURITY_TXT.format(
            contact=args.contact,
            expires=(date.today() + timedelta(days=365)).isoformat() + "T00:00:00.000Z",
            policy_url=args.policy_url or "https://example.com/security")),
    ]
    if args.ci:
        targets.append((root / ".github" / "workflows" / "cra-compliance.yml",
                        templates.CI_WORKFLOW))

    written, skipped = 0, 0
    for path, content in targets:
        if path.exists() and not args.force:
            print(term.kv("skipped", f"{term.grey(str(path.relative_to(root)))} "
                          f"{term.grey('(exists — use --force)')}"))
            skipped += 1
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(term.kv("created", term.cyan(str(path.relative_to(root)))))
        written += 1

    print()
    print(term.grey(f"  {written} written, {skipped} skipped."))
    print(term.grey("  Every « placeholder » must be completed before this counts as "
                    "evidence."))
    print()
    return EXIT_OK


# --------------------------------------------------------------------------
# cra triage / ledger
# --------------------------------------------------------------------------

def cmd_triage(args) -> int:
    root = Path(args.path).resolve()
    ledger = Ledger(root)
    try:
        entry = ledger.record(
            vuln_id=args.vuln_id, status=args.status, rationale=args.rationale,
            justification=args.justification or "", component=args.component or "",
            remediation_plan=args.plan or "", target_date=args.target_date or "",
            author=args.author or "")
    except ValueError as exc:
        print(term.red(f"  error: {exc}"), file=sys.stderr)
        return EXIT_ERROR

    print(term.header("Triage decision recorded"))
    print(term.kv("Vulnerability", term.bold(entry.vuln_id)))
    print(term.kv("Status", term.cyan(entry.status)))
    if entry.justification:
        print(term.kv("Justification", entry.justification))
    print(term.kv("Rationale", term.truncate(entry.rationale, 60)))
    print(term.kv("Author", entry.author))
    print(term.kv("Recorded", entry.recorded_at))
    print(term.kv("Entry hash", term.grey(entry.entry_hash)))
    print()
    print(term.grey(f"  Ledger: {ledger.path}"))
    print()
    return EXIT_OK


def cmd_ledger(args) -> int:
    root = Path(args.path).resolve()
    ledger = Ledger(root)
    entries = ledger.all_entries() if args.history else list(ledger.current().values())
    if not entries:
        print(term.header("Triage ledger", "no decisions recorded yet"))
        print(term.grey("  Record one:  ") +
              term.cyan("cra triage CVE-2021-44228 --status affected -r \"...\""))
        print()
        return EXIT_OK

    print(term.header("Triage ledger",
                      f"{len(entries)} {'entries (full history)' if args.history else 'current decisions'}"))
    for entry in sorted(entries, key=lambda x: x.recorded_at, reverse=True):
        colour = term.red if entry.status == "affected" else \
            term.green if entry.status in ("fixed", "not_affected") else term.yellow
        print(f"  {term.bold(entry.vuln_id):<28} {colour(entry.status):<22} "
              f"{term.grey(entry.recorded_at[:10])}  {term.grey(entry.author)}")
        print(f"    {term.truncate(entry.rationale, term.width() - 6)}")
        if entry.justification:
            print(f"    {term.grey('justification: ' + entry.justification)}")
        if entry.remediation_plan:
            print(f"    {term.grey('plan: ' + entry.remediation_plan)}"
                  + (term.grey(f" (target {entry.target_date})") if entry.target_date else ""))
        print()
    return EXIT_OK


# --------------------------------------------------------------------------
# cra notify
# --------------------------------------------------------------------------

def cmd_notify(args) -> int:
    root = Path(args.path).resolve()
    log = _logger(True)
    result = run_scan(root, offline=args.offline, log=log)

    target = args.vuln_id.upper()
    match = next((v for v in result.unique_vulns
                  if v.id.upper() == target or target in [a.upper() for a in v.aliases]), None)
    if match is None:
        print(term.red(f"  {args.vuln_id} was not found in the current scan."), file=sys.stderr)
        if result.kev_vulns:
            print(term.grey("  Actively exploited findings available: ") +
                  ", ".join(v.cve for v in result.kev_vulns[:6]), file=sys.stderr)
        return EXIT_ERROR

    draft = notification.build(result, match, supplier=args.supplier,
                               contact=args.contact, member_state=args.member_state,
                               stage=args.stage)

    print(term.header(f"Article 14 {args.stage.replace('_', ' ')} draft",
                      f"{match.cve} · {result.project_name} {result.project_version}"))
    if not match.kev:
        print(term.yellow("  Note: this vulnerability is not in the CISA KEV catalogue. "
                          "Article 14(1)(a) is triggered by active exploitation — confirm "
                          "before submitting."))
        print()
    print(term.kv("Deadline (early warning)", term.red(draft["deadlines"]["early_warning_due"])))
    print(term.kv("Deadline (notification)", term.yellow(draft["deadlines"]["full_notification_due"])))
    print(term.kv("Channel", draft["submission_channel"]))
    print()

    out = Path(args.output) if args.output else \
        root / f"article14-{args.stage}-{match.cve}.json"
    _write(out, draft, "Notification draft")
    print()
    print(term.grey("  Complete every « placeholder » before submission. The manufacturer "
                    "is responsible for accuracy."))
    print()
    return EXIT_OK


# --------------------------------------------------------------------------
# cra advisory
# --------------------------------------------------------------------------

def cmd_advisory(args) -> int:
    root = Path(args.path).resolve()
    result = run_scan(root, offline=args.offline, log=_logger(True))
    triage = Ledger(root).current()
    doc = csaf_export.build(result, supplier=args.supplier, triage=triage,
                            only_kev=args.only_exploited,
                            profile="csaf_security_advisory" if args.publish else "csaf_vex")
    count = len(doc["vulnerabilities"])
    print(term.header("CSAF 2.0 advisory",
                      f"{count} vulnerabilit{'y' if count == 1 else 'ies'} · profile "
                      f"{doc['document']['category']}"))
    _write(Path(args.output), doc, "Advisory")
    print()
    return EXIT_OK


# --------------------------------------------------------------------------
# cra deadlines
# --------------------------------------------------------------------------

def cmd_deadlines(_args) -> int:
    print(term.header("Cyber Resilience Act — regulatory timeline",
                      "Regulation (EU) 2024/2847"))
    for entry in article14.deadline_status():
        days = entry["days"]
        if days <= 0:
            badge, colour = "IN FORCE", term.red
        elif days < 90:
            badge, colour = _plural_days(days), term.red
        elif days < 400:
            badge, colour = _plural_days(days), term.yellow
        else:
            badge, colour = _plural_days(days), term.grey
        print(f"  {term.bold(entry['date'])}   {colour(badge.ljust(14))} {entry['label']}")
    print()
    print(term.grey("  Reporting flows through the single reporting platform to ENISA and "
                    "the\n  CSIRT designated as coordinator in the Member State of main "
                    "establishment."))
    print()
    return EXIT_OK


# --------------------------------------------------------------------------
# cra watch
# --------------------------------------------------------------------------

def cmd_watch(args) -> int:
    root = Path(args.path).resolve()
    state_path = root / ".cra-sentinel" / "last-scan.json"
    previous = {}
    if state_path.exists():
        try:
            previous = json.loads(state_path.read_text())
        except ValueError:
            previous = {}

    result = run_scan(root, offline=args.offline, log=_logger(args.quiet))
    current_ids = {v.id for v in result.unique_vulns}
    current_kev = {v.id for v in result.kev_vulns}
    previous_ids = set(previous.get("vuln_ids", []))
    previous_kev = set(previous.get("kev_ids", []))

    new_vulns = current_ids - previous_ids
    new_kev = current_kev - previous_kev
    resolved = previous_ids - current_ids

    print(term.header("Watch", f"{result.project_name} {result.project_version}"))
    if not previous:
        print(term.grey("  No previous baseline — establishing one now."))
    print(term.kv("New findings", term.yellow(str(len(new_vulns))) if new_vulns else "0"))
    print(term.kv("Newly exploited", term.red(str(len(new_kev))) if new_kev else "0"))
    print(term.kv("Resolved since baseline", term.green(str(len(resolved)))
                  if resolved else "0"))

    if new_kev:
        print()
        print("  " + term.on_red(" NEW ARTICLE 14 TRIGGER "))
        print()
        for vuln in result.kev_vulns:
            if vuln.id in new_kev:
                print(f"    {term.bold(term.red(vuln.cve))}  {vuln.summary[:60]}")
        print()
        print(term.grey("  The 24-hour early-warning clock starts when you become aware. "
                        "That is now."))

    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({
        "scanned_at": result.scanned_at,
        "scan_id": result.scan_id,
        "vuln_ids": sorted(current_ids),
        "kev_ids": sorted(current_kev),
        "readiness_score": result.readiness_score,
    }, indent=2))
    print()
    return EXIT_THRESHOLD if (new_kev and args.fail_on_new) else EXIT_OK


# --------------------------------------------------------------------------
# cra serve
# --------------------------------------------------------------------------

def cmd_serve(args) -> int:
    from .server.app import serve
    return serve(Path(args.path).resolve(), host=args.host, port=args.port,
                 supplier=args.supplier, offline=args.offline)


# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cra",
        description="CRA Sentinel — Cyber Resilience Act compliance scanner "
                    "for products with digital elements.",
        epilog="Regulation (EU) 2024/2847. Article 14 reporting applies from "
               "11 September 2026.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version",
                        version=f"CRA Sentinel {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(sub):
        sub.add_argument("path", nargs="?", default=".", help="project directory")
        sub.add_argument("--offline", action="store_true",
                         help="use cached advisory data only; never hit the network")
        sub.add_argument("--supplier", default="", help="manufacturer legal name")

    # scan
    scan_parser = subparsers.add_parser("scan", help="scan a project and produce evidence")
    common(scan_parser)
    scan_parser.add_argument("--report", metavar="FILE", help="write the HTML report")
    scan_parser.add_argument("--sbom", metavar="FILE", help="write a CycloneDX 1.6 SBOM")
    scan_parser.add_argument("--spdx", metavar="FILE", help="write an SPDX 2.3 SBOM")
    scan_parser.add_argument("--csaf", metavar="FILE", help="write a CSAF 2.0 advisory")
    scan_parser.add_argument("--json", dest="json_out", metavar="FILE",
                             help="write the raw scan result")
    scan_parser.add_argument("--fail-on", default="none",
                             choices=["none", "exploited", "critical", "high", "any", "score"],
                             help="exit non-zero when the threshold is breached (CI gate)")
    scan_parser.add_argument("--min-score", type=int, default=75,
                             help="minimum readiness score with --fail-on score")
    scan_parser.add_argument("--include-dev", action="store_true",
                             help="include development-only dependencies")
    scan_parser.add_argument("--name", default="", help="override the product name")
    scan_parser.add_argument("--product-version", default="",
                             help="override the product version")
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress")
    scan_parser.set_defaults(func=cmd_scan)

    # init
    init_parser = subparsers.add_parser(
        "init", help="scaffold SECURITY.md, the Article 14 runbook and security.txt")
    init_parser.add_argument("path", nargs="?", default=".")
    init_parser.add_argument("--contact", default="security@example.com",
                             help="monitored security contact address")
    init_parser.add_argument("--supplier", default="", help="manufacturer legal name")
    init_parser.add_argument("--name", default="", help="product name")
    init_parser.add_argument("--product-version", default="", help="product version")
    init_parser.add_argument("--member-state", default="",
                             help="Member State of main establishment")
    init_parser.add_argument("--support-years", type=int, default=5,
                             help="declared support period (CRA default expectation: 5)")
    init_parser.add_argument("--policy-url", default="", help="URL of the published policy")
    init_parser.add_argument("--ci", action="store_true",
                             help="also write a GitHub Actions compliance workflow")
    init_parser.add_argument("--force", action="store_true", help="overwrite existing files")
    init_parser.set_defaults(func=cmd_init)

    # triage
    triage_parser = subparsers.add_parser(
        "triage", help="record a triage decision in the evidence ledger")
    triage_parser.add_argument("vuln_id", help="CVE or OSV identifier")
    triage_parser.add_argument("--path", default=".")
    triage_parser.add_argument("--status", required=True, choices=sorted(STATES),
                               help="; ".join(f"{k}: {v}" for k, v in STATES.items()))
    triage_parser.add_argument("-r", "--rationale", required=True,
                               help="written reasoning — this is the evidence")
    triage_parser.add_argument("--justification", choices=sorted(JUSTIFICATIONS),
                               help="required for not_affected (CSAF 2.0 flag label)")
    triage_parser.add_argument("--component", default="", help="affected component")
    triage_parser.add_argument("--plan", default="", help="remediation plan")
    triage_parser.add_argument("--target-date", default="", help="remediation target date")
    triage_parser.add_argument("--author", default="", help="decision author")
    triage_parser.set_defaults(func=cmd_triage)

    # ledger
    ledger_parser = subparsers.add_parser("ledger", help="show the triage ledger")
    ledger_parser.add_argument("path", nargs="?", default=".")
    ledger_parser.add_argument("--history", action="store_true",
                               help="show every entry, not just current decisions")
    ledger_parser.set_defaults(func=cmd_ledger)

    # notify
    notify_parser = subparsers.add_parser(
        "notify", help="draft an Article 14 notification to ENISA and the CSIRT")
    notify_parser.add_argument("vuln_id", help="CVE or OSV identifier")
    notify_parser.add_argument("--path", default=".")
    notify_parser.add_argument("--stage", default="early_warning",
                               choices=["early_warning", "notification", "final"],
                               help="24h / 72h / 14d after corrective measure")
    notify_parser.add_argument("--supplier", default="")
    notify_parser.add_argument("--contact", default="")
    notify_parser.add_argument("--member-state", default="")
    notify_parser.add_argument("--offline", action="store_true")
    notify_parser.add_argument("-o", "--output", default="", help="output file")
    notify_parser.set_defaults(func=cmd_notify)

    # advisory
    advisory_parser = subparsers.add_parser("advisory", help="generate a CSAF 2.0 advisory")
    common(advisory_parser)
    advisory_parser.add_argument("-o", "--output", default="advisory.json")
    advisory_parser.add_argument("--only-exploited", action="store_true",
                                 help="restrict to actively exploited vulnerabilities")
    advisory_parser.add_argument("--publish", action="store_true",
                                 help="use the csaf_security_advisory profile")
    advisory_parser.set_defaults(func=cmd_advisory)

    # deadlines
    deadlines_parser = subparsers.add_parser("deadlines", help="show the CRA timeline")
    deadlines_parser.set_defaults(func=cmd_deadlines)

    # watch
    watch_parser = subparsers.add_parser(
        "watch", help="re-scan and report what changed since the last baseline")
    common(watch_parser)
    watch_parser.add_argument("--fail-on-new", action="store_true",
                              help="exit non-zero when a new exploited vulnerability appears")
    watch_parser.add_argument("-q", "--quiet", action="store_true")
    watch_parser.set_defaults(func=cmd_watch)

    # watchtower
    from .watchtower.commands import register as register_watchtower
    register_watchtower(subparsers)

    # serve
    serve_parser = subparsers.add_parser("serve", help="local compliance dashboard")
    common(serve_parser)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    serve_parser.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n" + term.grey("  interrupted"), file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # last-resort guard: a scanner must not crash a CI job
        print(term.red(f"  unexpected error: {exc}"), file=sys.stderr)
        if "--debug" in (argv or sys.argv):
            raise
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
