"""The sweep.

One pass over the portfolio. Everything here is written so that a single bad
product cannot stop the sweep: a repository that will not clone, a manifest
that will not parse, an SMTP server that will not answer. A monitoring service
that dies on the first exception monitors nothing.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from ..scanner.core import scan as run_scan
from .config import Config
from .notify import Alert
from .store import Product, Store, iso, parse, utcnow

GIT_TIMEOUT = 180


@dataclass
class SweepReport:
    products_scanned: int = 0
    products_failed: int = 0
    new_findings: int = 0
    newly_exploited: int = 0
    resolved: int = 0
    alerts_raised: int = 0
    alerts_sent: int = 0
    escalations: int = 0
    delivery_errors: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)

    @property
    def needs_attention(self) -> bool:
        return bool(self.newly_exploited or self.products_failed or self.delivery_errors)


def _git(args: list[str], cwd: Path | None = None) -> tuple[bool, str]:
    try:
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                                text=True, timeout=GIT_TIMEOUT, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return False, str(exc)
    return result.returncode == 0, (result.stderr or result.stdout).strip()


def refresh_source(product: Product, workdir: Path, log) -> tuple[Path | None, str]:
    """Return the directory to scan, cloning or pulling when the source is git."""
    if product.source_kind == "path":
        path = Path(product.source).expanduser()
        if not path.is_dir():
            return None, f"source directory not found: {path}"
        return path, ""

    checkout = workdir / product.slug
    if checkout.is_dir() and (checkout / ".git").exists():
        log(f"  {product.slug}: fetching")
        ok, message = _git(["fetch", "--quiet", "--depth", "1", "origin"], cwd=checkout)
        if not ok:
            return None, f"git fetch failed: {message}"
        branch = product.branch or "HEAD"
        ok, message = _git(["reset", "--hard", "--quiet", f"origin/{branch}"
                            if product.branch else "FETCH_HEAD"], cwd=checkout)
        if not ok:
            return None, f"git reset failed: {message}"
        return checkout, ""

    if checkout.exists():
        shutil.rmtree(checkout, ignore_errors=True)
    checkout.parent.mkdir(parents=True, exist_ok=True)
    log(f"  {product.slug}: cloning")
    args = ["clone", "--quiet", "--depth", "1"]
    if product.branch:
        args += ["--branch", product.branch]
    args += [product.source, str(checkout)]
    ok, message = _git(args)
    if not ok:
        return None, f"git clone failed: {message}"
    return checkout, ""


def _finding_rows(result) -> list[dict]:
    by_key = {c.key: c for c in result.components}
    rows = []
    for vuln in result.unique_vulns:
        component = by_key.get(vuln.component_key)
        rows.append({
            "vuln_id": vuln.id,
            "cve": vuln.cve,
            "severity": vuln.severity,
            "cvss": vuln.cvss_score,
            "component": (f"{component.full_name} {component.version}"
                          if component else vuln.component_key),
            "summary": vuln.summary or "",
            "fixed_in": vuln.fixed_versions[0] if vuln.fixed_versions else "",
            "kev": vuln.kev,
            "ransomware": vuln.kev_ransomware,
        })
    return rows


def _alert_from(product: Product, row: dict, alert_row, kind: str) -> Alert:
    return Alert(
        product_name=product.name, product_slug=product.slug, supplier=product.supplier,
        kind=kind, vuln_id=row.get("vuln_id", ""), cve=row.get("cve", ""),
        severity=row.get("severity", "UNKNOWN"), cvss=row.get("cvss"),
        component=row.get("component", ""), summary=row.get("summary", ""),
        fixed_in=row.get("fixed_in", ""), ransomware=bool(row.get("ransomware")),
        awareness_at=alert_row["awareness_at"],
        early_warning_due=alert_row["early_warning_due"],
        notification_due=alert_row["notification_due"])


def sweep_product(product: Product, store: Store, config: Config,
                  report: SweepReport, log) -> None:
    sweep_id = store.open_sweep(product.id)

    directory, error = refresh_source(product, config.workdir, log)
    if directory is None:
        store.close_sweep(sweep_id, "error", error=error)
        report.products_failed += 1
        report.lines.append(f"✕ {product.slug}: {error}")
        _dispatch(product, {"summary": error}, "scan_error", store, config, report, log)
        return

    try:
        log(f"  {product.slug}: scanning {directory}")
        result = run_scan(directory, log=lambda *_: None)
    except Exception as exc:                     # a scan must never kill the sweep
        store.close_sweep(sweep_id, "error", error=f"{type(exc).__name__}: {exc}")
        report.products_failed += 1
        report.lines.append(f"✕ {product.slug}: scan failed — {exc}")
        _dispatch(product, {"summary": f"{type(exc).__name__}: {exc}"},
                  "scan_error", store, config, report, log)
        return

    # An unverified scan is not a clean scan. Do not reconcile against it:
    # every existing finding would look resolved and the ledger would be wrong.
    if result.unverified:
        store.close_sweep(sweep_id, "unverified", scan_id=result.scan_id,
                          score=result.readiness_score,
                          components=len(result.components),
                          error="no advisory source reachable")
        report.products_failed += 1
        report.lines.append(f"! {product.slug}: unverified — no advisory source reachable")
        _dispatch(product, {"summary": "no advisory source reachable"},
                  "unverified", store, config, report, log)
        return

    rows = _finding_rows(result)
    changes = store.reconcile(product.id, rows)
    store.close_sweep(sweep_id, "ok", scan_id=result.scan_id,
                      score=result.readiness_score, components=len(result.components),
                      findings=len(rows), kev_count=len(result.kev_vulns))

    report.products_scanned += 1
    report.new_findings += len(changes["new"])
    report.newly_exploited += len(changes["newly_exploited"])
    report.resolved += len(changes["resolved"])

    summary = (f"{len(result.components)} components · {len(rows)} findings · "
               f"{len(result.kev_vulns)} exploited · score {result.readiness_score}")
    marker = "!" if changes["newly_exploited"] else "·"
    report.lines.append(f"{marker} {product.slug}: {summary}")

    for row in changes["newly_exploited"]:
        _dispatch(product, row, "exploited", store, config, report, log)

    if config.alert_on_new_critical:
        for row in changes["new"]:
            if not row["kev"] and row["severity"] == "CRITICAL":
                _dispatch(product, row, "new_critical", store, config, report, log)


def _dispatch(product: Product, row: dict, kind: str, store: Store, config: Config,
              report: SweepReport, log) -> None:
    """Record awareness first, deliver second. If delivery fails the timestamp
    still exists — which is the artefact that actually matters."""
    vuln_id = row.get("vuln_id") or f"{kind}:{utcnow().date()}"
    alert_row = store.raise_alert(product.id, vuln_id, kind)
    if alert_row is None:
        return                                   # already known, already alerted

    report.alerts_raised += 1
    alert = _alert_from(product, row, alert_row, kind)
    delivered, error = config.channels.send(alert)
    store.mark_sent(alert_row["id"], delivered, error)

    if delivered:
        report.alerts_sent += 1
        log(f"  alert sent via {', '.join(delivered)}: {alert.subject}")
    if error:
        report.delivery_errors.append(f"{product.slug}/{vuln_id}: {error}")
        log(f"  DELIVERY FAILED: {error}")


def escalate(store: Store, config: Config, report: SweepReport, log) -> None:
    """Re-notify on regulatory alerts nobody has acknowledged.

    The 24-hour obligation is on the manufacturer, so the operator has to hear
    about it well before the window closes — hence a default of 8 hours, not 24.
    """
    threshold = config.escalate_after_hours
    for row in store.breaching(hours=threshold):
        awareness = parse(row["awareness_at"])
        if awareness is None:
            continue
        hours_open = (utcnow() - awareness).total_seconds() / 3600
        remaining = 24 - hours_open

        alert = Alert(
            product_name=row["product_name"], product_slug=row["slug"], supplier="",
            kind="exploited", vuln_id=row["vuln_id"],
            cve=(row["label"] if "label" in row.keys() else row["vuln_id"]),
            severity="CRITICAL", cvss=None, component="—",
            summary=(f"RELANCE — alerte non acquittée depuis {hours_open:.0f} h. "
                     + (f"Il reste {remaining:.0f} h avant l'échéance d'alerte précoce."
                        if remaining > 0
                        else "L'ÉCHÉANCE DES 24 HEURES EST DÉPASSÉE.")),
            fixed_in="", ransomware=False,
            awareness_at=row["awareness_at"],
            early_warning_due=row["early_warning_due"],
            notification_due=row["notification_due"],
            escalation_hours=round(hours_open))
        delivered, error = config.channels.send(alert)
        report.escalations += 1
        if error:
            report.delivery_errors.append(f"escalation {row['slug']}: {error}")
        log(f"  escalation: {row['slug']} / {row['vuln_id']} open {hours_open:.0f}h")


def sweep(config: Config, log=lambda *_: None, only: str = "") -> SweepReport:
    store = Store(config.database)
    config.workdir.mkdir(parents=True, exist_ok=True)
    report = SweepReport()

    products = store.products(active_only=True)
    if only:
        products = [p for p in products if p.slug == only]
        if not products:
            report.lines.append(f"no active product with slug '{only}'")
            return report

    log(f"sweeping {len(products)} product(s)")
    for product in products:
        try:
            sweep_product(product, store, config, report, log)
        except Exception as exc:                 # last-resort guard per product
            report.products_failed += 1
            report.lines.append(f"✕ {product.slug}: unexpected — {exc}")
            log(f"  {product.slug}: unexpected error {exc}")

    try:
        escalate(store, config, report, log)
    except Exception as exc:
        log(f"  escalation pass failed: {exc}")

    return report
