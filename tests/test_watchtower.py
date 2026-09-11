"""Watchtower tests. Fully offline — no network, no SMTP, no git."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cra_sentinel.watchtower.config import Config
from cra_sentinel.watchtower.dashboard import render
from cra_sentinel.watchtower.notify import Alert, Channels
from cra_sentinel.watchtower.store import Store, iso, parse, utcnow


def finding(vuln_id: str, kev: bool = False, cve: str = "", severity: str = "CRITICAL"):
    return {"vuln_id": vuln_id, "cve": cve or vuln_id, "severity": severity,
            "cvss": 9.8, "component": "log4j-core 2.14.1", "summary": "RCE",
            "fixed_in": "2.15.0", "kev": kev, "ransomware": kev}


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.store = Store(self.dir / "wt.db")
        self.pid = self.store.add_product("acme", "Gateway 3.2.1", "/tmp/acme",
                                          supplier="Acme GmbH")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class TestReconcile(StoreCase):
    def test_first_sweep_reports_everything_as_new(self):
        changes = self.store.reconcile(self.pid, [finding("A"), finding("B")])
        self.assertEqual(len(changes["new"]), 2)
        self.assertEqual(changes["newly_exploited"], [])

    def test_transition_to_exploited_is_detected_once(self):
        self.store.reconcile(self.pid, [finding("A", kev=False)])
        changes = self.store.reconcile(self.pid, [finding("A", kev=True)])
        self.assertEqual(len(changes["newly_exploited"]), 1,
                         "becoming actively exploited is the legal trigger")
        again = self.store.reconcile(self.pid, [finding("A", kev=True)])
        self.assertEqual(again["newly_exploited"], [],
                         "an already-exploited finding must not re-trigger")

    def test_finding_that_arrives_already_exploited_triggers(self):
        changes = self.store.reconcile(self.pid, [finding("A", kev=True)])
        self.assertEqual(len(changes["newly_exploited"]), 1)

    def test_kev_since_is_recorded_and_never_moves(self):
        self.store.reconcile(self.pid, [finding("A", kev=True)])
        first = self.store.open_findings(self.pid)[0]["kev_since"]
        self.assertIsNotNone(first)
        self.store.reconcile(self.pid, [finding("A", kev=True)])
        self.assertEqual(self.store.open_findings(self.pid)[0]["kev_since"], first)

    def test_disappearing_finding_is_resolved_not_deleted(self):
        self.store.reconcile(self.pid, [finding("A"), finding("B")])
        changes = self.store.reconcile(self.pid, [finding("A")])
        self.assertEqual(len(changes["resolved"]), 1)
        self.assertEqual(len(self.store.open_findings(self.pid)), 1)
        with self.store.connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
        self.assertEqual(total, 2, "history must survive; nothing is deleted")

    def test_reappearing_finding_is_reopened(self):
        self.store.reconcile(self.pid, [finding("A")])
        self.store.reconcile(self.pid, [])
        self.store.reconcile(self.pid, [finding("A")])
        self.assertEqual(len(self.store.open_findings(self.pid)), 1)


class TestAlerts(StoreCase):
    def test_deadlines_are_24h_and_72h_from_awareness(self):
        alert = self.store.raise_alert(self.pid, "CVE-1", "exploited")
        awareness = parse(alert["awareness_at"])
        self.assertEqual(parse(alert["early_warning_due"]) - awareness,
                         timedelta(hours=24))
        self.assertEqual(parse(alert["notification_due"]) - awareness,
                         timedelta(hours=72))

    def test_duplicate_alert_is_refused(self):
        self.assertIsNotNone(self.store.raise_alert(self.pid, "CVE-1", "exploited"))
        self.assertIsNone(self.store.raise_alert(self.pid, "CVE-1", "exploited"))

    def test_different_kinds_alert_separately(self):
        self.assertIsNotNone(self.store.raise_alert(self.pid, "CVE-1", "exploited"))
        self.assertIsNotNone(self.store.raise_alert(self.pid, "CVE-1", "new_critical"))

    def test_acknowledge_closes_and_is_idempotent(self):
        alert = self.store.raise_alert(self.pid, "CVE-1", "exploited")
        self.assertTrue(self.store.acknowledge(alert["id"], "tom", "not affected"))
        self.assertFalse(self.store.acknowledge(alert["id"], "tom"),
                         "acknowledging twice must not overwrite the first record")
        self.assertEqual(self.store.open_alerts(), [])

    def test_breaching_finds_only_stale_unacknowledged_alerts(self):
        self.store.reconcile(self.pid, [finding("GHSA-x", kev=True, cve="CVE-2021-44228")])
        self.store.raise_alert(self.pid, "GHSA-x", "exploited",
                               awareness=utcnow() - timedelta(hours=10))
        self.assertEqual(len(self.store.breaching(hours=8)), 1)
        self.assertEqual(len(self.store.breaching(hours=12)), 0)

    def test_breaching_ignores_acknowledged(self):
        alert = self.store.raise_alert(self.pid, "CVE-1", "exploited",
                                       awareness=utcnow() - timedelta(hours=30))
        self.store.acknowledge(alert["id"], "tom")
        self.assertEqual(self.store.breaching(hours=8), [])

    def test_awareness_timestamp_survives_delivery_failure(self):
        alert = self.store.raise_alert(self.pid, "CVE-1", "exploited")
        self.store.mark_sent(alert["id"], [], "smtp: connection refused")
        row = self.store.alerts_for(self.pid)[0]
        self.assertIsNotNone(row["awareness_at"])
        self.assertIn("connection refused", row["delivery_error"])
        self.assertIsNone(row["acknowledged_at"],
                          "an undelivered alert stays open")


class TestIdentifiers(StoreCase):
    """The alert email tells the operator to type the CVE. That has to work."""

    def setUp(self):
        super().setUp()
        self.store.reconcile(self.pid, [finding("GHSA-jfh8-c2jp-5v3q", kev=True,
                                                cve="CVE-2021-44228")])

    def test_resolves_by_cve(self):
        self.assertEqual(self.store.resolve_vuln_id(self.pid, "CVE-2021-44228"),
                         "GHSA-jfh8-c2jp-5v3q")

    def test_resolves_by_osv_id(self):
        self.assertEqual(self.store.resolve_vuln_id(self.pid, "GHSA-jfh8-c2jp-5v3q"),
                         "GHSA-jfh8-c2jp-5v3q")

    def test_case_insensitive(self):
        self.assertEqual(self.store.resolve_vuln_id(self.pid, "cve-2021-44228"),
                         "GHSA-jfh8-c2jp-5v3q")

    def test_unknown_returns_none(self):
        self.assertIsNone(self.store.resolve_vuln_id(self.pid, "CVE-1999-0001"))

    def test_open_alerts_expose_the_cve_as_label(self):
        self.store.raise_alert(self.pid, "GHSA-jfh8-c2jp-5v3q", "exploited")
        self.assertEqual(self.store.open_alerts()[0]["label"], "CVE-2021-44228")


class TestNotify(unittest.TestCase):
    def _alert(self, **overrides):
        base = dict(product_name="Gateway 3.2.1", product_slug="acme",
                    supplier="Acme GmbH", kind="exploited", vuln_id="GHSA-x",
                    cve="CVE-2021-44228", severity="CRITICAL", cvss=10.0,
                    component="log4j-core 2.14.1", summary="RCE", fixed_in="2.15.0",
                    ransomware=True, awareness_at="2026-09-10T17:00:00Z",
                    early_warning_due="2026-09-11T17:00:00Z",
                    notification_due="2026-09-13T17:00:00Z")
        base.update(overrides)
        return Alert(**base)

    def test_regulatory_body_carries_the_clock_and_the_commands(self):
        body = self._alert().as_text()
        for expected in ("2026-09-11T17:00:00Z", "ARTICLE 14", "2024/2847",
                         "cra triage", "cra notify",
                         "cra watchtower ack acme CVE-2021-44228"):
            self.assertIn(expected, body)

    def test_ack_command_uses_the_cve_not_the_osv_id(self):
        self.assertIn("ack acme CVE-2021-44228", self._alert().as_text())
        self.assertNotIn("ack acme GHSA-x", self._alert().as_text())

    def test_non_regulatory_alert_says_no_clock_is_running(self):
        body = self._alert(kind="new_critical").as_text()
        self.assertIn("aucun délai Article 14 ne court", body)

    def test_unverified_alert_refuses_to_imply_clean(self):
        body = self._alert(kind="unverified").as_text()
        self.assertIn("pas contrôlé", body)

    def test_escalation_subject_shows_remaining_time(self):
        self.assertIn("reste 15 h", self._alert(escalation_hours=9).subject)
        self.assertIn("DÉPASSÉE", self._alert(escalation_hours=30).subject)

    def test_unconfigured_channels_report_the_failure(self):
        delivered, error = Channels().send(self._alert())
        self.assertEqual(delivered, [])
        self.assertIn("no delivery channel", error)

    def test_webhook_payload_is_json_serialisable(self):
        json.dumps(self._alert().as_webhook())


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_scaffold_then_load(self):
        path = Config.scaffold(self.dir / "config.json")
        config = Config.load(path)
        self.assertEqual(config.escalate_after_hours, 8)
        self.assertTrue(config.warnings(), "template placeholders must be flagged")

    def test_password_never_comes_from_the_file(self):
        path = self.dir / "config.json"
        path.write_text(json.dumps({
            "notify": {"smtp_host": "smtp.test", "mail_to": ["a@b.c"],
                       "smtp_password": "hunter2"}}))
        self.assertEqual(Config.load(path).channels.smtp_password, "",
                         "a password in the config file must be ignored, not used")

    def test_missing_config_is_actionable(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            Config.load(self.dir / "nope.json")
        self.assertIn("watchtower init", str(ctx.exception))


class TestDashboard(StoreCase):
    def test_renders_with_an_open_clock(self):
        self.store.reconcile(self.pid, [finding("GHSA-x", kev=True, cve="CVE-2021-44228")])
        self.store.raise_alert(self.pid, "GHSA-x", "exploited")
        page = render(self.store, operator="Tom")
        self.assertIn("CVE-2021-44228", page)
        self.assertIn("Gateway 3.2.1", page)
        self.assertIn("prefers-color-scheme", page)

    def test_renders_empty_portfolio(self):
        empty = Store(self.dir / "empty.db")
        page = render(empty)
        self.assertIn("Aucun produit surveillé", page)

    def test_escapes_hostile_product_names(self):
        self.store.add_product("x", "<script>alert(1)</script>", "/tmp/x")
        page = render(self.store)
        self.assertNotIn("<script>alert(1)", page)


if __name__ == "__main__":
    unittest.main(verbosity=1)
