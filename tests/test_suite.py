"""Test suite. Runs offline except where marked — CI must not depend on OSV."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cra_sentinel.assess import article14
from cra_sentinel.evidence.ledger import Ledger
from cra_sentinel.exporters import csaf, cyclonedx, notification, spdx
from cra_sentinel.model import Component, ScanResult, Vulnerability
from cra_sentinel.report import html as html_report
from cra_sentinel.scanner import cvss, detectors, intel


class TestCVSS(unittest.TestCase):
    """Scores are checked against the published values in the CVSS 3.1 spec."""

    CASES = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "HIGH"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "LOW"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
    ]

    def test_base_scores(self):
        for vector, expected, band in self.CASES:
            with self.subTest(vector=vector):
                score, computed_band = cvss.evaluate(vector)
                self.assertEqual(score, expected)
                self.assertEqual(computed_band, band)

    def test_malformed_vector_is_not_fatal(self):
        self.assertEqual(cvss.evaluate("garbage"), (None, "UNKNOWN"))
        self.assertEqual(cvss.evaluate(""), (None, "UNKNOWN"))
        self.assertEqual(cvss.evaluate("CVSS:3.1/AV:X"), (None, "UNKNOWN"))


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name: str, content: str) -> Path:
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_package_lock_v3(self):
        path = self.write("package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20", "license": "MIT"},
                "node_modules/@scope/pkg": {"version": "2.0.0"},
                "node_modules/a/node_modules/b": {"version": "3.0.0"},
            }}))
        components = detectors.parse(path, self.dir)
        by_name = {c.full_name: c for c in components}
        self.assertEqual(by_name["lodash"].version, "4.17.20")
        self.assertEqual(by_name["lodash"].licenses, ["MIT"])
        self.assertEqual(by_name["@scope/pkg"].purl, "pkg:npm/%40scope/pkg@2.0.0")
        self.assertFalse(by_name["b"].direct, "nested package must be transitive")

    def test_requirements_pins_only(self):
        path = self.write("requirements.txt",
                          "requests==2.19.1\n# comment\nflask>=1.0\n-r other.txt\n"
                          "django==4.2.1  # trailing\n")
        names = {c.name for c in detectors.parse(path, self.dir)}
        self.assertEqual(names, {"requests", "django"},
                         "unpinned specs cannot be resolved to a shipped version")

    def test_maven_property_resolution(self):
        path = self.write("pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
          <properties><lib.version>2.14.1</lib.version></properties>
          <dependencies>
            <dependency><groupId>org.example</groupId><artifactId>lib</artifactId>
              <version>${lib.version}</version></dependency>
            <dependency><groupId>org.example</groupId><artifactId>unresolved</artifactId>
              <version>${missing.version}</version></dependency>
          </dependencies></project>""")
        components = detectors.parse(path, self.dir)
        self.assertEqual(len(components), 1, "unresolvable properties must be dropped")
        self.assertEqual(components[0].version, "2.14.1")
        self.assertEqual(components[0].full_name, "org.example:lib")

    def test_go_mod_require_block(self):
        path = self.write("go.mod", "module x\ngo 1.21\nrequire (\n"
                                    "\tgithub.com/gin-gonic/gin v1.7.0\n"
                                    "\tgolang.org/x/crypto v0.1.0 // indirect\n)\n")
        components = detectors.parse(path, self.dir)
        self.assertEqual(len(components), 2)
        self.assertEqual(components[0].purl, "pkg:golang/github.com/gin-gonic/gin@v1.7.0")

    def test_go_mod_marks_indirect_requirements(self):
        path = self.write("go.mod", "module x\ngo 1.21\nrequire (\n"
                                    "\tgithub.com/gin-gonic/gin v1.7.0\n"
                                    "\tgolang.org/x/crypto v0.1.0 // indirect\n)\n")
        by_name = {c.name: c for c in detectors.parse(path, self.dir)}
        self.assertTrue(by_name["gin"].direct)
        self.assertFalse(by_name["crypto"].direct,
                         "// indirect must not be reported as a direct dependency")

    def test_go_sum_keeps_only_the_selected_version(self):
        # go.sum is a checksum database for the whole module graph. Every
        # version it lists is not a version that ships.
        path = self.write("go.sum",
                          "golang.org/x/net v0.0.0-20180724234803-3673e40ba225 h1:aaa=\n"
                          "golang.org/x/net v0.0.0-20180724234803-3673e40ba225/go.mod h1:bbb=\n"
                          "golang.org/x/net v0.0.0-20210525063256-abc453219eb5 h1:ccc=\n"
                          "golang.org/x/net v0.17.0 h1:ddd=\n"
                          "golang.org/x/text v0.3.0 h1:eee=\n")
        components = detectors.parse(path, self.dir)
        self.assertEqual(len(components), 2, "one component per module, not per line")
        by_name = {c.name: c for c in components}
        self.assertEqual(by_name["net"].version, "v0.17.0")
        self.assertFalse(by_name["net"].direct)

    def test_go_version_ordering(self):
        key = detectors.go_version_key
        self.assertGreater(key("v0.17.0"), key("v0.0.0-20210525063256-abc453219eb5"))
        self.assertGreater(key("v0.0.0-20210525063256-abc"),
                           key("v0.0.0-20180724234803-abc"))
        self.assertGreater(key("v1.2.3"), key("v1.2.3-rc1"))
        self.assertGreater(key("v2.0.0+incompatible"), key("v1.9.9"))
        self.assertGreater(key("v1.10.0"), key("v1.9.0"))

    def test_go_mod_outranks_go_sum_in_the_same_directory(self):
        self.write("go.sum", "golang.org/x/net v0.17.0 h1:ddd=\n")
        self.write("go.mod", "module x\ngo 1.21\nrequire golang.org/x/net v0.17.0\n")
        found = [p.name for p in detectors.discover_manifests(self.dir)]
        self.assertIn("go.mod", found)
        self.assertNotIn("go.sum", found,
                         "go.mod describes the build; go.sum describes the graph")

    def test_cargo_and_gemfile(self):
        cargo = self.write("Cargo.lock",
                           '[[package]]\nname = "serde"\nversion = "1.0.130"\n')
        self.assertEqual(detectors.parse(cargo, self.dir)[0].purl, "pkg:cargo/serde@1.0.130")
        gems = self.write("Gemfile.lock",
                          "GEM\n  specs:\n    rails (7.0.4)\n    rake (13.0.6)\n")
        self.assertEqual(len(detectors.parse(gems, self.dir)), 2)

    def test_broken_manifest_returns_empty(self):
        path = self.write("package-lock.json", "{ not json at all")
        self.assertEqual(detectors.parse(path, self.dir), [],
                         "a malformed manifest must never abort a compliance scan")

    def test_lockfile_wins_over_manifest(self):
        self.write("package.json", json.dumps({"dependencies": {"x": "1.0.0"}}))
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
        found = [p.name for p in detectors.discover_manifests(self.dir)]
        self.assertIn("package-lock.json", found)
        self.assertNotIn("package.json", found)

    def test_ignored_directories_are_skipped(self):
        self.write("node_modules/pkg/package.json", "{}")
        self.write("package.json", json.dumps({"dependencies": {"x": "1.0.0"}}))
        found = detectors.discover_manifests(self.dir)
        self.assertEqual(len(found), 1)


def _fixture_scan(with_kev: bool = True) -> ScanResult:
    component = Component(name="log4j-core", version="2.14.1", ecosystem="maven",
                          namespace="org.apache.logging.log4j", source="pom.xml")
    vuln = Vulnerability(
        id="CVE-2021-44228", summary="Remote code execution in Log4j",
        severity="CRITICAL", cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        fixed_versions=["2.15.0"], kev=with_kev, kev_ransomware=with_kev,
        cwe_ids=["CWE-502"], component_key=component.key)
    component.vulnerabilities = [vuln]
    return ScanResult(project_name="gateway", project_version="3.2.1",
                      project_path="/tmp/gateway", components=[component],
                      manifests=["pom.xml"], tool_version="1.0.0")


class TestAssessment(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_kev_fails_article14_check(self):
        scan = _fixture_scan(with_kev=True)
        checks = article14.run_checks(scan, self.dir)
        art14 = next(c for c in checks if c.id == "ART14-01")
        self.assertEqual(art14.status, article14.FAIL)
        self.assertIn("KEV", art14.evidence)

    def test_no_kev_passes_article14_check(self):
        scan = _fixture_scan(with_kev=False)
        checks = article14.run_checks(scan, self.dir)
        self.assertEqual(next(c for c in checks if c.id == "ART14-01").status,
                         article14.PASS)

    def test_security_md_satisfies_disclosure_checks(self):
        (self.dir / "SECURITY.md").write_text(
            "Contact security@acme.eu. Early warning within 24 hours to ENISA and "
            "the CSIRT. Supported until 2031. Signed update mechanism over OTA.")
        scan = _fixture_scan(with_kev=False)
        checks = {c.id: c for c in article14.run_checks(scan, self.dir)}
        for check_id in ("VULN-01", "ART14-02", "ART14-03", "UPD-01", "UPD-02"):
            self.assertEqual(checks[check_id].status, article14.PASS,
                             f"{check_id} should pass with a complete SECURITY.md")

    def test_manual_checks_excluded_from_score(self):
        scan = _fixture_scan(with_kev=False)
        checks = article14.run_checks(scan, self.dir)
        self.assertTrue(any(c.status == article14.MANUAL for c in checks))
        self.assertLessEqual(article14.score(checks), 100)
        self.assertGreaterEqual(article14.score(checks), 0)

    def test_grade_boundaries(self):
        self.assertEqual(article14.grade(90)[0], "A")
        self.assertEqual(article14.grade(89)[0], "B")
        self.assertEqual(article14.grade(55)[0], "C")
        self.assertEqual(article14.grade(0)[0], "E")


class TestUnverifiedScans(unittest.TestCase):
    """The most dangerous failure mode for a compliance tool is reporting
    'no findings' when it simply could not look. These lock that shut."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _unverified_scan(self) -> ScanResult:
        scan = ScanResult(project_name="p", project_version="1.0",
                          project_path="/tmp/p", tool_version="1.0.0",
                          components=[Component("lodash", "4.17.15", "npm")],
                          manifests=["package.json"], offline=True)
        scan.advisory_data_available = False
        return scan

    def test_unverified_flag_requires_components(self):
        empty = ScanResult(project_name="p", project_version="1.0",
                           project_path="/tmp/p", tool_version="1.0.0")
        empty.advisory_data_available = False
        self.assertFalse(empty.unverified, "no components means nothing to verify")
        self.assertTrue(self._unverified_scan().unverified)

    def test_article14_check_is_not_pass_when_unverified(self):
        checks = {c.id: c for c in article14.run_checks(self._unverified_scan(), self.dir)}
        self.assertEqual(checks["ART14-01"].status, article14.MANUAL)
        self.assertIn("NOT VERIFIED", checks["ART14-01"].evidence)
        self.assertNotEqual(checks["ART14-01"].status, article14.PASS)

    def test_vulnerability_check_is_not_pass_when_unverified(self):
        checks = {c.id: c for c in article14.run_checks(self._unverified_scan(), self.dir)}
        self.assertEqual(checks["VULN-02"].status, article14.MANUAL)

    def test_report_warns_loudly(self):
        scan = self._unverified_scan()
        scan.checks = article14.run_checks(scan, self.dir)
        scan.readiness_score = article14.score(scan.checks)
        page = html_report.render(scan)
        self.assertIn("Unverified", page)
        self.assertIn("not checked", page.lower())
        self.assertIn("No advisory data", page)

    def test_verified_clean_scan_still_passes(self):
        scan = _fixture_scan(with_kev=False)
        scan.components[0].vulnerabilities = []
        checks = {c.id: c for c in article14.run_checks(scan, self.dir)}
        self.assertEqual(checks["ART14-01"].status, article14.PASS,
                         "a genuinely clean verified scan must still pass")


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.ledger = Ledger(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_not_affected_requires_justification(self):
        with self.assertRaises(ValueError):
            self.ledger.record("CVE-1", "not_affected", "because")

    def test_rationale_is_mandatory(self):
        with self.assertRaises(ValueError):
            self.ledger.record("CVE-1", "affected", "   ")

    def test_unknown_status_rejected(self):
        with self.assertRaises(ValueError):
            self.ledger.record("CVE-1", "probably_fine", "x")

    def test_latest_decision_wins_and_history_is_kept(self):
        self.ledger.record("CVE-1", "under_investigation", "triaging")
        self.ledger.record("CVE-1", "fixed", "upgraded to 2.15.0")
        self.assertEqual(self.ledger.current()["CVE-1"].status, "fixed")
        self.assertEqual(len(self.ledger.all_entries()), 2,
                         "history must be preserved for audit")

    def test_corrupt_line_does_not_break_reading(self):
        self.ledger.record("CVE-1", "affected", "real entry")
        with self.ledger.path.open("a") as handle:
            handle.write("{ corrupt\n\n")
        self.assertEqual(len(self.ledger.all_entries()), 1)


class TestExporters(unittest.TestCase):
    def setUp(self):
        self.scan = _fixture_scan()
        self.scan.readiness_score = 42

    def test_cyclonedx_shape(self):
        doc = cyclonedx.build(self.scan, supplier="Acme GmbH")
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertEqual(doc["specVersion"], "1.6")
        self.assertTrue(doc["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(len(doc["components"]), 1)
        self.assertEqual(doc["components"][0]["purl"],
                         "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        vuln = doc["vulnerabilities"][0]
        self.assertEqual(vuln["ratings"][0]["score"], 10.0)
        self.assertEqual(vuln["cwes"], [502])
        self.assertIn({"name": "cra:article14Reportable", "value": "true"},
                      vuln["properties"])

    def test_cyclonedx_vex_analysis_from_triage(self):
        class Decision:
            status, rationale, justification = "not_affected", "not reachable", \
                "vulnerable_code_not_in_execute_path"
            remediation_plan = ""
        doc = cyclonedx.build(self.scan, triage={"CVE-2021-44228": Decision()})
        analysis = doc["vulnerabilities"][0]["analysis"]
        self.assertEqual(analysis["state"], "not_affected")
        self.assertEqual(analysis["justification"], "code_not_reachable")

    def test_spdx_shape(self):
        doc = spdx.build(self.scan, supplier="Acme GmbH")
        self.assertEqual(doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(doc["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertTrue(any(r["relationshipType"] == "DESCRIBES"
                            for r in doc["relationships"]))
        package = doc["packages"][1]
        self.assertEqual(package["externalRefs"][0]["referenceType"], "purl")

    def test_csaf_shape_and_profile(self):
        doc = csaf.build(self.scan, supplier="Acme GmbH", only_kev=True)
        self.assertEqual(doc["document"]["csaf_version"], "2.0")
        self.assertEqual(doc["document"]["category"], "csaf_vex")
        self.assertEqual(len(doc["vulnerabilities"]), 1)
        entry = doc["vulnerabilities"][0]
        self.assertEqual(entry["cve"], "CVE-2021-44228")
        self.assertIn("under_investigation", entry["product_status"])
        self.assertEqual(entry["scores"][0]["cvss_v3"]["baseScore"], 10.0)

    def test_csaf_flags_require_not_affected(self):
        class Decision:
            status, rationale, justification = "not_affected", "n/a", \
                "component_not_present"
            recorded_at, author, remediation_plan = "2026-09-10T00:00:00Z", "tester", ""
        doc = csaf.build(self.scan, triage={"CVE-2021-44228": Decision()})
        entry = doc["vulnerabilities"][0]
        self.assertIn("known_not_affected", entry["product_status"])
        self.assertEqual(entry["flags"][0]["label"], "component_not_present")

    def test_article14_notification_has_all_deadlines(self):
        draft = notification.build(self.scan, self.scan.kev_vulns[0],
                                   supplier="Acme GmbH", stage="early_warning")
        self.assertIn("24 hours", draft["legal_basis"])
        for key in ("early_warning_due", "full_notification_due", "final_report_due"):
            self.assertIn(key, draft["deadlines"])
        self.assertTrue(draft["vulnerability"]["actively_exploited"])

    def test_all_exports_are_json_serialisable(self):
        for doc in (cyclonedx.build(self.scan), spdx.build(self.scan),
                    csaf.build(self.scan),
                    notification.build(self.scan, self.scan.kev_vulns[0])):
            json.dumps(doc)


class TestReport(unittest.TestCase):
    def test_report_is_self_contained_and_escaped(self):
        scan = _fixture_scan()
        scan.project_name = '<script>alert("xss")</script>'
        scan.readiness_score = 42
        scan.checks = article14.run_checks(scan, Path(tempfile.mkdtemp()))
        page = html_report.render(scan, supplier="Acme & Co")
        self.assertNotIn('<script>alert', page, "project name must be escaped")
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("Acme &amp; Co", page)
        self.assertNotIn("http://", page.split("<style>")[1].split("</style>")[0],
                         "stylesheet must not reference external resources")
        self.assertIn("CVE-2021-44228", page)
        self.assertIn("prefers-color-scheme", page, "must support dark mode")
        self.assertIn("@media print", page, "must be printable to PDF")

    def test_empty_scan_still_renders(self):
        scan = ScanResult(project_name="empty", project_version="0.0.0",
                          project_path="/tmp/empty", tool_version="1.0.0")
        scan.checks = article14.run_checks(scan, Path(tempfile.mkdtemp()))
        scan.readiness_score = article14.score(scan.checks)
        page = html_report.render(scan)
        self.assertIn("No vulnerabilities detected", page)


class TestTransport(unittest.TestCase):
    """Network problems must produce an actionable message, never a silent
    zero-finding scan."""

    def setUp(self):
        self.intel = intel.Intel(Path(tempfile.mkdtemp()), offline=True)

    def test_tls_failure_names_the_fix(self):
        message = self.intel._explain(
            OSError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"))
        self.assertIn("certificate verification failed", message.lower())
        self.assertIn("certifi", message)

    def test_timeout_is_identified(self):
        self.assertIn("timeout", self.intel._explain(TimeoutError("timed out")).lower())

    def test_ssl_context_has_a_ca_bundle(self):
        context = intel._ssl_context()
        self.assertTrue(context.verify_mode, "certificate verification must stay on")
        self.assertGreater(len(context.get_ca_certs()), 0,
                           "a usable CA bundle must be loaded")

    def test_offline_scan_reports_no_advisory_data(self):
        component = Component("lodash", "4.17.15", "npm")
        self.intel.enrich([component])
        self.assertFalse(self.intel.advisory_data_available)


class TestSourceCompatibility(unittest.TestCase):
    def test_every_module_compiles(self):
        """Guards against syntax that only newer interpreters accept —
        nested same-quote f-strings (PEP 701) cost us a broken 3.10 install."""
        import py_compile
        root = Path(__file__).resolve().parents[1] / "cra_sentinel"
        for module in sorted(root.rglob("*.py")):
            with self.subTest(module=module.name):
                py_compile.compile(str(module), doraise=True, cfile=str(
                    Path(tempfile.mkdtemp()) / "out.pyc"))


class TestModel(unittest.TestCase):
    def test_purl_encoding_of_scoped_names(self):
        self.assertEqual(Component("pkg", "1.0", "npm", namespace="@scope").purl,
                         "pkg:npm/%40scope/pkg@1.0")

    def test_severity_ordering(self):
        component = Component("x", "1.0", "npm")
        component.vulnerabilities = [
            Vulnerability(id="a", severity="LOW"),
            Vulnerability(id="b", severity="CRITICAL"),
            Vulnerability(id="c", severity="MEDIUM")]
        self.assertEqual(component.max_severity, "CRITICAL")

    def test_scan_id_is_deterministic(self):
        scan = _fixture_scan()
        self.assertEqual(scan.scan_id, scan.scan_id)
        self.assertTrue(scan.scan_id.startswith("cras-"))

    def test_cve_resolved_from_aliases(self):
        vuln = Vulnerability(id="GHSA-abcd", aliases=["CVE-2024-1111"])
        self.assertEqual(vuln.cve, "CVE-2024-1111")


if __name__ == "__main__":
    unittest.main(verbosity=2)
