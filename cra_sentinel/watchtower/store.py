"""Portfolio state.

SQLite because the retainer promise is evidentiary: a client pays for a
defensible record of *when the manufacturer became aware*. Article 14 starts
its clock at awareness, not at confirmation and not at the fix — so that
timestamp is the single most valuable field in this whole system, and it has
to survive a crash, a restart and an audit five years later.

Nothing is ever deleted. Findings are resolved by setting a timestamp.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id           INTEGER PRIMARY KEY,
  slug         TEXT NOT NULL UNIQUE,
  name         TEXT NOT NULL,
  supplier     TEXT NOT NULL DEFAULT '',
  contact      TEXT NOT NULL DEFAULT '',
  member_state TEXT NOT NULL DEFAULT '',
  source_kind  TEXT NOT NULL DEFAULT 'path',   -- path | git
  source       TEXT NOT NULL,
  branch       TEXT NOT NULL DEFAULT '',
  active       INTEGER NOT NULL DEFAULT 1,
  added_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sweeps (
  id          INTEGER PRIMARY KEY,
  product_id  INTEGER NOT NULL REFERENCES products(id),
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  status      TEXT NOT NULL DEFAULT 'running', -- running | ok | unverified | error
  scan_id     TEXT NOT NULL DEFAULT '',
  score       INTEGER,
  components  INTEGER,
  findings    INTEGER,
  kev_count   INTEGER,
  error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sweeps_product ON sweeps(product_id, started_at DESC);

CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY,
  product_id    INTEGER NOT NULL REFERENCES products(id),
  vuln_id       TEXT NOT NULL,
  cve           TEXT NOT NULL DEFAULT '',
  severity      TEXT NOT NULL DEFAULT 'UNKNOWN',
  cvss          REAL,
  component     TEXT NOT NULL DEFAULT '',
  summary       TEXT NOT NULL DEFAULT '',
  fixed_in      TEXT NOT NULL DEFAULT '',
  kev           INTEGER NOT NULL DEFAULT 0,
  ransomware    INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL,
  kev_since     TEXT,                          -- when it BECAME actively exploited
  last_seen_at  TEXT NOT NULL,
  resolved_at   TEXT,
  UNIQUE(product_id, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_kev ON findings(product_id, kev, resolved_at);

CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER PRIMARY KEY,
  product_id      INTEGER NOT NULL REFERENCES products(id),
  vuln_id         TEXT NOT NULL,
  kind            TEXT NOT NULL,               -- exploited | new_critical | scan_error | unverified
  awareness_at    TEXT NOT NULL,               -- Article 14 clock starts HERE
  early_warning_due TEXT NOT NULL,
  notification_due  TEXT NOT NULL,
  sent_at         TEXT,
  channels        TEXT NOT NULL DEFAULT '',
  delivery_error  TEXT NOT NULL DEFAULT '',
  acknowledged_at TEXT,
  acknowledged_by TEXT NOT NULL DEFAULT '',
  note            TEXT NOT NULL DEFAULT '',
  UNIQUE(product_id, vuln_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(acknowledged_at, awareness_at);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class Product:
    id: int
    slug: str
    name: str
    supplier: str
    contact: str
    member_state: str
    source_kind: str
    source: str
    branch: str
    active: bool
    added_at: str


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema', ?)",
                         (str(SCHEMA_VERSION),))
        finally:
            conn.close()

    @contextmanager
    def connect(self):
        """One connection, one transaction. WAL lets the dashboard read while a
        sweep writes, which matters once sweeps take minutes.

        The in_transaction guards are not defensive noise: executescript() and
        some PRAGMAs commit implicitly, so an unguarded COMMIT here raises
        "no transaction is active" and takes the whole sweep down with it.
        """
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("BEGIN")
            yield conn
            if conn.in_transaction:
                conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # -- products ---------------------------------------------------------

    def add_product(self, slug: str, name: str, source: str, source_kind: str = "path",
                    supplier: str = "", contact: str = "", member_state: str = "",
                    branch: str = "") -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """INSERT INTO products(slug, name, supplier, contact, member_state,
                                        source_kind, source, branch, added_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (slug, name, supplier, contact, member_state, source_kind,
                 source, branch, iso(utcnow())))
            return cur.lastrowid

    def products(self, active_only: bool = True) -> list[Product]:
        query = "SELECT * FROM products"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY name"
        with self.connect() as conn:
            return [Product(**{**dict(r), "active": bool(r["active"])})
                    for r in conn.execute(query)]

    def product(self, slug: str) -> Product | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM products WHERE slug = ?", (slug,)).fetchone()
        return Product(**{**dict(row), "active": bool(row["active"])}) if row else None

    def set_active(self, slug: str, active: bool) -> bool:
        with self.connect() as conn:
            return conn.execute("UPDATE products SET active = ? WHERE slug = ?",
                                (1 if active else 0, slug)).rowcount > 0

    # -- sweeps -----------------------------------------------------------

    def open_sweep(self, product_id: int) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO sweeps(product_id, started_at) VALUES (?,?)",
                (product_id, iso(utcnow())))
            return cur.lastrowid

    def close_sweep(self, sweep_id: int, status: str, scan_id: str = "",
                    score: int | None = None, components: int | None = None,
                    findings: int | None = None, kev_count: int | None = None,
                    error: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                """UPDATE sweeps SET finished_at=?, status=?, scan_id=?, score=?,
                       components=?, findings=?, kev_count=?, error=? WHERE id=?""",
                (iso(utcnow()), status, scan_id, score, components, findings,
                 kev_count, error[:500], sweep_id))

    def last_sweep(self, product_id: int) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                """SELECT * FROM sweeps WHERE product_id=? AND finished_at IS NOT NULL
                   ORDER BY started_at DESC LIMIT 1""", (product_id,)).fetchone()

    def sweeps(self, product_id: int, limit: int = 30) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return list(conn.execute(
                """SELECT * FROM sweeps WHERE product_id=? ORDER BY started_at DESC
                   LIMIT ?""", (product_id, limit)))

    # -- findings ---------------------------------------------------------

    def reconcile(self, product_id: int, current: list[dict]) -> dict[str, list[dict]]:
        """Merge this sweep's findings into the ledger.

        Returns the transitions that matter: findings seen for the first time,
        and — the one that starts a legal clock — findings that have just
        become actively exploited.
        """
        now = iso(utcnow())
        new_findings: list[dict] = []
        newly_exploited: list[dict] = []

        with self.connect() as conn:
            existing = {
                r["vuln_id"]: r for r in
                conn.execute("SELECT * FROM findings WHERE product_id=?", (product_id,))
            }
            seen = set()

            for item in current:
                vid = item["vuln_id"]
                seen.add(vid)
                prior = existing.get(vid)

                if prior is None:
                    conn.execute(
                        """INSERT INTO findings(product_id, vuln_id, cve, severity, cvss,
                               component, summary, fixed_in, kev, ransomware,
                               first_seen_at, kev_since, last_seen_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (product_id, vid, item["cve"], item["severity"], item["cvss"],
                         item["component"], item["summary"][:400], item["fixed_in"],
                         int(item["kev"]), int(item["ransomware"]), now,
                         now if item["kev"] else None, now))
                    new_findings.append(item)
                    if item["kev"]:
                        newly_exploited.append(item)
                    continue

                became_exploited = item["kev"] and not prior["kev"]
                conn.execute(
                    """UPDATE findings SET severity=?, cvss=?, fixed_in=?, kev=?,
                           ransomware=?, last_seen_at=?, resolved_at=NULL,
                           kev_since=COALESCE(kev_since, ?)
                       WHERE product_id=? AND vuln_id=?""",
                    (item["severity"], item["cvss"], item["fixed_in"], int(item["kev"]),
                     int(item["ransomware"]), now, now if item["kev"] else None,
                     product_id, vid))
                if became_exploited:
                    newly_exploited.append(item)

            gone = [v for v in existing if v not in seen and not existing[v]["resolved_at"]]
            for vid in gone:
                conn.execute(
                    "UPDATE findings SET resolved_at=? WHERE product_id=? AND vuln_id=?",
                    (now, product_id, vid))

        return {"new": new_findings, "newly_exploited": newly_exploited,
                "resolved": [{"vuln_id": v} for v in gone]}

    def open_findings(self, product_id: int, kev_only: bool = False) -> list[sqlite3.Row]:
        query = "SELECT * FROM findings WHERE product_id=? AND resolved_at IS NULL"
        if kev_only:
            query += " AND kev = 1"
        query += " ORDER BY kev DESC, cvss DESC"
        with self.connect() as conn:
            return list(conn.execute(query, (product_id,)))

    # -- alerts -----------------------------------------------------------

    def raise_alert(self, product_id: int, vuln_id: str, kind: str,
                    awareness: datetime | None = None) -> sqlite3.Row | None:
        """Record awareness. Returns the alert row, or None if one already
        exists — deduplication is not a nicety here: re-alerting resets nothing
        legally, but it trains the recipient to ignore the channel."""
        moment = awareness or utcnow()
        try:
            with self.connect() as conn:
                cur = conn.execute(
                    """INSERT INTO alerts(product_id, vuln_id, kind, awareness_at,
                           early_warning_due, notification_due)
                       VALUES (?,?,?,?,?,?)""",
                    (product_id, vuln_id, kind, iso(moment),
                     iso(moment + timedelta(hours=24)),
                     iso(moment + timedelta(hours=72))))
                return conn.execute("SELECT * FROM alerts WHERE id=?",
                                    (cur.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            return None

    def mark_sent(self, alert_id: int, channels: list[str], error: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE alerts SET sent_at=?, channels=?, delivery_error=? WHERE id=?",
                (iso(utcnow()), ",".join(channels), error[:300], alert_id))

    def acknowledge(self, alert_id: int, by: str, note: str = "") -> bool:
        with self.connect() as conn:
            return conn.execute(
                """UPDATE alerts SET acknowledged_at=?, acknowledged_by=?, note=?
                   WHERE id=? AND acknowledged_at IS NULL""",
                (iso(utcnow()), by, note[:500], alert_id)).rowcount > 0

    def resolve_vuln_id(self, product_id: int, identifier: str) -> str | None:
        """Accept either the OSV id or the CVE alias.

        Alerts are keyed on the OSV id because it is stable, but every human
        artefact — the alert email, a client phone call, a regulator's letter —
        uses the CVE. Both must work, or the command we print in the alert is
        a command that fails."""
        wanted = identifier.strip().upper()
        with self.connect() as conn:
            row = conn.execute(
                """SELECT vuln_id FROM findings
                   WHERE product_id = ?
                     AND (UPPER(vuln_id) = ? OR UPPER(cve) = ?) LIMIT 1""",
                (product_id, wanted, wanted)).fetchone()
        return row["vuln_id"] if row else None

    def open_alerts(self) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return list(conn.execute(
                """SELECT a.*, p.slug, p.name AS product_name, p.supplier,
                          COALESCE(NULLIF(f.cve, ''), a.vuln_id) AS label,
                          f.severity, f.cvss, f.component, f.fixed_in, f.ransomware
                   FROM alerts a
                   JOIN products p ON p.id = a.product_id
                   LEFT JOIN findings f
                          ON f.product_id = a.product_id AND f.vuln_id = a.vuln_id
                   WHERE a.acknowledged_at IS NULL
                   ORDER BY a.awareness_at"""))

    def alerts_for(self, product_id: int, limit: int = 50) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return list(conn.execute(
                "SELECT * FROM alerts WHERE product_id=? ORDER BY awareness_at DESC LIMIT ?",
                (product_id, limit)))

    def breaching(self, hours: int = 24) -> list[sqlite3.Row]:
        """Open alerts whose early-warning window has run out. This is the
        query the whole service exists to answer."""
        cutoff = iso(utcnow() - timedelta(hours=hours))
        with self.connect() as conn:
            return list(conn.execute(
                """SELECT a.*, p.slug, p.name AS product_name,
                          COALESCE(NULLIF(f.cve, ''), a.vuln_id) AS label
                   FROM alerts a
                   JOIN products p ON p.id = a.product_id
                   LEFT JOIN findings f
                          ON f.product_id = a.product_id AND f.vuln_id = a.vuln_id
                   WHERE a.acknowledged_at IS NULL AND a.kind='exploited'
                         AND a.awareness_at <= ?
                   ORDER BY a.awareness_at""", (cutoff,)))

    def portfolio_summary(self) -> dict:
        with self.connect() as conn:
            row = conn.execute("""
                SELECT (SELECT COUNT(*) FROM products WHERE active=1) AS products,
                       (SELECT COUNT(*) FROM findings WHERE kev=1 AND resolved_at IS NULL)
                           AS exploited,
                       (SELECT COUNT(*) FROM alerts WHERE acknowledged_at IS NULL)
                           AS open_alerts
            """).fetchone()
        return dict(row)
