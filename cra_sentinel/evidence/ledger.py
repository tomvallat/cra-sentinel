"""Append-only triage ledger.

Annex I Part II(2) requires vulnerabilities to be addressed "without delay" —
but a manufacturer is equally allowed to conclude a component is not affected.
What is *not* allowed is an undocumented decision. This ledger is the artefact
an auditor reads: who decided what, when, and on what grounds.

Entries are never mutated. A superseding decision appends a new entry and the
latest one wins, so the full decision history survives.
"""
from __future__ import annotations

import getpass
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..model import utcnow

# CycloneDX / CSAF VEX analysis states
STATES = {
    "affected": "The product is affected; remediation is required.",
    "not_affected": "The product is not affected by this vulnerability.",
    "fixed": "The vulnerability has been remediated in the shipped version.",
    "under_investigation": "Assessment in progress; no conclusion reached yet.",
    "false_positive": "The finding does not apply to this product.",
}

# CSAF 2.0 flag labels justifying a not_affected state
JUSTIFICATIONS = {
    "component_not_present": "The vulnerable component is not present in the shipped artefact.",
    "vulnerable_code_not_present": "The vulnerable code is not present.",
    "vulnerable_code_not_in_execute_path": "The vulnerable code is present but never reached.",
    "vulnerable_code_cannot_be_controlled_by_adversary": "The vulnerable code cannot be influenced by an attacker.",
    "inline_mitigations_already_exist": "Compensating controls already neutralise the issue.",
}


@dataclass
class TriageEntry:
    vuln_id: str
    status: str
    rationale: str
    author: str
    recorded_at: str = field(default_factory=utcnow)
    justification: str = ""
    component: str = ""
    remediation_plan: str = ""
    target_date: str = ""
    scan_id: str = ""

    @property
    def entry_hash(self) -> str:
        payload = f"{self.vuln_id}|{self.status}|{self.rationale}|{self.recorded_at}|{self.author}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


class Ledger:
    def __init__(self, root: Path):
        self.path = root / ".cra-sentinel" / "triage.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: TriageEntry) -> TriageEntry:
        with self.path.open("a", encoding="utf-8") as handle:
            record = asdict(entry)
            record["entry_hash"] = entry.entry_hash
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return entry

    def all_entries(self) -> list[TriageEntry]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except ValueError:
                continue
            data.pop("entry_hash", None)
            try:
                out.append(TriageEntry(**data))
            except TypeError:
                continue
        return out

    def current(self) -> dict[str, TriageEntry]:
        """Latest decision per vulnerability id."""
        latest: dict[str, TriageEntry] = {}
        for entry in self.all_entries():
            latest[entry.vuln_id] = entry
        return latest

    def record(self, vuln_id: str, status: str, rationale: str,
               justification: str = "", component: str = "",
               remediation_plan: str = "", target_date: str = "",
               author: str = "", scan_id: str = "") -> TriageEntry:
        if status not in STATES:
            raise ValueError(f"unknown status '{status}'. Valid: {', '.join(STATES)}")
        if justification and justification not in JUSTIFICATIONS:
            raise ValueError(f"unknown justification '{justification}'. "
                             f"Valid: {', '.join(JUSTIFICATIONS)}")
        if status == "not_affected" and not justification:
            raise ValueError(
                "a 'not_affected' decision requires --justification: CSAF 2.0 mandates "
                "an impact statement, and an auditor will ask for it.")
        if not rationale.strip():
            raise ValueError("a rationale is mandatory — the written reasoning is the evidence.")

        try:
            author = author or getpass.getuser()
        except Exception:
            author = author or "unknown"

        return self.append(TriageEntry(
            vuln_id=vuln_id, status=status, rationale=rationale.strip(),
            author=author, justification=justification, component=component,
            remediation_plan=remediation_plan, target_date=target_date, scan_id=scan_id))
