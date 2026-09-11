"""CVSS v3.1 / v4.0 base score computation.

OSV returns severity as a CVSS vector string. We compute the numeric base score
locally rather than trusting a vendor field, because CRA Annex I requires the
manufacturer to be able to justify its own severity assessment.
"""
from __future__ import annotations

W_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},          # scope-unchanged values
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},         # scope-changed values
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A roundup: smallest 1-decimal number >= value."""
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (scaled // 10_000 + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    out = {}
    for part in (vector or "").split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            out[k] = v
    return out


def score_v3(vector: str) -> float | None:
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - ((1 - W_V3["CIA"][m["C"]]) * (1 - W_V3["CIA"][m["I"]]) * (1 - W_V3["CIA"][m["A"]]))
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed \
            else 6.42 * iss
        exploitability = 8.22 * W_V3["AV"][m["AV"]] * W_V3["AC"][m["AC"]] \
            * W_V3["PR_C" if scope_changed else "PR"][m["PR"]] * W_V3["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    return _roundup(raw)


def score_v4_approx(vector: str) -> float | None:
    """CVSS v4.0 nomenclature is not yet common in OSV. We approximate from the
    exploitability/impact metrics so v4-only advisories still get a band."""
    m = parse_vector(vector)
    if not m.get("AV"):
        return None
    impact = max(("VC" in m and m["VC"] or "N"), ("VI" in m and m["VI"] or "N"),
                 ("VA" in m and m["VA"] or "N"), key=lambda x: {"H": 3, "L": 2, "N": 1}.get(x, 0))
    base = {"H": 8.0, "L": 5.0, "N": 2.0}.get(impact, 2.0)
    if m.get("AV") == "N":
        base += 1.0
    if m.get("PR") == "N":
        base += 0.5
    if m.get("UI") == "N":
        base += 0.4
    return round(min(base, 10.0), 1)


def band(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def evaluate(vector: str) -> tuple[float | None, str]:
    """Return (score, severity band) for any CVSS vector string."""
    if not vector:
        return None, "UNKNOWN"
    if vector.startswith("CVSS:4"):
        score = score_v4_approx(vector)
    else:
        score = score_v3(vector)
    return score, band(score)
