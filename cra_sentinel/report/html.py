"""Self-contained HTML compliance report.

One file, no external assets, no network at render time — it has to survive
being emailed to a notified body, printed to PDF, and opened in five years.
"""
from __future__ import annotations

import html
import json
from datetime import date

from ..assess import article14

CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f6f7f9; --surface:#ffffff; --surface-2:#fbfcfd; --ink:#11161d; --ink-2:#4a5563;
  --ink-3:#78828f; --line:#e3e7ec; --line-2:#eef1f4;
  --crit:#b3261e; --crit-bg:#fdecea; --high:#c2620a; --high-bg:#fdf1e4;
  --med:#8a6d00; --med-bg:#fdf8e2; --low:#3f6212; --low-bg:#f2f7e8;
  --ok:#136c43; --ok-bg:#e8f5ee; --info:#1f4e9c; --info-bg:#eaf1fc;
  --accent:#0f3a5f;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.04);
  --radius:10px;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#0d1117; --surface:#161b22; --surface-2:#1b2129; --ink:#e6edf3; --ink-2:#9aa6b2;
    --ink-3:#6e7681; --line:#262d36; --line-2:#1f252d;
    --crit-bg:#2d1416; --high-bg:#2a1e0d; --med-bg:#26220c; --low-bg:#16220f;
    --ok-bg:#0f2119; --info-bg:#121e30;
    --crit:#ff6b60; --high:#ffa04d; --med:#e0c341; --low:#8fce5c; --ok:#4bd18d; --info:#79aaf5;
    --accent:#cfe3f5; --shadow:0 1px 3px rgba(0,0,0,.4);
  }
}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
  font-feature-settings:"tnum" 0}
.wrap{max-width:1140px;margin:0 auto;padding:32px 20px 72px}
h1,h2,h3{line-height:1.25;letter-spacing:-.011em;margin:0}
h1{font-size:26px;font-weight:660}
h2{font-size:17px;font-weight:640;margin:0 0 14px}
h3{font-size:14px;font-weight:620}
p{margin:0 0 10px}
a{color:var(--info);text-decoration:none}
a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:.86em;font-variant-ligatures:none}
.muted{color:var(--ink-2)}
.dim{color:var(--ink-3);font-size:13px}

header.top{display:flex;flex-wrap:wrap;gap:18px;align-items:flex-start;
  justify-content:space-between;padding-bottom:20px;margin-bottom:24px;
  border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:11px;font-weight:640;font-size:13px;
  letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3)}
.brand .mark{width:22px;height:22px;border-radius:6px;background:var(--accent);
  display:grid;place-items:center;color:var(--surface);font-size:11px;font-weight:800;
  letter-spacing:0}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .brand .mark{color:#0d1117}}
.meta{text-align:right;font-size:12.5px;color:var(--ink-3);line-height:1.7}

.banner{display:flex;gap:14px;padding:16px 18px;border-radius:var(--radius);
  margin-bottom:22px;border:1px solid transparent;align-items:flex-start}
.banner.crit{background:var(--crit-bg);border-color:color-mix(in srgb,var(--crit) 32%,transparent)}
.banner.ok{background:var(--ok-bg);border-color:color-mix(in srgb,var(--ok) 28%,transparent)}
.banner .icon{font-size:19px;line-height:1.3}
.banner .t{font-weight:660;margin-bottom:3px}
.banner.crit .t{color:var(--crit)}
.banner.ok .t{color:var(--ok)}
.banner .b{font-size:13.5px;color:var(--ink-2)}

.grid{display:grid;gap:16px}
.cards{grid-template-columns:repeat(auto-fit,minmax(190px,1fr));margin-bottom:22px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  padding:16px 18px;box-shadow:var(--shadow)}
.card .label{font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--ink-3);font-weight:620;margin-bottom:7px}
.card .value{font-size:27px;font-weight:670;letter-spacing:-.02em;line-height:1.1}
.card .sub{font-size:12.5px;color:var(--ink-3);margin-top:4px}

section{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  padding:22px 24px;margin-bottom:18px;box-shadow:var(--shadow)}
.section-head{display:flex;justify-content:space-between;align-items:baseline;
  gap:12px;flex-wrap:wrap;margin-bottom:14px}
.section-head h2{margin:0}

.score-row{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.gauge{flex:0 0 auto}
.score-text{flex:1;min-width:230px}
.score-grade{font-size:32px;font-weight:700;letter-spacing:-.02em}
.score-label{font-size:15px;font-weight:600;margin-top:2px}
.score-note{font-size:13.5px;color:var(--ink-2);margin-top:8px;max-width:52ch}

.bar{display:flex;height:9px;border-radius:5px;overflow:hidden;background:var(--line-2);
  margin:12px 0 8px}
.bar span{display:block}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12.5px;color:var(--ink-2)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}

table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;
  color:var(--ink-3);font-weight:620;padding:8px 10px;border-bottom:1px solid var(--line);
  white-space:nowrap}
td{padding:10px;border-bottom:1px solid var(--line-2);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--surface-2)}
.tbl-wrap{overflow-x:auto;margin:0 -4px}

.pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11.5px;
  font-weight:640;letter-spacing:.01em;white-space:nowrap}
.p-crit{background:var(--crit-bg);color:var(--crit)}
.p-high{background:var(--high-bg);color:var(--high)}
.p-med{background:var(--med-bg);color:var(--med)}
.p-low{background:var(--low-bg);color:var(--low)}
.p-ok{background:var(--ok-bg);color:var(--ok)}
.p-info{background:var(--info-bg);color:var(--info)}
.p-none{background:var(--line-2);color:var(--ink-3)}
.kev{background:var(--crit);color:#fff;font-weight:700}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .kev{color:#1a0b0b}}

.check{display:grid;grid-template-columns:22px 1fr auto;gap:12px;padding:13px 0;
  border-bottom:1px solid var(--line-2);align-items:start}
.check:last-child{border-bottom:none}
.check .st{font-size:15px;line-height:1.4;text-align:center}
.check .title{font-weight:590}
.check .ref{font-size:12px;color:var(--ink-3);margin-top:2px}
.check .ev{font-size:13px;color:var(--ink-2);margin-top:6px}
.check .rem{font-size:13px;margin-top:7px;padding:9px 11px;border-radius:7px;
  background:var(--surface-2);border-left:2.5px solid var(--line);color:var(--ink-2)}
.check.fail .rem{border-left-color:var(--crit)}
.check.warn .rem{border-left-color:var(--high)}
.check.manual .rem{border-left-color:var(--info)}

.timeline{list-style:none;padding:0;margin:0}
.timeline li{display:flex;gap:14px;padding:11px 0;border-bottom:1px solid var(--line-2)}
.timeline li:last-child{border-bottom:none}
.timeline .when{flex:0 0 128px;font-weight:620;font-size:13.5px}
.timeline .cd{flex:0 0 104px;font-size:12.5px;font-weight:620}
.timeline .what{flex:1;font-size:13.5px;color:var(--ink-2)}

.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.filters button{font:inherit;font-size:12.5px;font-weight:590;padding:5px 11px;
  border-radius:7px;border:1px solid var(--line);background:var(--surface);
  color:var(--ink-2);cursor:pointer;transition:.12s}
.filters button:hover{border-color:var(--ink-3);color:var(--ink)}
.filters button[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);
  color:var(--surface)}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]) .filters button[aria-pressed="true"]{color:#0d1117}}
.search{font:inherit;font-size:13px;padding:6px 11px;border-radius:7px;
  border:1px solid var(--line);background:var(--surface);color:var(--ink);min-width:180px}
.search:focus{outline:2px solid var(--info);outline-offset:1px}
.hidden{display:none!important}
.empty{padding:26px;text-align:center;color:var(--ink-3);font-size:13.5px}

footer{margin-top:34px;padding-top:20px;border-top:1px solid var(--line);
  font-size:12px;color:var(--ink-3);line-height:1.7}

@media print{
  body{background:#fff;font-size:10.5pt}
  .wrap{max-width:none;padding:0}
  section{break-inside:avoid;box-shadow:none;border-color:#d5d9de}
  .filters,.search{display:none}
  .hidden{display:table-row!important}
  a{color:inherit;text-decoration:none}
  tbody tr:hover{background:none}
}
@media (max-width:640px){
  .wrap{padding:20px 14px 48px}
  h1{font-size:21px}
  .meta{text-align:left}
  .timeline li{flex-wrap:wrap}
  .timeline .when,.timeline .cd{flex:0 0 auto}
}
"""

JS = """
(function(){
  var rows=[].slice.call(document.querySelectorAll('#vuln-body tr'));
  var btns=[].slice.call(document.querySelectorAll('.filters [data-filter]'));
  var box=document.getElementById('vuln-search');
  var empty=document.getElementById('vuln-empty');
  var active='all';
  function apply(){
    var q=(box&&box.value||'').toLowerCase().trim();
    var shown=0;
    rows.forEach(function(r){
      var okF = active==='all' || r.dataset.sev===active ||
                (active==='kev'&&r.dataset.kev==='1') ||
                (active==='fixable'&&r.dataset.fixable==='1');
      var okQ = !q || r.textContent.toLowerCase().indexOf(q)>-1;
      var show = okF&&okQ;
      r.classList.toggle('hidden',!show);
      if(show) shown++;
    });
    if(empty) empty.classList.toggle('hidden',shown>0);
  }
  btns.forEach(function(b){
    b.addEventListener('click',function(){
      active=b.dataset.filter;
      btns.forEach(function(x){x.setAttribute('aria-pressed',String(x===b));});
      apply();
    });
  });
  if(box) box.addEventListener('input',apply);
  apply();
})();
"""

SEV_CLASS = {"CRITICAL": "p-crit", "HIGH": "p-high", "MEDIUM": "p-med",
             "LOW": "p-low", "UNKNOWN": "p-none", "NONE": "p-none"}
SEV_VAR = {"CRITICAL": "var(--crit)", "HIGH": "var(--high)", "MEDIUM": "var(--med)",
           "LOW": "var(--low)", "UNKNOWN": "var(--ink-3)"}
STATUS_ICON = {"pass": ("✓", "p-ok"), "fail": ("✕", "p-crit"),
               "warn": ("!", "p-high"), "manual": ("◐", "p-info")}
STATUS_WORD = {"pass": "Pass", "fail": "Fail", "warn": "Partial", "manual": "Attest"}
CATEGORY_TITLE = {
    "article14": "Article 14 — Reporting obligations",
    "sbom": "Annex I Part II(1) — Component inventory",
    "vulnerability": "Annex I Part II(2) — Vulnerability handling",
    "process": "Annex I Part II — Process and disclosure",
    "evidence": "Evidence and traceability",
    "conformity": "Conformity assessment",
}


def e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _gauge(score: int) -> str:
    radius, circumference = 52, 2 * 3.14159 * 52
    filled = circumference * score / 100
    color = ("var(--ok)" if score >= 75 else
             "var(--med)" if score >= 55 else
             "var(--high)" if score >= 35 else "var(--crit)")
    return f"""<svg class="gauge" width="132" height="132" viewBox="0 0 132 132" role="img"
 aria-label="Readiness score {score} out of 100">
 <circle cx="66" cy="66" r="{radius}" fill="none" stroke="var(--line-2)" stroke-width="11"/>
 <circle cx="66" cy="66" r="{radius}" fill="none" stroke="{color}" stroke-width="11"
   stroke-linecap="round" stroke-dasharray="{filled:.1f} {circumference:.1f}"
   transform="rotate(-90 66 66)"/>
 <text x="66" y="62" text-anchor="middle" font-size="30" font-weight="700"
   fill="var(--ink)" font-family="inherit">{score}</text>
 <text x="66" y="82" text-anchor="middle" font-size="11" fill="var(--ink-3)"
   font-family="inherit" letter-spacing="1">/ 100</text>
</svg>"""


def _severity_bar(counts: dict[str, int]) -> str:
    total = sum(counts.values())
    if not total:
        return '<p class="dim">No vulnerabilities detected in the resolved components.</p>'
    segments, legend = [], []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        n = counts.get(sev, 0)
        if not n:
            continue
        segments.append(f'<span style="width:{100*n/total:.2f}%;background:{SEV_VAR[sev]}"></span>')
        legend.append(f'<span><i style="background:{SEV_VAR[sev]}"></i>'
                      f'{sev.title()} <strong>{n}</strong></span>')
    return f'<div class="bar">{"".join(segments)}</div><div class="legend">{"".join(legend)}</div>'


def _checks_section(checks) -> str:
    order = ["article14", "vulnerability", "sbom", "process", "evidence", "conformity"]
    blocks = []
    for category in order:
        group = [c for c in checks if c.category == category]
        if not group:
            continue
        rows = []
        for check in group:
            icon, pill = STATUS_ICON.get(check.status, ("·", "p-none"))
            remediation = (f'<div class="rem">{e(check.remediation)}</div>'
                           if check.remediation and check.status != "pass" else "")
            rows.append(f"""<div class="check {e(check.status)}">
 <div class="st" style="color:var({'--ok' if check.status=='pass' else '--crit' if check.status=='fail' else '--high' if check.status=='warn' else '--info'})">{icon}</div>
 <div>
   <div class="title">{e(check.title)}</div>
   <div class="ref mono">{e(check.id)} · {e(check.cra_ref)}</div>
   <div class="ev">{e(check.evidence)}</div>
   {remediation}
 </div>
 <div><span class="pill {pill}">{STATUS_WORD.get(check.status, check.status)}</span></div>
</div>""")
        blocks.append(f'<h3 style="margin:18px 0 4px;color:var(--ink-2)">'
                      f'{e(CATEGORY_TITLE.get(category, category))}</h3>' + "".join(rows))
    return "".join(blocks)


def _vuln_rows(scan, triage: dict) -> str:
    vulns = sorted(scan.unique_vulns,
                   key=lambda v: (not v.kev, -(v.cvss_score or 0), v.id))
    by_key = {c.key: c for c in scan.components}
    rows = []
    for v in vulns:
        component = by_key.get(v.component_key)
        comp_label = (f"{component.full_name} {component.version}"
                      if component else v.component_key)
        fix = ", ".join(v.fixed_versions[:2]) if v.fixed_versions else "—"
        decision = triage.get(v.id)
        if decision:
            state = f'<span class="pill p-ok">{e(decision.status.replace("_"," "))}</span>'
        else:
            state = '<span class="pill p-none">untriaged</span>'
        kev_badge = ('<span class="pill kev" title="Listed in CISA Known Exploited '
                     'Vulnerabilities — Article 14 trigger">EXPLOITED</span> ') if v.kev else ""
        score = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "—"
        link = f"https://osv.dev/vulnerability/{v.id}"
        rows.append(f"""<tr data-sev="{e(v.severity)}" data-kev="{1 if v.kev else 0}"
 data-fixable="{1 if v.fixed_versions else 0}">
 <td class="mono"><a href="{e(link)}" target="_blank" rel="noopener">{e(v.cve)}</a></td>
 <td>{kev_badge}<span class="pill {SEV_CLASS.get(v.severity,'p-none')}">{e(v.severity.title())}</span></td>
 <td class="mono">{score}</td>
 <td class="mono">{e(comp_label)}</td>
 <td>{e((v.summary or '—')[:110])}</td>
 <td class="mono">{e(fix)}</td>
 <td>{state}</td>
</tr>""")
    return "".join(rows)


def _plural_days(days: int) -> str:
    return f"in {days} day" if days == 1 else f"in {days} days"


def _timeline() -> str:
    items = []
    for entry in article14.deadline_status():
        days = entry["days"]
        if days <= 0:
            countdown, color = "IN FORCE", "var(--crit)"
        elif days < 90:
            countdown, color = _plural_days(days), "var(--crit)"
        elif days < 400:
            countdown, color = _plural_days(days), "var(--high)"
        else:
            countdown, color = _plural_days(days), "var(--ink-3)"
        items.append(f'<li><span class="when mono">{e(entry["date"])}</span>'
                     f'<span class="cd" style="color:{color}">{countdown}</span>'
                     f'<span class="what">{e(entry["label"])}</span></li>')
    return f'<ul class="timeline">{"".join(items)}</ul>'


def render(scan, supplier: str = "", triage: dict | None = None) -> str:
    triage = triage or {}
    counts = scan.severity_counts()
    kev = scan.kev_vulns
    grade, grade_label = article14.grade(scan.readiness_score)
    failing = [c for c in scan.checks if c.status == "fail"]
    manual = [c for c in scan.checks if c.status == "manual"]
    direct = sum(1 for c in scan.components if c.direct)

    if getattr(scan, "unverified", False):
        banner = """<div class="banner crit">
 <div class="icon">⚠</div>
 <div><div class="t">Unverified — no advisory source was consulted</div>
 <div class="b">This scan resolved the component inventory but could not reach
 OSV.dev or the CISA KEV catalogue, and no cached advisory data was available.
 <strong>Zero findings below means &ldquo;not checked&rdquo;, not &ldquo;clean&rdquo;.</strong>
 Re-run with network access before filing this report as evidence under
 Regulation (EU) 2024/2847.</div></div></div>"""
    elif kev:
        ransom = sum(1 for v in kev if v.kev_ransomware)
        banner = f"""<div class="banner crit">
 <div class="icon">⚠</div>
 <div><div class="t">Article 14 exposure — {len(kev)} actively exploited
   vulnerabilit{'y' if len(kev)==1 else 'ies'} in shipped components</div>
 <div class="b">{e(', '.join(v.cve for v in kev[:6]))}{' and others' if len(kev)>6 else ''}.
 {f'{ransom} linked to known ransomware campaigns. ' if ransom else ''}
 If this product is placed on the EU market and any of these is exploited,
 Article 14(1)(a) of Regulation (EU) 2024/2847 requires an early warning to ENISA and
 the relevant CSIRT <strong>within 24 hours of becoming aware</strong>, a full notification
 within 72 hours, and a final report within 14 days of a corrective measure.</div></div></div>"""
    else:
        banner = """<div class="banner ok">
 <div class="icon">✓</div>
 <div><div class="t">No actively exploited vulnerability detected</div>
 <div class="b">No component matches the CISA Known Exploited Vulnerabilities catalogue.
 No Article 14(1)(a) reporting clock is running on the basis of this scan.</div></div></div>"""

    note = ("This product is in a defensible position. Remaining items are mostly "
            "attestations only a human can sign."
            if scan.readiness_score >= 75 else
            "Material gaps remain between the current state and the essential "
            "requirements of Annex I. The items marked Fail below are the shortest "
            "path to raising this score.")

    body = f"""<div class="wrap">
<header class="top">
  <div>
    <div class="brand"><span class="mark">CS</span> CRA Sentinel</div>
    <h1 style="margin-top:12px">{e(scan.project_name)} <span class="muted"
      style="font-weight:400">{e(scan.project_version)}</span></h1>
    <p class="dim" style="margin-top:5px">Cyber Resilience Act readiness assessment
      {f'· {e(supplier)}' if supplier else ''}</p>
  </div>
  <div class="meta">
    <div>Scan <span class="mono">{e(scan.scan_id)}</span></div>
    <div>{e(scan.scanned_at)}</div>
    <div>Regulation (EU) 2024/2847</div>
    <div>{'No advisory data' if getattr(scan,'unverified',False) else ('Cached advisory data' if scan.offline else 'OSV.dev + CISA KEV')}</div>
  </div>
</header>

{banner}

<section>
  <div class="score-row">
    {_gauge(scan.readiness_score)}
    <div class="score-text">
      <div class="score-grade" style="color:var({'--ok' if scan.readiness_score>=75 else '--med' if scan.readiness_score>=55 else '--crit'})">Grade {e(grade)}</div>
      <div class="score-label">{e(grade_label)}</div>
      <div class="score-note">{note}</div>
      <div class="dim" style="margin-top:10px">
        {len([c for c in scan.checks if c.status=='pass'])} passed ·
        {len([c for c in scan.checks if c.status=='warn'])} partial ·
        {len(failing)} failed · {len(manual)} require manual attestation
      </div>
    </div>
  </div>
</section>

<div class="grid cards">
  <div class="card"><div class="label">Components</div>
    <div class="value">{len(scan.components)}</div>
    <div class="sub">{direct} direct · {len(scan.components)-direct} transitive</div></div>
  <div class="card"><div class="label">Findings</div>
    <div class="value">{len(scan.unique_vulns)}</div>
    <div class="sub">{counts['CRITICAL']} critical · {counts['HIGH']} high</div></div>
  <div class="card"><div class="label">Actively exploited</div>
    <div class="value" style="color:var({'--crit' if kev else '--ok'})">{len(kev)}</div>
    <div class="sub">CISA KEV intersection</div></div>
  <div class="card"><div class="label">Triage recorded</div>
    <div class="value">{len(triage)}</div>
    <div class="sub">of {len(scan.unique_vulns)} findings</div></div>
</div>

<section>
  <h2>Severity distribution</h2>
  {_severity_bar(counts)}
</section>

<section>
  <h2>Regulatory timeline</h2>
  {_timeline()}
  <p class="dim" style="margin-top:12px">Reporting under Article 14 flows through the
  single reporting platform to ENISA and the CSIRT designated as coordinator in the
  Member State of main establishment.</p>
</section>

<section>
  <div class="section-head">
    <h2>Compliance checks</h2>
    <span class="dim">{len(scan.checks)} controls assessed against Regulation (EU) 2024/2847</span>
  </div>
  {_checks_section(scan.checks)}
</section>

<section>
  <div class="section-head">
    <h2>Vulnerability register</h2>
    <div class="filters">
      <input class="search" id="vuln-search" type="search" placeholder="Filter…"
        aria-label="Filter vulnerabilities">
      <button data-filter="all" aria-pressed="true">All</button>
      <button data-filter="kev" aria-pressed="false">Exploited</button>
      <button data-filter="CRITICAL" aria-pressed="false">Critical</button>
      <button data-filter="HIGH" aria-pressed="false">High</button>
      <button data-filter="fixable" aria-pressed="false">Fix available</button>
    </div>
  </div>
  <div class="tbl-wrap">
  <table>
    <thead><tr><th>Identifier</th><th>Severity</th><th>CVSS</th><th>Component</th>
      <th>Summary</th><th>Fixed in</th><th>Assessment</th></tr></thead>
    <tbody id="vuln-body">{_vuln_rows(scan, triage)}</tbody>
  </table>
  </div>
  <div class="empty hidden" id="vuln-empty">No finding matches the current filter.</div>
</section>

<footer>
  <p><strong>Scope and limitations.</strong> This report is generated from dependency
  manifests resolved at {e(scan.scanned_at)} and cross-referenced against the OSV.dev
  advisory database and the CISA Known Exploited Vulnerabilities catalogue. It covers
  third-party component risk. It does not assess first-party source code, hardware,
  cryptographic implementation, or the organisational measures required by Annex I
  Part I. Checks marked "Attest" cannot be verified by a tool and remain the
  manufacturer's responsibility.</p>
  <p>CRA Sentinel v{e(scan.tool_version)} · scan {e(scan.scan_id)} ·
  generated {e(date.today().isoformat())}. This document supports, and does not replace,
  the technical documentation required under Annex VII.</p>
</footer>
</div>"""

    return (f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CRA readiness — {e(scan.project_name)} {e(scan.project_version)}</title>
<meta name="generator" content="CRA Sentinel {e(scan.tool_version)}">
<style>{CSS}</style></head>
<body>{body}<script>{JS}</script></body></html>""")
