"""Portfolio dashboard.

Read-mostly, one page, no build step. The operator's morning question is
"what is on my clock right now", so the countdown sits above everything else.
"""
from __future__ import annotations

import html
from datetime import timedelta

from ..report.html import CSS as REPORT_CSS
from .store import Store, parse, utcnow

EXTRA_CSS = """
.pf-head{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;
  flex-wrap:wrap;padding-bottom:18px;margin-bottom:22px;border-bottom:1px solid var(--line)}
.clock{display:grid;grid-template-columns:auto 1fr auto;gap:16px;align-items:center;
  padding:14px 18px;border-radius:var(--radius);margin-bottom:10px;
  background:var(--crit-bg);border:1px solid color-mix(in srgb,var(--crit) 34%,transparent)}
.clock.warn{background:var(--high-bg);border-color:color-mix(in srgb,var(--high) 34%,transparent)}
.clock .rem{font-variant-numeric:tabular-nums;font-weight:700;font-size:19px;
  color:var(--crit);white-space:nowrap;min-width:104px}
.clock.warn .rem{color:var(--high)}
.clock .who{font-size:13px;color:var(--ink-2)}
.clock .who b{color:var(--ink);font-size:14.5px}
.clock .act{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--ink-3);
  text-align:right;white-space:nowrap}
.prod{display:grid;grid-template-columns:1fr auto auto auto auto;gap:14px;
  align-items:center;padding:13px 0;border-bottom:1px solid var(--line-2)}
.prod:last-child{border-bottom:none}
.prod .nm{font-weight:600}
.prod .sub{font-size:12px;color:var(--ink-3);font-family:ui-monospace,Menlo,monospace}
.prod .met{text-align:right;font-variant-numeric:tabular-nums;font-size:13px;
  color:var(--ink-2);min-width:62px}
.prod .met i{display:block;font-style:normal;font-size:10.5px;color:var(--ink-3);
  text-transform:uppercase;letter-spacing:.05em}
.stale{color:var(--high)}
@media (max-width:720px){
  .prod{grid-template-columns:1fr 1fr;gap:8px}
  .clock{grid-template-columns:1fr;gap:6px}
  .clock .act{text-align:left}
}
"""


def e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _remaining(due_iso: str) -> tuple[str, bool]:
    due = parse(due_iso)
    if due is None:
        return "—", False
    delta = due - utcnow()
    seconds = delta.total_seconds()
    if seconds <= 0:
        return "DÉPASSÉ", False
    hours, minutes = int(seconds // 3600), int((seconds % 3600) // 60)
    return f"{hours} h {minutes:02d}", hours >= 8


def render(store: Store, operator: str = "") -> str:
    summary = store.portfolio_summary()
    products = store.products(active_only=True)
    alerts = store.open_alerts()
    now = utcnow()

    clocks = []
    for alert in alerts:
        if alert["kind"] != "exploited":
            continue
        remaining, calm = _remaining(alert["early_warning_due"])
        clocks.append(f"""<div class="clock {'warn' if calm else ''}">
  <div class="rem">{e(remaining)}</div>
  <div class="who"><b>{e(alert['product_name'])}</b> — {e(alert['label'] or alert['vuln_id'])}
    <div class="dim">Prise de connaissance {e(alert['awareness_at'])} ·
      alerte précoce due {e(alert['early_warning_due'])}</div></div>
  <div class="act">cra watchtower ack {e(alert['slug'])} {e(alert['label'] or alert['vuln_id'])}</div>
</div>""")

    if not clocks:
        clocks.append("""<div class="banner ok"><div class="icon">✓</div>
  <div><div class="t">Aucune horloge Article 14 en cours</div>
  <div class="b">Aucune vulnérabilité activement exploitée n'attend
  d'acquittement sur le portefeuille.</div></div></div>""")

    rows = []
    for product in products:
        last = store.last_sweep(product.id)
        kev = len(store.open_findings(product.id, kev_only=True))
        total = len(store.open_findings(product.id))
        when = parse(last["started_at"]) if last else None
        age_hours = (now - when).total_seconds() / 3600 if when else None
        if age_hours is None:
            freshness, stale = "jamais", True
        elif age_hours < 1:
            freshness, stale = "à l'instant", False
        elif age_hours < 48:
            freshness, stale = f"il y a {int(age_hours)} h", age_hours > 30
        else:
            freshness, stale = f"il y a {int(age_hours / 24)} j", True
        status = last["status"] if last else "—"
        score = last["score"] if last and last["score"] is not None else "—"

        rows.append(f"""<div class="prod">
  <div><div class="nm">{e(product.name)}</div>
    <div class="sub">{e(product.slug)}{f' · {e(product.supplier)}' if product.supplier else ''}</div></div>
  <div class="met"><i>Score</i>{e(score)}</div>
  <div class="met"><i>Findings</i>{total}</div>
  <div class="met"><i>Exploitées</i>
    <span style="color:var({'--crit' if kev else '--ok'})">{kev}</span></div>
  <div class="met"><i>Balayage</i>
    <span class="{'stale' if stale else ''}">{e(freshness)}</span>
    <div class="sub" style="text-transform:none">{e(status)}</div></div>
</div>""")

    if not rows:
        rows.append('<p class="dim">Aucun produit surveillé. '
                    'Ajoutez-en un avec <span class="mono">cra watchtower add</span>.</p>')

    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="120">
<title>Watchtower — portefeuille CRA</title>
<style>{REPORT_CSS}{EXTRA_CSS}</style></head><body>
<div class="wrap">
  <header class="top">
    <div>
      <div class="brand"><span class="mark">CS</span> Watchtower</div>
      <h1 style="margin-top:12px">Portefeuille sous surveillance</h1>
      <p class="dim" style="margin-top:5px">Règlement (UE) 2024/2847 · Article 14
        {f'· {e(operator)}' if operator else ''}</p>
    </div>
    <div class="meta">
      <div>{summary['products']} produit(s) actif(s)</div>
      <div>{summary['open_alerts']} alerte(s) non acquittée(s)</div>
      <div>{e(now.isoformat().replace('+00:00', 'Z'))}</div>
    </div>
  </header>

  <section>
    <div class="section-head"><h2>Horloges en cours</h2>
      <span class="dim">Compte à rebours jusqu'à l'échéance d'alerte précoce (24 h)</span></div>
    {''.join(clocks)}
  </section>

  <div class="grid cards">
    <div class="card"><div class="label">Produits</div>
      <div class="value">{summary['products']}</div><div class="sub">sous surveillance</div></div>
    <div class="card"><div class="label">Exploitées</div>
      <div class="value" style="color:var({'--crit' if summary['exploited'] else '--ok'})">{summary['exploited']}</div>
      <div class="sub">non résolues, tout le portefeuille</div></div>
    <div class="card"><div class="label">Alertes ouvertes</div>
      <div class="value">{summary['open_alerts']}</div><div class="sub">en attente d'acquittement</div></div>
  </div>

  <section>
    <div class="section-head"><h2>Produits</h2>
      <span class="dim">Un balayage de plus de 30 h est signalé</span></div>
    {''.join(rows)}
  </section>

  <footer>
    <p>Chaque horodatage de prise de connaissance est conservé de façon
    définitive : c'est le fait de référence à partir duquel courent les délais
    de l'Article 14. Cette page se rafraîchit toutes les deux minutes.</p>
    <p>CRA Sentinel Watchtower · surveillance continue · ne constitue pas un
    conseil juridique.</p>
  </footer>
</div></body></html>"""
