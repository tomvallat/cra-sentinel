"""`cra watchtower ...` subcommands."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

from .. import term
from .config import DEFAULT_DIR, Config
from .dashboard import render
from .runner import sweep
from .store import Store, parse, utcnow

EXIT_OK, EXIT_ATTENTION, EXIT_ERROR = 0, 1, 2


def _log(quiet: bool):
    def log(message: str) -> None:
        if not quiet:
            stamp = time.strftime("%H:%M:%S")
            print(term.grey(f"  {stamp} {message}"), file=sys.stderr)
    return log


def _config(args) -> Config:
    return Config.load(Path(args.config) if args.config else None)


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "produit"


# --------------------------------------------------------------------------

def cmd_init(args) -> int:
    path = Config.scaffold(Path(args.config) if args.config else None)
    print(term.header("Watchtower initialisé", str(path.parent)))
    print(term.kv("Configuration", term.cyan(str(path))))
    print()
    print(term.grey("  Renseignez les canaux d'alerte, puis exportez le mot de passe :"))
    print(term.grey("    export CRA_SMTP_PASSWORD='...'"))
    print(term.grey("    export CRA_WEBHOOK_URL='https://hooks.slack.com/...'   (optionnel)"))
    print()
    print(term.grey("  Puis ajoutez un produit :"))
    print(term.cyan("    cra watchtower add \"Gateway 3.2.1\" --source /srv/clients/acme"))
    print()
    return EXIT_OK


def cmd_add(args) -> int:
    try:
        config = _config(args)
    except (FileNotFoundError, ValueError) as exc:
        print(term.red(f"  {exc}"), file=sys.stderr)
        return EXIT_ERROR

    source = args.source
    kind = "git" if re.match(r"^(https?://|git@|ssh://)", source) else "path"
    if kind == "path":
        resolved = Path(source).expanduser()
        if not resolved.is_dir():
            print(term.red(f"  répertoire introuvable : {resolved}"), file=sys.stderr)
            return EXIT_ERROR
        source = str(resolved.resolve())

    store = Store(config.database)
    slug = args.slug or _slugify(args.name)
    if store.product(slug):
        print(term.red(f"  le slug '{slug}' est déjà utilisé — précisez --slug"),
              file=sys.stderr)
        return EXIT_ERROR

    store.add_product(slug=slug, name=args.name, source=source, source_kind=kind,
                      supplier=args.supplier, contact=args.contact,
                      member_state=args.member_state, branch=args.branch)

    print(term.header("Produit ajouté au portefeuille"))
    print(term.kv("Nom", term.bold(args.name)))
    print(term.kv("Slug", term.cyan(slug)))
    print(term.kv("Source", f"{term.grey(kind)}  {source}"))
    if args.supplier:
        print(term.kv("Fabricant", args.supplier))
    print()
    print(term.grey("  Premier balayage :  ") + term.cyan(f"cra watchtower run --only {slug}"))
    print()
    return EXIT_OK


def cmd_run(args) -> int:
    try:
        config = _config(args)
    except (FileNotFoundError, ValueError) as exc:
        print(term.red(f"  {exc}"), file=sys.stderr)
        return EXIT_ERROR

    log = _log(args.quiet)
    for warning in config.warnings():
        print(term.yellow(f"  attention : {warning}"), file=sys.stderr)

    report = sweep(config, log=log, only=args.only)

    if not args.quiet:
        print(term.header("Balayage terminé"))
    for line in report.lines:
        colour = term.red if line.startswith("✕") else \
            term.yellow if line.startswith("!") else term.grey
        print("  " + colour(line))
    print()
    print(term.kv("Produits balayés", str(report.products_scanned)))
    if report.products_failed:
        print(term.kv("Produits en échec", term.red(str(report.products_failed))))
    print(term.kv("Nouvelles vulnérabilités", str(report.new_findings)))
    if report.newly_exploited:
        print(term.kv("Nouvellement exploitées",
                      term.red(term.bold(str(report.newly_exploited)))))
    print(term.kv("Résolues", term.green(str(report.resolved)) if report.resolved else "0"))
    print(term.kv("Alertes émises", str(report.alerts_raised)))
    if report.escalations:
        print(term.kv("Relances", term.yellow(str(report.escalations))))
    if report.delivery_errors:
        print()
        print(term.red("  Échecs de distribution :"))
        for error in report.delivery_errors:
            print(term.red(f"    {error}"))
        print(term.grey("    L'horodatage de prise de connaissance est enregistré "
                        "malgré tout."))
    print()
    return EXIT_ATTENTION if report.needs_attention else EXIT_OK


def cmd_status(args) -> int:
    try:
        config = _config(args)
    except (FileNotFoundError, ValueError) as exc:
        print(term.red(f"  {exc}"), file=sys.stderr)
        return EXIT_ERROR

    store = Store(config.database)
    summary = store.portfolio_summary()
    products = store.products(active_only=not args.all)
    alerts = store.open_alerts()
    now = utcnow()

    print(term.header("Portefeuille sous surveillance",
                      f"{summary['products']} produit(s) · "
                      f"{summary['open_alerts']} alerte(s) ouverte(s)"))

    if alerts:
        print(f"  {term.bold('Horloges en cours')}")
        print()
        for alert in alerts:
            due = parse(alert["early_warning_due"])
            if due is None:
                remaining, colour = "—", term.grey
            else:
                seconds = (due - now).total_seconds()
                if seconds <= 0:
                    remaining, colour = "DÉPASSÉ", term.red
                else:
                    remaining = f"{int(seconds // 3600)}h{int((seconds % 3600) // 60):02d}"
                    colour = term.red if seconds < 8 * 3600 else term.yellow
            label = alert["label"] or alert["vuln_id"]
            print(f"    {colour(remaining.rjust(9))}  {term.bold(label):<26} "
                  f"{term.grey(alert['product_name'])}  {term.grey(alert['slug'])}")
        print()
        print(term.grey("    Acquitter : ") +
              term.cyan(f"cra watchtower ack <slug> <CVE> --by <nom>"))
        print()

    if not products:
        print(term.grey("  Aucun produit. ") +
              term.cyan("cra watchtower add \"<nom>\" --source <chemin|url>"))
        print()
        return EXIT_OK

    print(f"  {term.bold('Produits')}")
    print()
    for product in products:
        last = store.last_sweep(product.id)
        kev = len(store.open_findings(product.id, kev_only=True))
        total = len(store.open_findings(product.id))
        when = parse(last["started_at"]) if last else None
        if when is None:
            freshness = term.yellow("jamais balayé")
        else:
            hours = (now - when).total_seconds() / 3600
            label = "à l'instant" if hours < 1 else (
                f"il y a {int(hours)} h" if hours < 48 else f"il y a {int(hours/24)} j")
            freshness = term.yellow(label) if hours > 30 else term.grey(label)
        state = last["status"] if last else "—"
        flag = term.red(f"{kev} exploitée(s)") if kev else term.green("aucune exploitée")
        print(f"    {term.bold(product.slug):<26} {flag:<28} "
              f"{term.grey(str(total) + ' findings'):<20} {freshness}")
        if state not in ("ok", "—"):
            print(f"      {term.yellow('dernier balayage : ' + state)}"
                  + (f" — {term.grey(last['error'][:70])}" if last and last["error"] else ""))
    print()
    return EXIT_OK


def cmd_ack(args) -> int:
    try:
        config = _config(args)
    except (FileNotFoundError, ValueError) as exc:
        print(term.red(f"  {exc}"), file=sys.stderr)
        return EXIT_ERROR

    store = Store(config.database)
    product = store.product(args.slug)
    if product is None:
        print(term.red(f"  produit inconnu : {args.slug}"), file=sys.stderr)
        return EXIT_ERROR

    resolved = store.resolve_vuln_id(product.id, args.vuln_id) or args.vuln_id
    matches = [a for a in store.alerts_for(product.id)
               if a["vuln_id"].upper() == resolved.upper()
               and a["acknowledged_at"] is None]
    if not matches:
        print(term.yellow(f"  aucune alerte ouverte pour {args.vuln_id} sur "
                          f"{args.slug}"), file=sys.stderr)
        return EXIT_ERROR

    for alert in matches:
        store.acknowledge(alert["id"], args.by, args.note)

    print(term.header("Alerte acquittée"))
    print(term.kv("Produit", product.name))
    print(term.kv("Vulnérabilité", term.bold(args.vuln_id)))
    print(term.kv("Par", args.by))
    print(term.kv("Prise de connaissance", term.grey(matches[0]["awareness_at"])))
    print(term.kv("Acquittée le", term.grey(matches[0] and utcnow().isoformat()
                                            .replace("+00:00", "Z"))))
    if args.note:
        print(term.kv("Note", args.note))
    print()
    print(term.grey("  Les relances s'arrêtent. L'horodatage initial reste "
                    "l'élément de preuve."))
    print()
    return EXIT_OK


def cmd_dashboard(args) -> int:
    try:
        config = _config(args)
    except (FileNotFoundError, ValueError) as exc:
        print(term.red(f"  {exc}"), file=sys.stderr)
        return EXIT_ERROR

    store = Store(config.database)
    page = render(store, operator=args.operator)

    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(page, encoding="utf-8")
        print(term.header("Tableau de bord écrit"))
        print(term.kv("Fichier", term.cyan(str(path))))
        print()
        return EXIT_OK

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    operator = args.operator

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(term.grey(f"  · {self.address_string()} {fmt % a}"))

        def do_GET(self):
            if self.path not in ("/", "/index.html"):
                self.send_error(404)
                return
            body = render(Store(config.database), operator=operator).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    print(term.header("Tableau de bord Watchtower"))
    print(term.kv("URL", term.cyan(f"http://{args.host}:{args.port}/")))
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print()
        print(term.yellow("  Cette page expose la posture de vulnérabilité de vos "
                          "clients\n  et n'a aucune authentification. Placez-la "
                          "derrière un reverse\n  proxy authentifié avant de "
                          "l'exposer."))
    print()
    print(term.grey("  Ctrl-C pour arrêter."))
    print()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n" + term.grey("  arrêté"))
    finally:
        server.server_close()
    return EXIT_OK


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "watchtower", help="surveillance continue d'un portefeuille de produits")
    parser.add_argument("--config", default="",
                        help=f"fichier de configuration (défaut : {DEFAULT_DIR}/config.json)")
    sub = parser.add_subparsers(dest="wt_command", required=True)

    p = sub.add_parser("init", help="créer la configuration")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="ajouter un produit au portefeuille")
    p.add_argument("name", help="nom du produit tel qu'il apparaîtra dans les alertes")
    p.add_argument("--source", required=True, help="chemin local ou URL git")
    p.add_argument("--slug", default="", help="identifiant court (déduit du nom sinon)")
    p.add_argument("--branch", default="", help="branche git à suivre")
    p.add_argument("--supplier", default="", help="raison sociale du fabricant")
    p.add_argument("--contact", default="", help="contact sécurité du client")
    p.add_argument("--member-state", default="", help="État membre d'établissement principal")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("run", help="exécuter un balayage (à mettre en cron/timer)")
    p.add_argument("--only", default="", help="ne balayer qu'un seul produit")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("status", help="état du portefeuille et horloges en cours")
    p.add_argument("--all", action="store_true", help="inclure les produits désactivés")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("ack", help="acquitter une alerte et arrêter les relances")
    p.add_argument("slug")
    p.add_argument("vuln_id")
    p.add_argument("--by", required=True, help="qui acquitte")
    p.add_argument("--note", default="", help="décision prise")
    p.set_defaults(func=cmd_ack)

    p = sub.add_parser("dashboard", help="tableau de bord portefeuille")
    p.add_argument("-o", "--output", default="", help="écrire dans un fichier au lieu de servir")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8788)
    p.add_argument("--operator", default="", help="nom affiché en en-tête")
    p.set_defaults(func=cmd_dashboard)
