"""Alert delivery.

Two channels, both stdlib: SMTP and a generic JSON webhook that Slack, Teams
and Discord all accept. Delivery failure is recorded, never swallowed — an
alert the operator never received is indistinguishable from no alert at all,
and that is the failure this whole service exists to prevent.
"""
from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

USER_AGENT = "CRA-Sentinel-Watchtower/1.0"


@dataclass
class Alert:
    """What the operator needs in order to act, and nothing else."""
    product_name: str
    product_slug: str
    supplier: str
    kind: str
    vuln_id: str
    cve: str
    severity: str
    cvss: float | None
    component: str
    summary: str
    fixed_in: str
    ransomware: bool
    awareness_at: str
    early_warning_due: str
    notification_due: str
    dashboard_url: str = ""
    escalation_hours: int = 0     # >0 marks a reminder, not a first notice

    @property
    def is_regulatory(self) -> bool:
        return self.kind == "exploited"

    @property
    def subject(self) -> str:
        if self.escalation_hours:
            remaining = 24 - self.escalation_hours
            window = (f"reste {remaining} h" if remaining > 0 else "ÉCHÉANCE DÉPASSÉE")
            return (f"[RELANCE · {window}] {self.cve} non acquittée — "
                    f"{self.product_name}")
        if self.kind == "exploited":
            return (f"[ARTICLE 14 · 24h] {self.cve} activement exploitée — "
                    f"{self.product_name}")
        if self.kind == "new_critical":
            return f"[Critique] {self.cve} — {self.product_name}"
        if self.kind == "unverified":
            return f"[Non vérifié] Scan sans source d'avis — {self.product_name}"
        return f"[Erreur] Échec du scan — {self.product_name}"

    def as_text(self) -> str:
        if self.kind == "exploited":
            return self._regulatory_body()
        if self.kind == "new_critical":
            return (
                f"Nouvelle vulnérabilité critique — {self.product_name}\n"
                f"{'=' * 62}\n\n"
                f"  {self.cve}   {self.severity}   CVSS {self.cvss or '—'}\n"
                f"  Composant : {self.component}\n"
                f"  {self.summary}\n\n"
                f"  Correctif disponible : {self.fixed_in or 'aucun publié'}\n\n"
                f"Pas activement exploitée à ce jour : aucun délai Article 14 ne court.\n"
                f"À traiter dans le cycle normal de remédiation.\n"
                f"{self._footer()}")
        if self.kind == "unverified":
            return (
                f"Scan non vérifié — {self.product_name}\n"
                f"{'=' * 62}\n\n"
                f"Aucune source d'avis de sécurité n'a pu être consultée lors du\n"
                f"dernier balayage. Le résultat ne dit RIEN sur l'exposition réelle\n"
                f"du produit : zéro vulnérabilité signifie ici « pas contrôlé ».\n\n"
                f"La surveillance est donc interrompue pour ce produit jusqu'à\n"
                f"résolution. Vérifier la connectivité réseau de la sonde.\n"
                f"{self._footer()}")
        return (
            f"Échec du scan — {self.product_name}\n"
            f"{'=' * 62}\n\n{self.summary}\n\n"
            f"La surveillance de ce produit est interrompue jusqu'à résolution.\n"
            f"{self._footer()}")

    def _regulatory_body(self) -> str:
        ransom = ("\n  ⚠ Associée à des campagnes de rançongiciel connues.\n"
                  if self.ransomware else "")
        return (
            f"VULNÉRABILITÉ ACTIVEMENT EXPLOITÉE\n"
            f"{'=' * 62}\n\n"
            f"Produit      : {self.product_name}\n"
            f"Fabricant    : {self.supplier or '—'}\n\n"
            f"  {self.cve}   {self.severity}   CVSS {self.cvss or '—'}\n"
            f"  Composant : {self.component}\n"
            f"  {self.summary}\n"
            f"{ransom}\n"
            f"  Correctif disponible : {self.fixed_in or 'aucun publié'}\n\n"
            f"{'-' * 62}\n"
            f"HORLOGE ARTICLE 14 — Règlement (UE) 2024/2847\n"
            f"{'-' * 62}\n\n"
            f"  Prise de connaissance   {self.awareness_at}\n"
            f"  Alerte précoce (24 h)   {self.early_warning_due}\n"
            f"  Notification (72 h)     {self.notification_due}\n"
            f"  Rapport final           14 j après mesure corrective\n\n"
            f"Ces échéances courent depuis l'horodatage de prise de connaissance\n"
            f"ci-dessus, qui est le fait de référence en cas de contrôle.\n\n"
            f"À FAIRE MAINTENANT\n"
            f"  1. Confirmer que le produit est bien affecté (le composant peut\n"
            f"     être présent sans que le code vulnérable soit atteignable).\n"
            f"  2. Si non affecté : consigner la décision et sa justification.\n"
            f"       cra triage {self.cve} --status not_affected \\\n"
            f"           --justification vulnerable_code_not_in_execute_path \\\n"
            f"           -r \"...\"\n"
            f"  3. Si affecté : préparer l'alerte précoce.\n"
            f"       cra notify {self.cve} --stage early_warning\n"
            f"  4. Accuser réception pour arrêter les relances.\n"
            f"       cra watchtower ack {self.product_slug} {self.cve} --by <nom>\n"
            f"{self._footer()}")

    def _footer(self) -> str:
        link = f"\nTableau de bord : {self.dashboard_url}\n" if self.dashboard_url else ""
        return (f"\n{'-' * 62}\n{link}"
                f"CRA Sentinel Watchtower · surveillance continue\n"
                f"Cet avis est un élément de preuve, pas un conseil juridique.\n")

    def as_webhook(self) -> dict:
        colour = {"exploited": "#b3261e", "new_critical": "#c2620a",
                  "unverified": "#8a6d00", "scan_error": "#5d6b73"}.get(self.kind, "#5d6b73")
        headline = ("🔴 *ARTICLE 14 — 24 h*" if self.kind == "exploited"
                    else f"*{self.kind.replace('_', ' ').title()}*")
        lines = [
            f"{headline}  ·  *{self.product_name}*",
            f"`{self.cve}`  {self.severity}  CVSS {self.cvss or '—'}",
            f"Composant : `{self.component}`",
        ]
        if self.is_regulatory:
            lines += [
                f"Prise de connaissance : `{self.awareness_at}`",
                f"*Alerte précoce due : {self.early_warning_due}*",
                f"Correctif : {self.fixed_in or 'aucun publié'}",
            ]
        if self.dashboard_url:
            lines.append(f"<{self.dashboard_url}|Ouvrir le tableau de bord>")
        text = "\n".join(lines)
        # Slack reads `text`/`attachments`; Teams and Discord tolerate both.
        return {"text": text,
                "attachments": [{"color": colour, "text": text, "fallback": self.subject}]}


@dataclass
class Channels:
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    mail_from: str = ""
    mail_to: list[str] = field(default_factory=list)
    webhook_url: str = ""
    dashboard_url: str = ""
    timeout: int = 20

    @property
    def configured(self) -> list[str]:
        names = []
        if self.smtp_host and self.mail_to:
            names.append("email")
        if self.webhook_url:
            names.append("webhook")
        return names

    def send(self, alert: Alert) -> tuple[list[str], str]:
        """Returns (channels that succeeded, combined error text)."""
        alert.dashboard_url = alert.dashboard_url or self.dashboard_url
        delivered, errors = [], []

        if self.smtp_host and self.mail_to:
            try:
                self._email(alert)
                delivered.append("email")
            except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
                errors.append(f"email: {exc}")

        if self.webhook_url:
            try:
                self._webhook(alert)
                delivered.append("webhook")
            except (urllib.error.URLError, OSError, ValueError) as exc:
                errors.append(f"webhook: {exc}")

        if not self.configured:
            errors.append("no delivery channel configured")

        return delivered, "; ".join(errors)

    def _email(self, alert: Alert) -> None:
        message = EmailMessage()
        message["Subject"] = alert.subject
        message["From"] = self.mail_from or self.smtp_user
        message["To"] = ", ".join(self.mail_to)
        message["Date"] = formatdate(localtime=True)
        message["Message-ID"] = make_msgid(domain="cra-sentinel.local")
        if alert.is_regulatory:
            message["X-Priority"] = "1"
            message["Importance"] = "high"
        message.set_content(alert.as_text())

        context = ssl.create_default_context()
        if self.smtp_port == 465:
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port,
                                  timeout=self.timeout, context=context) as server:
                self._authenticate(server)
                server.send_message(message)
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as server:
                server.ehlo()
                if self.smtp_starttls:
                    server.starttls(context=context)
                    server.ehlo()
                self._authenticate(server)
                server.send_message(message)

    def _authenticate(self, server) -> None:
        if self.smtp_user and self.smtp_password:
            server.login(self.smtp_user, self.smtp_password)

    def _webhook(self, alert: Alert) -> None:
        payload = json.dumps(alert.as_webhook()).encode()
        request = urllib.request.Request(
            self.webhook_url, data=payload, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if response.status >= 300:
                raise ValueError(f"webhook returned HTTP {response.status}")
