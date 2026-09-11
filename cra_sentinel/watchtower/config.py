"""Watchtower configuration.

Secrets never live in the config file. The file carries structure; the
environment carries credentials. That split is what lets the config be
committed to the operator's own repository without leaking an SMTP password.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .notify import Channels

DEFAULT_DIR = Path(os.environ.get("CRA_WATCHTOWER_HOME",
                                  Path.home() / ".cra-watchtower"))

TEMPLATE = {
    "workdir": "~/.cra-watchtower/work",
    "database": "~/.cra-watchtower/watchtower.db",
    "dashboard_url": "",
    "alert_on_new_critical": False,
    "escalate_after_hours": 8,
    "notify": {
        "mail_to": ["vous@exemple.fr"],
        "mail_from": "watchtower@exemple.fr",
        "smtp_host": "smtp.exemple.fr",
        "smtp_port": 587,
        "smtp_starttls": True,
        "smtp_user": "",
        "webhook_url": "",
        "_secrets": "SMTP password comes from CRA_SMTP_PASSWORD, never from this file",
    },
}


@dataclass
class Config:
    path: Path
    workdir: Path
    database: Path
    channels: Channels
    alert_on_new_critical: bool = False
    escalate_after_hours: int = 8
    raw: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        path = Path(path) if path else DEFAULT_DIR / "config.json"
        if not path.exists():
            raise FileNotFoundError(
                f"no configuration at {path} — run `cra watchtower init` first")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ValueError(f"{path} is not valid JSON: {exc}") from exc

        notify = data.get("notify") or {}
        channels = Channels(
            smtp_host=notify.get("smtp_host", ""),
            smtp_port=int(notify.get("smtp_port", 587)),
            smtp_user=notify.get("smtp_user", ""),
            # Credentials come from the environment, always.
            smtp_password=os.environ.get("CRA_SMTP_PASSWORD", ""),
            smtp_starttls=bool(notify.get("smtp_starttls", True)),
            mail_from=notify.get("mail_from", ""),
            mail_to=[a for a in (notify.get("mail_to") or []) if a],
            webhook_url=os.environ.get("CRA_WEBHOOK_URL", notify.get("webhook_url", "")),
            dashboard_url=data.get("dashboard_url", ""),
        )
        return cls(
            path=path,
            workdir=Path(data.get("workdir", DEFAULT_DIR / "work")).expanduser(),
            database=Path(data.get("database", DEFAULT_DIR / "watchtower.db")).expanduser(),
            channels=channels,
            alert_on_new_critical=bool(data.get("alert_on_new_critical", False)),
            escalate_after_hours=int(data.get("escalate_after_hours", 8)),
            raw=data,
        )

    @staticmethod
    def scaffold(path: Path | None = None) -> Path:
        path = Path(path) if path else DEFAULT_DIR / "config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(TEMPLATE, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path

    def warnings(self) -> list[str]:
        out = []
        if not self.channels.configured:
            out.append("no delivery channel configured — alerts will be recorded but "
                       "not sent. Set notify.smtp_host + notify.mail_to, or "
                       "notify.webhook_url.")
        if self.channels.smtp_host and not self.channels.smtp_password \
                and self.channels.smtp_user:
            out.append("smtp_user is set but CRA_SMTP_PASSWORD is empty in the "
                       "environment — authentication will fail.")
        if "exemple.fr" in json.dumps(self.raw):
            out.append(f"{self.path} still contains template placeholders.")
        return out
