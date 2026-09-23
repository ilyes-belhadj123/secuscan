"""Envoi d'e-mails : SMTP si configuré, sinon boîte d'envoi locale (fichiers .eml).

La boîte d'envoi locale (data/outbox) sert au développement et aux démonstrations : les e-mails
y sont déposés au lieu d'être envoyés. Elle contient des liens sensibles (réinitialisation de mot
de passe) : elle n'est exposée par aucune route de l'API.
"""
import logging
import re
import smtplib
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import make_msgid

from .config import Settings

log = logging.getLogger(__name__)


@dataclass
class Delivery:
    sent: bool          # True : remis au serveur SMTP ; False : déposé dans la boîte d'envoi locale
    detail: str


def send_email(settings: Settings, to: str, subject: str, text: str) -> Delivery:
    msg = EmailMessage()
    msg["From"] = settings.secuscan_smtp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain="secuscan.local")
    msg.set_content(text)

    if settings.secuscan_smtp_host:
        try:
            with smtplib.SMTP(settings.secuscan_smtp_host, settings.secuscan_smtp_port, timeout=15) as smtp:
                if settings.secuscan_smtp_starttls:
                    smtp.starttls(context=ssl.create_default_context())
                if settings.secuscan_smtp_user:
                    smtp.login(settings.secuscan_smtp_user, settings.secuscan_smtp_password)
                smtp.send_message(msg)
            return Delivery(True, "envoyé")
        except (OSError, smtplib.SMTPException) as exc:
            # Pas de repli silencieux : l'échec est journalisé et signalé à l'appelant
            log.error("Envoi SMTP à %s échoué : %s", to, exc)
            return Delivery(False, f"échec de l'envoi SMTP : {exc.__class__.__name__}")

    outbox = settings.data_dir / "outbox"
    outbox.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    path = outbox / f"{stamp}-{re.sub(r'[^A-Za-z0-9@._-]', '_', to)}.eml"
    path.write_bytes(bytes(msg))
    log.info("SMTP non configuré : e-mail pour %s déposé dans %s", to, path)
    return Delivery(False, "boîte d'envoi locale (SMTP non configuré)")
