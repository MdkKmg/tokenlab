"""Journalisation des requetes/reponses HTTP du flow OIDC.

Chaque echange est capture dans un "transcript" (liste de dicts) attache a la
tentative de login en cours, pour affichage dans l'UI de resultat, ET emis en
JSON sur stdout via le logger standard (recupere par kube / le pilote de logs
du cluster). Les tokens et secrets du flow restent visibles dans l'UI (outil de
debug) mais sont masques dans les logs, qui sont collectes et conserves.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import httpx2

SENSITIVE_HEADER_NAMES = {"authorization"}
SENSITIVE_BODY_FIELDS = {"client_secret"}
# Masques dans l'UI uniquement quand COPY_BUTTON=false.
TOKEN_FIELDS = {"access_token", "refresh_token", "id_token"}
# Masques uniquement dans les logs : l'UI doit pouvoir les afficher.
LOG_ONLY_SENSITIVE_BODY_FIELDS = {"access_token", "refresh_token", "id_token", "code", "code_verifier"}


def configure_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("tokenlab")
    logger.setLevel(level.upper())
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.propagate = False
    return logger


def redact_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    if not headers:
        return {}
    redacted = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_NAMES:
            scheme = str(value).split(" ", 1)[0] if value else ""
            redacted[key] = f"{scheme} ***redacted***".strip()
        else:
            redacted[key] = value
    return redacted


def redact_body(body: Any, fields: set[str] = SENSITIVE_BODY_FIELDS) -> Any:
    if isinstance(body, dict):
        return {k: ("***redacted***" if k in fields else v) for k, v in body.items()}
    return body


def _redact_for_log(entry: dict[str, Any]) -> dict[str, Any]:
    fields = SENSITIVE_BODY_FIELDS | LOG_ONLY_SENSITIVE_BODY_FIELDS
    return {
        k: (redact_body(v, fields) if k in ("request_body", "response_body") else v) for k, v in entry.items()
    }


def redact_tokens(transcript: list[dict]) -> list[dict]:
    """Copie du transcript avec les tokens masques, pour l'UI quand COPY_BUTTON=false."""
    body_keys = ("request_body", "response_body")
    return [
        {k: (redact_body(v, TOKEN_FIELDS) if k in body_keys else v) for k, v in e.items()} for e in transcript
    ]


def _safe_response_body(response: httpx2.Response) -> Any:
    try:
        return response.json()
    except (json.JSONDecodeError, ValueError):
        return response.text


def record_exchange(
    transcript: list[dict],
    logger: logging.Logger,
    *,
    step: str,
    method: str,
    url: str,
    request_headers: dict | None = None,
    request_body: Any = None,
    response: httpx2.Response | None = None,
    note: str | None = None,
) -> dict:
    """Ajoute une entree au transcript et l'ecrit sur stdout. Retourne l'entree."""
    entry: dict[str, Any] = {
        "step": step,
        "method": method,
        "url": url,
        "request_headers": redact_headers(request_headers),
        "request_body": redact_body(request_body),
        "note": note,
    }
    if response is not None:
        entry["status_code"] = response.status_code
        entry["response_headers"] = dict(response.headers)
        entry["response_body"] = redact_body(_safe_response_body(response))

    transcript.append(entry)
    logger.info(json.dumps({"event": "http_exchange", **_redact_for_log(entry)}, default=str))
    return entry
