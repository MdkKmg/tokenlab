from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

import httpx2
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .checks import run_checks
from .config import HTTP_VERIFY_TLS, get_settings
from .dpop import generate_dpop_jwk, jwk_thumbprint, public_jwk
from .httplog import TOKEN_FIELDS, configure_logging, record_exchange, redact_body, redact_tokens
from .oidc import (
    build_authorization_url,
    build_logout_url,
    call_userinfo,
    decode_jwt_unverified,
    exchange_code_for_tokens,
    fetch_discovery,
    fetch_jwks,
    verify_jwt_signature,
)
from .pkce import generate_pkce_pair
from .recommendations import RECOMMENDATIONS, RECOMMENDATIONS_COUNT, REFERENCES
from .store import StateStore

BASE_DIR = Path(__file__).parent

settings = get_settings()
logger = configure_logging(settings.log_level)
store = StateStore(ttl_seconds=settings.state_ttl_seconds)

if not HTTP_VERIFY_TLS:
    logger.warning(
        json.dumps(
            {
                "event": "tls_verification_disabled",
                "message": (
                    "HTTP_VERIFY_TLS=false : les certificats TLS de Keycloak ne sont pas "
                    "verifies. A ne jamais utiliser hors dev local."
                ),
            }
        )
    )

app = FastAPI(title="tokenlab")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.filters["pretty_json"] = lambda obj: json.dumps(obj, indent=2, ensure_ascii=False, default=str)
if (BASE_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "config": settings.redacted(),
            "recommendations": RECOMMENDATIONS,
            "recommendations_count": RECOMMENDATIONS_COUNT,
            "references": REFERENCES,
        },
    )


def _render_error(request: Request, error: str, error_description: str, status_code: int = 502):
    return templates.TemplateResponse(
        request,
        "error.html",
        {"error": error, "error_description": error_description},
        status_code=status_code,
    )


def _ui_transcript(transcript: list[dict]) -> list[dict]:
    """Transcript a afficher : tokens masques si le bouton de copie est desactive."""
    return transcript if settings.copy_button else redact_tokens(transcript)


def _annotate_dpop_proofs(transcript: list[dict]) -> None:
    """Decode chaque preuve DPoP presente dans les headers de requete du transcript,
    pour affichage pedagogique (header + payload) a cote de chaque echange HTTP."""
    for entry in transcript:
        proof = (entry.get("request_headers") or {}).get("DPoP")
        if not proof:
            continue
        try:
            entry["dpop_proof_decoded"] = decode_jwt_unverified(proof)
        except Exception:  # noqa: S110 - decodage cosmetique best-effort, ne doit pas casser l'affichage
            pass


@app.get("/login")
async def login(request: Request, acr_values: str | None = None, acr_essential: bool = False):
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    transcript: list[dict] = []

    acr_values = (acr_values or "").strip() or None
    entry: dict = {
        "transcript": transcript,
        "nonce": nonce,
        "acr_values": acr_values,
        "acr_essential": acr_essential,
    }

    code_verifier = code_challenge = None
    if settings.enable_pkce:
        code_verifier, code_challenge = generate_pkce_pair()
        entry["code_verifier"] = code_verifier
        entry["code_challenge"] = code_challenge

    dpop_jwk = None
    if settings.enable_dpop:
        dpop_jwk = generate_dpop_jwk()
        entry["dpop_jwk"] = dpop_jwk

    try:
        async with httpx2.AsyncClient(
            timeout=settings.http_timeout_seconds, verify=HTTP_VERIFY_TLS
        ) as client:
            discovery = await fetch_discovery(client, settings, transcript, logger)
    except httpx2.HTTPError as exc:
        logger.error(json.dumps({"event": "discovery_failed", "error": str(exc)}))
        return _render_error(
            request,
            "discovery_oidc_echouee",
            f"Impossible de recuperer {settings.discovery_url} : {exc}",
        )

    auth_url, auth_params = build_authorization_url(
        settings,
        discovery,
        state,
        nonce,
        code_challenge,
        acr_values=acr_values,
        acr_essential=acr_essential,
    )
    record_exchange(
        transcript,
        logger,
        step="2. Redirection du navigateur vers Keycloak (GET /auth)",
        method="GET",
        url=discovery["authorization_endpoint"],
        request_body=auth_params,
        note="Requete initiee par le navigateur (redirection HTTP), pas par ce serveur : "
        "affichee ici pour verifier exactement ce qui est envoye a Keycloak.",
    )

    entry["discovery"] = discovery
    store.set(state, entry)

    return RedirectResponse(auth_url, status_code=302)


@app.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    entry = store.pop(state) if state else None

    if error or entry is None:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error": error or "state_invalide_ou_expire",
                "error_description": error_description
                or (
                    "Le parametre 'state' est manquant, inconnu ou a expire "
                    "(tentative de login trop ancienne ou deja utilisee)."
                ),
            },
            status_code=400,
        )

    transcript: list[dict] = entry["transcript"]
    discovery = entry["discovery"]
    code_verifier = entry.get("code_verifier")
    dpop_jwk = entry.get("dpop_jwk")

    pkce_info = None
    if code_verifier:
        pkce_info = {
            "code_verifier": code_verifier,
            "code_challenge": entry.get("code_challenge"),
            "method": "S256",
        }

    acr_requested = entry.get("acr_values")
    acr_essential = entry.get("acr_essential", False)

    try:
        async with httpx2.AsyncClient(
            timeout=settings.http_timeout_seconds, verify=HTTP_VERIFY_TLS
        ) as client:
            tokens, token_response = await exchange_code_for_tokens(
                client,
                settings,
                discovery,
                code=code,
                code_verifier=code_verifier,
                dpop_jwk=dpop_jwk,
                transcript=transcript,
                logger=logger,
            )

            if tokens is None:
                _annotate_dpop_proofs(transcript)
                return templates.TemplateResponse(
                    request,
                    "result.html",
                    {
                        "config": settings.redacted(),
                        "transcript": _ui_transcript(transcript),
                        "success": False,
                        "token_error_status": token_response.status_code,
                        "pkce_info": pkce_info,
                        "acr_info": {"requested": acr_requested, "essential": acr_essential}
                        if acr_requested
                        else None,
                    },
                    status_code=200,
                )

            userinfo = await call_userinfo(
                client,
                discovery,
                access_token=tokens["access_token"],
                token_type=tokens.get("token_type", "Bearer"),
                dpop_jwk=dpop_jwk,
                transcript=transcript,
                logger=logger,
            )

            try:
                jwks = await fetch_jwks(client, discovery, transcript, logger)
            except httpx2.HTTPError:
                # best-effort : la verification de signature reste informative, ne doit
                # pas transformer un login reussi en page d'erreur.
                jwks = None
    except httpx2.HTTPError as exc:
        logger.error(json.dumps({"event": "token_exchange_failed", "error": str(exc)}))
        return _render_error(
            request,
            "appel_http_echoue",
            f"Une requete HTTP du flow a echoue : {exc}",
        )

    decoded = {}
    for key in ("access_token", "id_token", "refresh_token"):
        if tokens.get(key):
            try:
                decoded[key] = decode_jwt_unverified(tokens[key])
                # refresh_token n'est jamais destine a etre verifie par un tiers (seul
                # Keycloak le valide, au /token) : sa cle de signature n'est pas forcement
                # publiee dans le JWKS, afficher "invalide" ici serait trompeur.
                if key != "refresh_token":
                    decoded[key]["signature"] = verify_jwt_signature(tokens[key], jwks)
            except Exception as exc:  # noqa: BLE001 - token peut etre opaque (non-JWT)
                decoded[key] = {"error": f"Non decodable en JWT ({exc})"}

    _annotate_dpop_proofs(transcript)

    dpop_info = None
    if dpop_jwk:
        thumbprint = jwk_thumbprint(dpop_jwk)
        cnf_jkt = (decoded.get("access_token", {}).get("payload") or {}).get("cnf", {}).get("jkt")
        dpop_info = {
            "public_jwk": public_jwk(dpop_jwk),
            "thumbprint": thumbprint,
            "cnf_jkt": cnf_jkt,
            "match": (cnf_jkt == thumbprint) if cnf_jkt else None,
        }

    acr_info = None
    acr_essential_unmet = False
    if acr_requested:
        id_payload = decoded.get("id_token", {}).get("payload") or {}
        acr_received = id_payload.get("acr")
        acr_match = (acr_received in acr_requested.split()) if acr_received else None
        acr_info = {
            "requested": acr_requested,
            "essential": acr_essential,
            "received": acr_received,
            "match": acr_match,
        }
        # Cote client, une claim "essential" non satisfaite doit etre traitee comme un
        # echec de l'authentification (RFC OIDC), meme si Keycloak a quand meme emis un
        # token : Keycloak ne bloque l'emission que si le realm a un flow de step-up
        # (Level of Authentication) configure pour le niveau demande.
        acr_essential_unmet = acr_essential and acr_match is not True

    checks = None
    if settings.enable_recommandations:
        checks = run_checks(
            settings,
            discovery,
            decoded,
            nonce=entry.get("nonce"),
            dpop_info=dpop_info,
            acr_info=acr_info,
        )

    logout_url = build_logout_url(settings, discovery, tokens.get("id_token"))

    return templates.TemplateResponse(
        request,
        "result.html",
        {
            "config": settings.redacted(),
            "transcript": _ui_transcript(transcript),
            "success": True,
            "acr_essential_unmet": acr_essential_unmet,
            "tokens": tokens if settings.copy_button else redact_body(tokens, TOKEN_FIELDS),
            "decoded": decoded,
            "userinfo": userinfo,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pkce_info": pkce_info,
            "dpop_info": dpop_info,
            "acr_info": acr_info,
            "checks": checks,
            "logout_url": logout_url,
        },
    )
