"""Rain's FastAPI access portal and JSON API."""

import argparse
from ipaddress import ip_address
import json
import os
from pathlib import Path
from typing import Annotated, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request as GatewayRequest, build_opener
from uuid import UUID

from fastapi import APIRouter, FastAPI, Form, HTTPException, Request
from pydantic import BaseModel, StrictBool, StringConstraints, ValidationError
import uvicorn

import rain
from rain import portal

DEFAULT_GATEWAY_URL = "https://gateway-staging-dac4.up.railway.app"
DEFAULT_ENVIRONMENT = "staging"
DEFAULT_CLUSTER = "rain"
DEFAULT_ACCOUNT = "misty-staging"


class MistyClient:
    def __init__(self, gateway_url=DEFAULT_GATEWAY_URL, api_key="", environment=DEFAULT_ENVIRONMENT):
        self.url = gateway_url.rstrip("/")
        self.api_key = api_key
        self.environment = environment
        self.opener = build_opener(rain.NoRedirect())

    def request(self, path, data=None):
        if not self.api_key:
            raise HTTPException(503, "Misty Gateway API key is not configured.")
        request = GatewayRequest(
            self.url + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={
                "X-API-Key": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=15) as response:
                return response.read()
        except HTTPError as exc:
            exc.close()
            status = {400: 400, 401: 403, 403: 403, 404: 404, 409: 409, 422: 400, 429: 429}.get(exc.code, 502)
            raise HTTPException(status, f"Misty Gateway rejected the request (HTTP {exc.code}).") from exc
        except (URLError, OSError) as exc:
            raise HTTPException(503, "Misty Gateway is unavailable.") from exc


def gateway_data(model, payload):
    try:
        return model.model_validate_json(payload)
    except ValidationError as exc:
        raise HTTPException(502, "Invalid response from Misty Gateway.") from exc


def client_ip(request):
    try:
        addr = ip_address(request.client.host if request.client else "127.0.0.1")
        return str(getattr(addr, "ipv4_mapped", None) or addr)
    except ValueError:
        return "127.0.0.1"


class EmailRequest(BaseModel):
    email: Annotated[str, StringConstraints(strip_whitespace=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


class PersonRequest(BaseModel):
    person_id: UUID
    name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)] = ""


class Verification(BaseModel):
    challenge_id: UUID
    code: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[0-9]{6}$")]
    name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)] = ""
    ssh_public_key: Annotated[str, StringConstraints(max_length=8192)] | None = None


class Issuer(BaseModel):
    issuer: str


class Challenge(Issuer):
    ok: Literal[True] = True
    challenge_id: UUID
    message: str | None = None
    expires_in: int = 600


class Confirmation(Issuer):
    person_id: UUID
    email: str | None = None


class Eligibility(Issuer):
    active: StrictBool


class Cluster(BaseModel):
    cluster: str
    account: str


class Status(Cluster):
    ok: bool
    environment: str
    issuer: str | None = None
    error: str | None = None


class Permissions(Cluster, Eligibility):
    ok: Literal[True] = True
    person_id: UUID
    slurm_username: str | None
    ssh_key_configured: bool
    ssh_key_fingerprint: str | None


class Approval(Cluster, Confirmation):
    ok: Literal[True] = True
    status: Literal["approved"] = "approved"
    slurm_username: str
    ssh_key_configured: bool
    ssh_key_fingerprint: str | None


class Error(BaseModel):
    detail: str


def configure_key(username, person_id, key, keys_dir):
    try:
        # Check ownership before writing a key to an existing account or its key file.
        if not rain.local_user_exists(username, person_id):
            if os.geteuid() != 0:
                raise HTTPException(503, "The local account has not been provisioned.")
            rain.add_local_user(username, person_id)
        rain.save_ssh_key(username, key, keys_dir=keys_dir)
        if not rain.install_authorized_key(username, key):
            raise HTTPException(503, "Could not install the SSH public key.")
    except rain.SyncError as exc:
        raise HTTPException(409, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, "Could not save the SSH public key.") from exc


def create_app(misty: MistyClient, *, cluster=DEFAULT_CLUSTER, account=DEFAULT_ACCOUNT, keys_dir=rain.DEFAULT_KEYS_DIR):
    app = FastAPI(title="Rain access portal", docs_url=None, redoc_url=None)
    api = APIRouter(responses={code: {"model": Error} for code in (400, 403, 404, 409, 429, 502, 503)})
    target = {"cluster": cluster, "account": account}

    @app.middleware("http")
    async def no_cache(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health() -> dict[str, Literal["ok"]]:
        return {"status": "ok"}

    @api.get("/api/status", response_model_exclude_none=True)
    def status() -> Status:
        try:
            issuer = gateway_data(Issuer, misty.request("/v1/auth/issuer"))
            return Status(ok=True, issuer=issuer.issuer, environment=misty.environment, **target)
        except HTTPException as exc:
            return Status(ok=False, error=exc.detail, environment=misty.environment, **target)

    @api.post("/api/request-code")
    def request_code(data: EmailRequest, request: Request) -> Challenge:
        return gateway_data(Challenge, misty.request("/v1/auth/email/start", {
            "email": data.email.lower(), "client_ip": client_ip(request),
        }))

    def eligibility(person_id):
        return gateway_data(Eligibility, misty.request(f"/v1/auth/people/{person_id}/status"))

    @api.post("/api/verify-code")
    def verify_code(data: Verification, request: Request) -> Approval:
        key = fingerprint = None
        if data.ssh_public_key is not None:
            valid, error, key, fingerprint = rain.validate_ssh_public_key(data.ssh_public_key)
            if not valid:
                raise HTTPException(400, error)
        person = gateway_data(Confirmation, misty.request("/v1/auth/email/confirm", {
            "challenge_id": str(data.challenge_id), "code": data.code, "client_ip": client_ip(request),
        }))
        if person.issuer != f"misty:{misty.environment}":
            raise HTTPException(403, "Unexpected authentication issuer.")
        if not eligibility(person.person_id).active:
            raise HTTPException(403, "Misty account is not currently active.")
        username = rain.username(person.person_id, name=data.name)
        if key:
            configure_key(username, person.person_id, key, keys_dir)
        return Approval(
            **person.model_dump(), **target, slurm_username=username,
            ssh_key_configured=key is not None, ssh_key_fingerprint=fingerprint,
        )

    @api.post("/api/check-permissions")
    def check_permissions(data: PersonRequest) -> Permissions:
        person = eligibility(data.person_id)
        username = rain.username(data.person_id, name=data.name) if person.active else None
        key = rain.get_ssh_key_info(username, keys_dir=keys_dir) if username else None
        return Permissions(
            **person.model_dump(), **target, person_id=data.person_id, slurm_username=username,
            ssh_key_configured=key is not None, ssh_key_fingerprint=key["fingerprint"] if key else None,
        )

    app.include_router(api)

    @app.get("/", include_in_schema=False)
    @app.get("/index.html", include_in_schema=False)
    def home():
        return portal.email_form()

    @app.post("/request-code", include_in_schema=False)
    def request_form(request: Request, email: Annotated[str, Form()] = ""):
        try:
            challenge = request_code(EmailRequest(email=email), request)
            return portal.code_form(challenge.challenge_id)
        except ValidationError:
            return portal.email_form("Enter a valid email address.", 422)
        except HTTPException as exc:
            return portal.email_form(exc.detail, exc.status_code)

    @app.post("/verify-code", include_in_schema=False)
    def verify_form(
        request: Request,
        challenge_id: Annotated[str, Form()] = "",
        code: Annotated[str, Form()] = "",
        name: Annotated[str, Form()] = "",
        ssh_public_key: Annotated[str, Form()] = "",
    ):
        try:
            challenge = UUID(challenge_id)
        except ValueError:
            return portal.email_form("Request a new verification code.", 422)
        try:
            result = verify_code(Verification(
                challenge_id=challenge, code=code, name=name, ssh_public_key=ssh_public_key,
            ), request)
        except ValidationError:
            return portal.code_form(challenge, "Check the code, name, and public key lengths.", 422)
        except HTTPException as exc:
            return portal.code_form(challenge, exc.detail, exc.status_code)
        return portal.approved(result, request.url.hostname or "rain.local")

    return app


def load_env_file():
    for path in (".env", "sync.env", "/etc/misty-slurm-sync/sync.env"):
        try:
            lines = Path(path).read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            key, sep, value = line.partition("=")
            key = key.strip()
            if sep and key and not key.startswith("#"):
                os.environ.setdefault(key, value.strip().strip("'\""))
        break


def main(args=None):
    load_env_file()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.getenv("RAIN_WEB_HOST", os.getenv("HOST", "0.0.0.0")))
    parser.add_argument("--port", type=int, default=os.getenv("RAIN_WEB_PORT", os.getenv("PORT", "8080")))
    parser.add_argument("--gateway-url", default=os.getenv("MISTY_GATEWAY_URL", DEFAULT_GATEWAY_URL))
    parser.add_argument("--api-key", default=os.getenv("MISTY_GATEWAY_API_KEY", ""))
    parser.add_argument("--environment", default=os.getenv("MISTY_ENVIRONMENT", DEFAULT_ENVIRONMENT))
    parser.add_argument("--cluster", default=os.getenv("SLURM_CLUSTER", DEFAULT_CLUSTER))
    parser.add_argument("--account", default=os.getenv("SLURM_ACCOUNT", DEFAULT_ACCOUNT))
    parser.add_argument("--keys-dir", default=os.getenv("RAIN_KEYS_DIR", rain.DEFAULT_KEYS_DIR))
    options = parser.parse_args(args)
    app = create_app(
        MistyClient(options.gateway_url, options.api_key, options.environment),
        cluster=options.cluster, account=options.account, keys_dir=options.keys_dir,
    )
    uvicorn.run(app, host=options.host, port=options.port)


if __name__ == "__main__":
    main()
