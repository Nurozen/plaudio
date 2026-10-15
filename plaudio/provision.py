"""Device authorization: binding token + cloud serial signature + RSA identity.

Ported from plaud-provision.ts. A recorder accepts an encrypted session only from a
client presenting:
  1. a signature over the recorder serial (`sn-sign`, cloud only; verified required:
     a bogus 0xFE10 makes the device disconnect),
  2. an RSA-2048 key pair (`gen-key` from the cloud, or `--local-key`, see below),
  3. the account's binding token (the `sub` claim of the partner-minted user token).

Both partner endpoints are POSTed with `Authorization: Bearer <token>` to
`https://{domain}/developer/api/open/partner/sdk/...`, domain platform-us (default) or
platform-jp. sn-sign body: {"type": <device type>, "sn": <serial>}. gen-key has no body.

--local-key path (UNVERIFIED): the sn-sign request does not include a public key, so the
signature should not bind to one, and a locally generated key pair may be accepted. The
public key string format the device expects is unknown (see keys.py).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from . import keys

PLAUD_DOMAINS = ("platform-us.plaud.ai", "platform-jp.plaud.ai")
DEFAULT_DOMAIN = PLAUD_DOMAINS[0]
GEN_KEY_PATH = "/developer/api/open/partner/sdk/gen-key"
SN_SIGN_PATH = "/developer/api/open/partner/sdk/sn-sign"
PARTNER_TOKEN_PATH = "/developer/api/oauth/partner/access-token"
PARTNER_USER_TOKEN_PATH = "/developer/api/open/partner/users/access-token"

BINDING_TOKEN_PATTERN = re.compile(r"^[\x21-\x7e]{1,64}$")
SERIAL_PATTERN = re.compile(r"^[0-9A-F]{16}$")
_DEVICE_TYPES = {"880": "notepin", "881": "notepro", "882": "notepins", "883": "notepro"}


class ProvisionError(ValueError):
    pass


# --------------------------------------------------------------------------- token


def normalize_access_token(raw: str) -> str:
    """Accept a raw JWT, a quoted string, a JSON storage blob or a `Bearer ...` header."""
    token = (raw or "").strip()
    if token.startswith("{"):
        try:
            parsed = json.loads(token)
            token = str(parsed.get("tokenstr") or parsed.get("access_token") or parsed.get("token") or "").strip()
        except (ValueError, AttributeError):
            pass
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        token = token[1:-1].strip()
    token = re.sub(r"^bearer\s+", "", token, flags=re.IGNORECASE).strip()
    return token


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    user_id: str
    client_id: str
    expires_at_ms: int


def parse_access_token(raw: str) -> TokenClaims:
    """Decode (never verify) the JWT payload."""
    parts = normalize_access_token(raw).split(".")
    if len(parts) != 3 or not all(parts):
        raise ProvisionError("That does not look like a Plaud sign-in token.")
    try:
        body = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise ProvisionError("The Plaud sign-in token could not be read.") from None
    sub = payload.get("sub") if isinstance(payload.get("sub"), str) else ""
    if not BINDING_TOKEN_PATTERN.match(sub):
        raise ProvisionError("The Plaud sign-in token is missing a usable device binding token.")
    try:
        exp = float(payload.get("exp") or 0)
    except (TypeError, ValueError):
        exp = 0
    user_id = payload.get("user_id")
    return TokenClaims(
        sub=sub,
        user_id=user_id if isinstance(user_id, str) and user_id else sub,
        client_id=payload.get("client_id") if isinstance(payload.get("client_id"), str) else "",
        expires_at_ms=int(exp * 1000) if exp > 0 else 0,
    )


def device_type_for_serial(serial: str) -> str:
    if not SERIAL_PATTERN.match(serial or ""):
        raise ProvisionError("A 16-character uppercase hex Plaud serial number is required.")
    return _DEVICE_TYPES.get(serial[:3], "note")


# --------------------------------------------------------------------------- HTTP


@dataclass
class HttpResponse:
    status: int
    body: bytes


# (url, headers, body or None) -> HttpResponse. Injectable for tests.
Transport = Callable[[str, dict[str, str], bytes | None], HttpResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # reference uses redirect: 'error'
        return None


def urllib_transport(url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
    # data=None keeps urllib from adding a form Content-Type; http.client still sends
    # Content-Length: 0 for a bodyless POST, matching fetch() in the reference.
    # Cloudflare in front of platform-*.plaud.ai rejects urllib's default User-Agent (error 1010).
    headers = {"User-Agent": "plaudio/0.1", "Accept": "application/json", **headers}
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=20) as response:
            return HttpResponse(response.status, response.read())
    except urllib.error.HTTPError as error:
        return HttpResponse(error.code, error.read() or b"")


_ERROR_COPY = {
    "ACCESS_TOKEN_INVALID": "Plaud rejected the sign-in token. Sign in again and paste a fresh token.",
    "CLIENT_USER_NOT_FOUND": "This Plaud account is not enabled for device authorization in that region.",
    "TOKEN_EXPIRED": "The Plaud sign-in token has expired. Sign in again and paste a fresh token.",
}


class Provisioner:
    def __init__(self, transport: Transport = urllib_transport) -> None:
        self.transport = transport

    def _post(self, path: str, token: str, domain: str, body: dict | None = None, auth: str = "Bearer") -> dict:
        if domain not in PLAUD_DOMAINS:
            raise ProvisionError("Unsupported Plaud region.")
        headers = {"Authorization": f"{auth} {token}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        elif auth == "Basic":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = b""
        try:
            response = self.transport(f"https://{domain}{path}", headers, data)
        except Exception:
            # Do not echo network errors: they may contain request details.
            raise ProvisionError("Plaud could not be reached to authorize this recorder.") from None
        if not 200 <= response.status < 300:
            detail = ""
            try:
                value = json.loads(response.body).get("detail")
                detail = value if isinstance(value, str) else ""
            except (ValueError, AttributeError):
                pass
            raise ProvisionError(_ERROR_COPY.get(detail, f"Plaud authorization failed (HTTP {response.status})."))
        try:
            payload = json.loads(response.body)
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            raise ProvisionError("Plaud returned an unreadable authorization response.")
        return payload

    def partner_user_token(self, creds: "PartnerCredentials", domain: str = DEFAULT_DOMAIN) -> str:
        """Mint an SDK user access token from Embedded SDK app credentials (portal.plaud.ai).

        The web.plaud.ai workspaceToken is rejected by sn-sign (ACCESS_TOKEN_INVALID); only
        partner-minted user tokens are accepted.
        """
        basic = base64.b64encode(f"{creds.client_id}:{creds.client_secret}".encode()).decode()
        partner = self._post(PARTNER_TOKEN_PATH, basic, domain, auth="Basic")
        partner = partner.get("data") if isinstance(partner.get("data"), dict) else partner
        if not isinstance(partner.get("access_token"), str) or not partner["access_token"]:
            raise ProvisionError("Plaud returned no partner access token.")
        user = self._post(PARTNER_USER_TOKEN_PATH, partner["access_token"], domain,
                          {"user_id": creds.user_id, "expires_in": 86400})
        user = user.get("data") if isinstance(user.get("data"), dict) else user
        if not isinstance(user.get("access_token"), str) or not user["access_token"]:
            raise ProvisionError("Plaud returned no SDK user token.")
        return user["access_token"]

    def generate_key_pair(self, token: str, domain: str = DEFAULT_DOMAIN) -> tuple[str, str]:
        result = self._post(GEN_KEY_PATH, token, domain)
        public, private = result.get("public_key"), result.get("private_key")
        if not isinstance(public, str) or not public or not isinstance(private, str) or not private:
            raise ProvisionError("Plaud returned no recorder key material.")
        return public, private

    def sign_serial(self, token: str, serial: str, domain: str = DEFAULT_DOMAIN, device_type: str | None = None) -> str:
        device_type = device_type or device_type_for_serial(serial)
        result = self._post(SN_SIGN_PATH, token, domain, {"type": device_type, "sn": serial})
        signature = result.get("signature")
        if not isinstance(signature, str) or not signature:
            raise ProvisionError("Plaud returned no recorder signature.")
        return signature

    def provision(
        self,
        token: str,
        serial: str,
        identifier: str = "",
        domain: str = DEFAULT_DOMAIN,
        protocol_version: int = 20,
        local_key: bool = False,
        public_key_format: keys.PublicKeyFormat = "pkcs1",
    ) -> "Identity":
        token = normalize_access_token(token)
        claims = parse_access_token(token)
        device_type = device_type_for_serial(serial)
        if local_key:
            pair = keys.generate_local_keypair(public_key_format)
            public, private, source = pair.public_key, pair.private_key, f"local:{public_key_format}"
        else:
            public, private = self.generate_key_pair(token, domain)
            keys.load_private_key(private)  # fail early if the cloud key is unusable
            source = f"cloud:{keys.describe_public_key(public)}"
        signature = self.sign_serial(token, serial, domain, device_type)
        return Identity(
            identifier=identifier,
            serial=serial,
            bindingToken=claims.sub,
            signature=signature,
            publicKey=public,
            privateKey=private,
            protocolVersion=protocol_version,
            deviceType=device_type,
            keySource=source,
            domain=domain,
        )


@dataclass(frozen=True)
class PartnerCredentials:
    client_id: str
    client_secret: str
    user_id: str


def load_partner_credentials(path: Path | None = None) -> PartnerCredentials | None:
    """Env PLAUD_CLIENT_ID / PLAUD_CLIENT_SECRET / PLAUD_USER_ID, else ~/.plaudio/developer.json."""
    path = path or Path.home() / ".plaudio" / "developer.json"
    saved: dict = {}
    if path.exists():
        try:
            saved = json.loads(path.read_text())
        except ValueError:
            raise ProvisionError(f"{path} is not valid JSON.") from None
    client_id = os.environ.get("PLAUD_CLIENT_ID") or saved.get("clientId", "")
    secret = os.environ.get("PLAUD_CLIENT_SECRET") or saved.get("clientSecret", "")
    user_id = os.environ.get("PLAUD_USER_ID") or saved.get("userId", "") or "plaudio-owner"
    if not client_id or not secret:
        return None
    return PartnerCredentials(client_id, secret, user_id)


# --------------------------------------------------------------------------- identity storage


@dataclass
class Identity:
    identifier: str  # CoreBluetooth UUID on macOS; may be "" (then found by advertised serial)
    serial: str
    bindingToken: str
    signature: str  # base64, as returned by sn-sign
    publicKey: str  # sent verbatim as UTF-8 in 0xFE12
    privateKey: str  # base64 DER RSA private key
    protocolVersion: int = 20
    deviceType: str = field(default="")
    keySource: str = field(default="")
    domain: str = field(default=DEFAULT_DOMAIN)

    def redacted(self) -> dict:
        def mask(value: str) -> str:
            return f"<{len(value)} chars>" if value else "<empty>"

        return {
            "identifier": self.identifier or "<scan by serial>",
            "serial": self.serial,
            "bindingToken": mask(self.bindingToken),
            "signature": mask(self.signature),
            "publicKey": mask(self.publicKey),
            "privateKey": mask(self.privateKey),
            "protocolVersion": self.protocolVersion,
            "deviceType": self.deviceType,
            "keySource": self.keySource,
            "domain": self.domain,
        }

    def validate(self) -> None:
        if not SERIAL_PATTERN.match(self.serial or ""):
            raise ProvisionError("Invalid saved serial")
        if not BINDING_TOKEN_PATTERN.match(self.bindingToken or ""):
            raise ProvisionError("Invalid saved binding token")
        for name in ("signature", "publicKey", "privateKey"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ProvisionError(f"Saved identity is missing {name}")


def plaudio_home() -> Path:
    return Path(os.environ.get("PLAUDIO_HOME") or Path.home() / ".plaudio")


def identity_path() -> Path:
    return plaudio_home() / "identity.json"


def save_identity(identity: Identity, path: Path | None = None) -> Path:
    path = Path(path or identity_path())
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(asdict(identity), handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def load_identity(path: Path | None = None) -> Identity:
    path = Path(path or identity_path())
    try:
        info = path.stat()
    except FileNotFoundError:
        raise ProvisionError(f"No identity at {path}; run `plaudio provision` first") from None
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ProvisionError("Identity file must be a regular file private to this user (chmod 600)")
    try:
        raw = json.loads(path.read_text())
        known = {k: v for k, v in raw.items() if k in Identity.__dataclass_fields__}
        identity = Identity(**known)
    except (ValueError, TypeError):
        raise ProvisionError("Saved Plaud identity could not be read") from None
    identity.validate()
    return identity
