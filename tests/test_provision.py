import base64
import json
import os
import stat

import pytest

from plaudio import keys
from plaudio.provision import (
    BINDING_TOKEN_PATTERN,
    HttpResponse,
    Identity,
    ProvisionError,
    Provisioner,
    device_type_for_serial,
    load_identity,
    normalize_access_token,
    parse_access_token,
    save_identity,
)

SERIAL = "8810000000000002"
BINDING_TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"


def token(payload):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJIUzI1NiJ9.{body}.signature"


def test_normalize_access_token():
    assert normalize_access_token("  abc.def.ghi  ") == "abc.def.ghi"
    assert normalize_access_token('"abc.def.ghi"') == "abc.def.ghi"
    assert normalize_access_token("Bearer abc.def.ghi") == "abc.def.ghi"
    assert normalize_access_token(json.dumps({"tokenstr": "abc.def.ghi"})) == "abc.def.ghi"
    assert normalize_access_token(json.dumps({"access_token": "abc.def.ghi"})) == "abc.def.ghi"
    assert normalize_access_token('{"tokenstr": "bearer abc.def.ghi"}') == "abc.def.ghi"


def test_parse_access_token():
    claims = parse_access_token(token({"sub": BINDING_TOKEN, "user_id": "user-7", "client_id": "plaud-web", "exp": 1_700_000_000}))
    assert (claims.sub, claims.user_id, claims.client_id, claims.expires_at_ms) == (
        BINDING_TOKEN, "user-7", "plaud-web", 1_700_000_000_000,
    )
    assert parse_access_token(token({"sub": BINDING_TOKEN})).user_id == BINDING_TOKEN
    with pytest.raises(ProvisionError, match="does not look like"):
        parse_access_token("not-a-jwt")
    with pytest.raises(ProvisionError, match="could not be read"):
        parse_access_token("a.!!!.c")
    with pytest.raises(ProvisionError, match="binding token"):
        parse_access_token(token({"user_id": "user-7"}))
    with pytest.raises(ProvisionError, match="binding token"):
        parse_access_token(token({"sub": "has spaces here"}))
    assert parse_access_token(token({"sub": "short"})).sub == "short"
    assert BINDING_TOKEN_PATTERN.match("x" * 64)


def test_device_type_for_serial():
    assert device_type_for_serial("8800000000000000") == "notepin"
    assert device_type_for_serial("8810000000000002") == "notepro"
    assert device_type_for_serial("8820000000000000") == "notepins"
    assert device_type_for_serial("8830000000000000") == "notepro"
    assert device_type_for_serial("8890000000000000") == "note"
    for bad in ("8810abcdef000002", "8810"):
        with pytest.raises(ProvisionError, match="serial"):
            device_type_for_serial(bad)


class FakeHttp:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def __call__(self, url, headers, body):
        self.requests.append((url, headers, body))
        for fragment, response in self.responses.items():
            if fragment in url:
                return response
        raise AssertionError(f"unexpected request {url}")


def ok(payload):
    return HttpResponse(200, json.dumps(payload).encode())


def test_cloud_provision_calls_gen_key_then_sn_sign():
    cloud = keys.generate_local_keypair()
    http = FakeHttp({"gen-key": ok({"public_key": cloud.public_key, "private_key": cloud.private_key}),
                     "sn-sign": ok({"signature": "SIGNATURE"})})
    access = token({"sub": BINDING_TOKEN})
    identity = Provisioner(http).provision(json.dumps({"tokenstr": access}), SERIAL, identifier="X")
    assert (identity.bindingToken, identity.signature, identity.publicKey, identity.deviceType) == (
        BINDING_TOKEN, "SIGNATURE", cloud.public_key, "notepro",
    )
    assert identity.keySource == "cloud:pkcs1"
    assert [u for u, _, _ in http.requests] == [
        "https://platform-us.plaud.ai/developer/api/open/partner/sdk/gen-key",
        "https://platform-us.plaud.ai/developer/api/open/partner/sdk/sn-sign",
    ]
    assert all(h["Authorization"] == f"Bearer {access}" for _, h, _ in http.requests)
    assert "Content-Type" not in http.requests[0][1] and http.requests[0][2] is None
    assert http.requests[1][1]["Content-Type"] == "application/json"
    assert json.loads(http.requests[1][2]) == {"type": "notepro", "sn": SERIAL}


def test_local_key_only_calls_sn_sign_on_jp_domain():
    http = FakeHttp({"sn-sign": ok({"signature": "SIG"})})
    identity = Provisioner(http).provision(token({"sub": BINDING_TOKEN}), SERIAL, domain="platform-jp.plaud.ai", local_key=True)
    assert [u for u, _, _ in http.requests] == ["https://platform-jp.plaud.ai/developer/api/open/partner/sdk/sn-sign"]
    assert identity.keySource == "local:pkcs1"
    assert keys.describe_public_key(identity.publicKey) == "pkcs1"
    keys.load_private_key(identity.privateKey)


def test_errors_are_actionable_and_do_not_leak():
    http = FakeHttp({"gen-key": HttpResponse(401, b'{"detail": "ACCESS_TOKEN_INVALID"}')})
    with pytest.raises(ProvisionError, match="rejected the sign-in token"):
        Provisioner(http).provision(token({"sub": BINDING_TOKEN}), SERIAL)

    def boom(*_):
        raise OSError("ECONNREFUSED secret-detail")

    with pytest.raises(ProvisionError, match="could not be reached") as info:
        Provisioner(boom).generate_key_pair(token({"sub": BINDING_TOKEN}))
    assert "secret" not in str(info.value)
    http = FakeHttp({"gen-key": ok({"public_key": "PUBLIC"})})
    with pytest.raises(ProvisionError, match="no recorder key material"):
        Provisioner(http).generate_key_pair(token({"sub": BINDING_TOKEN}))
    with pytest.raises(ProvisionError, match="region"):
        Provisioner(http).generate_key_pair("t", domain="platform.plaud.ai")
    http = FakeHttp({"sn-sign": HttpResponse(500, b"oops")})
    with pytest.raises(ProvisionError, match="HTTP 500"):
        Provisioner(http).sign_serial("t", SERIAL)


def test_identity_storage_is_private(tmp_path, monkeypatch):
    monkeypatch.setenv("PLAUDIO_HOME", str(tmp_path / "home"))
    identity = Identity(identifier="", serial=SERIAL, bindingToken=BINDING_TOKEN, signature="s", publicKey="p", privateKey="q")
    path = save_identity(identity)
    assert path == tmp_path / "home" / "identity.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert load_identity() == identity
    os.chmod(path, 0o644)
    with pytest.raises(ProvisionError, match="private"):
        load_identity()
    redacted = json.dumps(identity.redacted())
    assert BINDING_TOKEN not in redacted


def test_public_key_formats_roundtrip():
    for fmt in keys.PUBLIC_KEY_FORMATS:
        assert keys.describe_public_key(keys.generate_local_keypair(fmt).public_key) == fmt
    assert keys.describe_public_key("not a key!") == "unknown"


def test_partner_user_token_flow(tmp_path, monkeypatch):
    import base64 as b64
    from plaudio.provision import HttpResponse, PartnerCredentials, Provisioner, load_partner_credentials

    calls = []

    def transport(url, headers, body):
        calls.append((url, headers, body))
        if url.endswith("/oauth/partner/access-token"):
            assert headers["Authorization"] == "Basic " + b64.b64encode(b"cid:sec").decode()
            assert headers["Content-Type"] == "application/x-www-form-urlencoded"
            return HttpResponse(200, b'{"access_token":"PARTNER"}')
        assert headers["Authorization"] == "Bearer PARTNER"
        assert json.loads(body) == {"user_id": "me", "expires_in": 86400}
        return HttpResponse(200, b'{"data":{"access_token":"USER","expires_in":86400}}')

    assert Provisioner(transport).partner_user_token(PartnerCredentials("cid", "sec", "me")) == "USER"
    assert len(calls) == 2

    for k in ("PLAUD_CLIENT_ID", "PLAUD_CLIENT_SECRET", "PLAUD_USER_ID"):
        monkeypatch.delenv(k, raising=False)
    assert load_partner_credentials(tmp_path / "missing.json") is None
    f = tmp_path / "dev.json"
    f.write_text('{"clientId":"a","clientSecret":"b"}')
    assert load_partner_credentials(f) == PartnerCredentials("a", "b", "plaudio-owner")
