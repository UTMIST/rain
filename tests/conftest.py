import json
from unittest.mock import Mock, patch
from uuid import UUID

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from rain.web import create_app

PERSON_ID = UUID("550e8400-e29b-41d4-a716-446655440000")
CHALLENGE_ID = UUID("550e8400-e29b-41d4-a716-446655440001")
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqq90UoX99a5Y5oWpQk2vXpQYkQ9i3O5mF9y5uW6pT test@example.com"


class GatewayStub:
    environment = "staging"
    active = True
    issuer = "misty:staging"

    def request(self, path, data=None):
        payload = {"issuer": self.issuer}
        if path == "/v1/auth/email/start":
            payload["challenge_id"] = str(CHALLENGE_ID)
        elif path == "/v1/auth/email/confirm":
            if data["challenge_id"] != str(CHALLENGE_ID) or data["code"] != "012345":
                raise HTTPException(403, "Invalid verification code.")
            payload.update(person_id=str(PERSON_ID), email="user@example.org")
        elif path.startswith("/v1/auth/people/"):
            payload["active"] = self.active
        else:
            assert path == "/v1/auth/issuer"
        return json.dumps(payload).encode()


@pytest.fixture
def gateway():
    stub = GatewayStub()
    stub.request = Mock(wraps=stub.request)
    return stub


@pytest.fixture
def app(gateway, tmp_path):
    # Never read or write real keys or provision system accounts in tests.
    with (
        patch("rain.local_user_exists", return_value=True),
        patch("rain.add_local_user", side_effect=AssertionError("unexpected useradd")),
        patch("rain.install_authorized_key", return_value=True),
        patch("rain.get_ssh_key_info", return_value=None),
    ):
        yield create_app(gateway, keys_dir=tmp_path)


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client
