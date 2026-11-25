from unittest.mock import MagicMock, patch

import pytest

import rain
from rain.web import MistyClient

from conftest import CHALLENGE_ID, PERSON_ID, PUBLIC_KEY

VERIFY = {"challenge_id": str(CHALLENGE_ID), "code": "012345"}


def test_gateway_client():
    client = MistyClient("https://gateway.example.org/", "test-key")
    client.opener = MagicMock()
    response = client.opener.open.return_value.__enter__.return_value
    response.read.return_value = b'{"issuer":"misty:staging"}'

    assert client.request("/v1/auth/issuer") == response.read.return_value
    request = client.opener.open.call_args.args[0]
    assert request.full_url == "https://gateway.example.org/v1/auth/issuer"
    assert request.get_header("X-api-key") == "test-key"


def test_browser_flow(client, gateway, slurm_commands, tmp_path):
    page = client.get("/")
    assert page.status_code == 200
    assert "missing.css@" in page.text
    assert "<script" not in page.text and "<style" not in page.text
    assert page.headers["cache-control"] == "no-store"

    step = client.post("/request-code", data={"email": " User@Example.org "})
    assert step.status_code == 200
    assert f'value="{CHALLENGE_ID}"' in step.text
    assert 'name="ssh_public_key"' in step.text
    gateway.request.assert_called_once_with("/v1/auth/email/start", {
        "email": "user@example.org", "client_ip": "127.0.0.1",
    })

    retry = client.post("/verify-code", data={**VERIFY, "code": "bad", "ssh_public_key": PUBLIC_KEY})
    assert retry.status_code == 422
    assert f'value="{CHALLENGE_ID}"' in retry.text

    done = client.post("/verify-code", data={**VERIFY, "ssh_public_key": PUBLIC_KEY})
    assert done.status_code == 200
    assert "SSH key registered" in done.text
    username = rain.username(PERSON_ID)
    assert f"ssh {username}@testserver" in done.text
    assert "sbatch --account=misty-staging job.sh" in done.text
    slurm_commands.assert_called_with(
        rain.SACCTMGR, "-i", "add", "user", username, "Cluster=rain", "Account=misty-staging",
    )
    assert (tmp_path / "keys" / f"{username}.pub").read_text() == PUBLIC_KEY + "\n"


def test_api_status_and_read_only_permissions(client, gateway):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/api/status").json() == {
        "ok": True, "environment": "staging", "issuer": "misty:staging",
        "cluster": "rain", "account": "misty-staging",
    }
    params = {"person_id": str(PERSON_ID)}
    assert client.post("/api/check-permissions", json=params).json()["active"] is True
    gateway.active = False
    denied = client.post("/api/check-permissions", json=params).json()
    assert denied["active"] is False and denied["slurm_username"] is None


def test_api_verifies_without_registering_a_key(client, slurm_commands):
    payload = client.post("/api/verify-code", json={**VERIFY, "name": "Ada Lovelace"}).json()
    assert payload["person_id"] == str(PERSON_ID)
    assert payload["slurm_username"] == "msty-alovelace"
    assert payload["slurm_associated"] is False
    assert payload["ssh_key_configured"] is False
    slurm_commands.assert_not_called()


@pytest.mark.parametrize("case", ["invalid_code", "wrong_issuer", "inactive", "conflicting_user"])
def test_no_key_written_when_verification_fails(client, gateway, slurm_commands, tmp_path, case):
    data = {**VERIFY, "ssh_public_key": PUBLIC_KEY}
    if case == "invalid_code":
        data["code"] = "123456"
    elif case == "wrong_issuer":
        gateway.issuer = "misty:production"
    elif case == "inactive":
        gateway.active = False
    with patch("rain.local_user_exists", side_effect=rain.UserConflict("conflicting Linux user")) as local:
        response = client.post("/api/verify-code", json=data)
    assert response.status_code == (409 if case == "conflicting_user" else 403)
    assert not (tmp_path / "keys").exists()
    assert not any(args[1:4] == ("-i", "add", "user") for args, _ in slurm_commands.call_args_list)
    assert local.called is (case == "conflicting_user")


def test_association_failure_does_not_install_key(client, slurm_commands, tmp_path):
    slurm_commands.side_effect = ["|\n", "", rain.SyncError("sacctmgr add failed")]
    response = client.post("/api/verify-code", json={**VERIFY, "ssh_public_key": PUBLIC_KEY})
    assert response.status_code == 503
    assert "Could not provision Slurm access" in response.json()["detail"]
    assert not (tmp_path / "keys").exists()


def test_private_key_is_never_forwarded_or_echoed(client, gateway):
    bad_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret"
    response = client.post("/verify-code", data={**VERIFY, "ssh_public_key": bad_key})
    assert response.status_code == 400
    assert "Do not upload private keys" in response.text
    assert "secret" not in response.text
    gateway.request.assert_not_called()
