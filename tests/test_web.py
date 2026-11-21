"""Tests for the Rain access request web portal."""

import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from uuid import UUID

import rain
from rain import web

TEST_UUID = UUID("550e8400-e29b-41d4-a716-446655440000")
TEST_SLURM_USER = rain.username(TEST_UUID)
TEST_SSH_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqq90UoX99a5Y5oWpQk2vXpQYkQ9i3O5mF9y5uW6pT test@example.com"
)


class MistyClientTests(unittest.TestCase):
    def setUp(self):
        self.client = web.MistyClient(
            gateway_url="https://gateway.example.org",
            api_key="test-key",
            environment="staging",
        )

    @patch("urllib.request.urlopen")
    def test_get_issuer(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"issuer": "misty:staging"}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.get_issuer()
        self.assertEqual(res, {"issuer": "misty:staging"})

    @patch("urllib.request.urlopen")
    def test_start_email_login(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "issuer": "misty:staging",
            "challenge_id": "550e8400-e29b-41d4-a716-446655440001",
            "expires_in": 600,
            "message": "code sent",
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.start_email_login("user@mail.utoronto.ca", "127.0.0.1")
        self.assertEqual(res["challenge_id"], "550e8400-e29b-41d4-a716-446655440001")

    @patch("urllib.request.urlopen")
    def test_confirm_email_login_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "issuer": "misty:staging",
            "person_id": str(TEST_UUID),
            "email": "user@mail.utoronto.ca",
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.confirm_email_login(
            "550e8400-e29b-41d4-a716-446655440001", "123456", "127.0.0.1"
        )
        self.assertEqual(res["person_id"], str(TEST_UUID))

    @patch("urllib.request.urlopen")
    def test_confirm_email_login_issuer_mismatch(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "issuer": "misty:production",
            "person_id": str(TEST_UUID),
            "email": "user@mail.utoronto.ca",
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        with self.assertRaises(web.GatewayError) as ctx:
            self.client.confirm_email_login(
                "550e8400-e29b-41d4-a716-446655440001", "123456", "127.0.0.1"
            )
        self.assertEqual(ctx.exception.status_code, 403)

    @patch("urllib.request.urlopen")
    def test_get_person_status(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "issuer": "misty:staging",
            "active": True,
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.get_person_status(str(TEST_UUID))
        self.assertTrue(res["active"])


class SessionManagerTests(unittest.TestCase):
    def test_session_lifecycle(self):
        mgr = web.SessionManager()
        cookie_val, csrf_token = mgr.create_session()
        self.assertTrue(mgr.verify_session(cookie_val, csrf_token))
        self.assertFalse(mgr.verify_session(cookie_val, "wrong-token"))
        self.assertFalse(mgr.verify_session("tampered:cookie:val", csrf_token))
        self.assertFalse(mgr.verify_session(None, csrf_token))


class WebServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.keys_dir = Path(cls.temp_dir.name) / "keys"
        cls.keys_dir.mkdir(parents=True, exist_ok=True)

        cls.mock_client = MagicMock()
        cls.session_mgr = web.SessionManager()

        class TestHandler(web.AccessPortalHandler):
            misty_client = cls.mock_client
            session_manager = cls.session_mgr
            cluster = "rain"
            account = "misty-staging"
            keys_dir = str(cls.keys_dir)

        cls.server = web.http.server.ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp_dir.cleanup()

    def _request(self, method, path, data=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        req_headers = headers.copy() if headers else {}
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=req_headers)
        res = conn.getresponse()
        raw = res.read()
        res_data = None
        if "application/json" in res.getheader("Content-Type", ""):
            res_data = json.loads(raw.decode("utf-8"))
        conn.close()
        return res.status, res.getheaders(), res_data, raw

    def test_get_root_serves_html(self):
        status, headers, _, raw = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Rain", raw)
        self.assertIn(b"SSH Public Key", raw)
        self.assertIn(b"UTMIST", raw)

    def test_get_health(self):
        status, _, data, _ = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"status": "ok"})

    def test_get_api_status(self):
        self.mock_client.get_issuer.return_value = {"issuer": "misty:staging"}
        self.mock_client.environment = "staging"
        status, _, data, _ = self._request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["issuer"], "misty:staging")
        self.assertEqual(data["cluster"], "rain")
        self.assertEqual(data["account"], "misty-staging")
        self.assertTrue("csrf_token" in data)

    def test_request_code_valid_and_invalid(self):
        # Invalid email
        status, _, data, _ = self._request("POST", "/api/request-code", {"email": "invalid"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])

        # Valid email
        self.mock_client.start_email_login.return_value = {
            "issuer": "misty:staging",
            "challenge_id": "550e8400-e29b-41d4-a716-446655440002",
            "expires_in": 600,
            "message": "code sent",
        }
        status, _, data, _ = self._request("POST", "/api/request-code", {"email": "member@mail.utoronto.ca"})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["challenge_id"], "550e8400-e29b-41d4-a716-446655440002")

    def test_verify_code_success_without_ssh_key(self):
        self.mock_client.confirm_email_login.return_value = {
            "issuer": "misty:staging",
            "person_id": str(TEST_UUID),
            "email": "member@mail.utoronto.ca",
        }
        self.mock_client.get_person_status.return_value = {
            "issuer": "misty:staging",
            "active": True,
        }

        status, _, data, _ = self._request(
            "POST",
            "/api/verify-code",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440002",
                "code": "123456",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["person_id"], str(TEST_UUID))
        self.assertEqual(data["slurm_username"], TEST_SLURM_USER)
        self.assertEqual(data["cluster"], "rain")
        self.assertEqual(data["account"], "misty-staging")
        self.assertFalse(data["ssh_key_configured"])

    def test_verify_code_success_with_ssh_key(self):
        self.mock_client.confirm_email_login.return_value = {
            "issuer": "misty:staging",
            "person_id": str(TEST_UUID),
            "email": "member@mail.utoronto.ca",
        }
        self.mock_client.get_person_status.return_value = {
            "issuer": "misty:staging",
            "active": True,
        }

        status, _, data, _ = self._request(
            "POST",
            "/api/verify-code",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440002",
                "code": "123456",
                "ssh_public_key": TEST_SSH_KEY,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["person_id"], str(TEST_UUID))
        self.assertEqual(data["slurm_username"], TEST_SLURM_USER)
        self.assertTrue(data["ssh_key_configured"])
        self.assertTrue(data["ssh_key_fingerprint"].startswith("SHA256:"))

        # Check key was written to keys_dir
        saved_file = self.keys_dir / f"{TEST_SLURM_USER}.pub"
        self.assertTrue(saved_file.is_file())
        self.assertIn("ssh-ed25519", saved_file.read_text())

    def test_verify_code_rejects_private_key(self):
        status, _, data, _ = self._request(
            "POST",
            "/api/verify-code",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440002",
                "code": "123456",
                "ssh_public_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nbad\n-----END OPENSSH PRIVATE KEY-----",
            },
        )
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        self.assertIn("Do not upload private keys", data["error"])

    def test_verify_code_invalid_format(self):
        status, _, data, _ = self._request(
            "POST",
            "/api/verify-code",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440002",
                "code": "bad",
            },
        )
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])

    def test_verify_code_with_person_name(self):
        self.mock_client.confirm_email_login.return_value = {
            "issuer": "misty:staging",
            "person_id": str(TEST_UUID),
            "email": "ada.lovelace@mail.utoronto.ca",
        }
        self.mock_client.get_person_status.return_value = {
            "issuer": "misty:staging",
            "active": True,
        }

        status, _, data, _ = self._request(
            "POST",
            "/api/verify-code",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440002",
                "code": "123456",
                "name": "Ada Lovelace",
                "ssh_public_key": TEST_SSH_KEY,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["slurm_username"], "msty-alovelace")

    def test_post_ssh_key_endpoint(self):
        self.mock_client.get_person_status.return_value = {
            "issuer": "misty:staging",
            "active": True,
        }
        status, _, data, _ = self._request(
            "POST",
            "/api/ssh-key",
            {
                "person_id": str(TEST_UUID),
                "ssh_public_key": TEST_SSH_KEY,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["slurm_username"], TEST_SLURM_USER)
        self.assertTrue(data["fingerprint"].startswith("SHA256:"))

    def test_post_ssh_key_inactive_person(self):
        self.mock_client.get_person_status.return_value = {
            "issuer": "misty:staging",
            "active": False,
        }
        status, _, data, _ = self._request(
            "POST",
            "/api/ssh-key",
            {
                "person_id": str(TEST_UUID),
                "ssh_public_key": TEST_SSH_KEY,
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(data["ok"])

    def test_check_permissions(self):
        # Active person without key initially
        self.mock_client.get_person_status.return_value = {
            "issuer": "misty:staging",
            "active": True,
        }
        status, _, data, _ = self._request("POST", "/api/check-permissions", {"person_id": str(TEST_UUID)})
        self.assertEqual(status, 200)
        self.assertTrue(data["active"])
        self.assertEqual(data["slurm_username"], TEST_SLURM_USER)
        self.assertFalse(data["ssh_key_configured"])

        # After saving key
        rain.save_ssh_key(TEST_SLURM_USER, TEST_SSH_KEY, keys_dir=str(self.keys_dir))
        status, _, data, _ = self._request("POST", "/api/check-permissions", {"person_id": str(TEST_UUID)})
        self.assertEqual(status, 200)
        self.assertTrue(data["active"])
        self.assertEqual(data["slurm_username"], TEST_SLURM_USER)
        self.assertTrue(data["ssh_key_configured"])
        self.assertTrue(data["ssh_key_fingerprint"].startswith("SHA256:"))

        # Inactive person
        self.mock_client.get_person_status.return_value = {
            "issuer": "misty:staging",
            "active": False,
        }
        status, _, data, _ = self._request("POST", "/api/check-permissions", {"person_id": str(TEST_UUID)})
        self.assertEqual(status, 200)
        self.assertFalse(data["active"])
        self.assertIsNone(data["slurm_username"])

        # Bad UUID
        status, _, data, _ = self._request("POST", "/api/check-permissions", {"person_id": "not-a-uuid"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])


if __name__ == "__main__":
    unittest.main()
