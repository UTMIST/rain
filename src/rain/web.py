"""Web portal for requesting compute access and verifying Misty permissions."""

import argparse
import base64
import hashlib
import hmac
import http.cookies
import http.server
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import time
from typing import Any, Dict, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

import rain

LOG = logging.getLogger("rain.web")

# Default configuration matching Misty Staging environment
DEFAULT_GATEWAY_URL = "https://gateway-staging-dac4.up.railway.app"
DEFAULT_ENVIRONMENT = "staging"
DEFAULT_API_KEY = "gw_3VD0v-mg_uBUfhkwCPaJzENpqemnZCDX-YGcVzrL3mUH8Q88PE1g"
DEFAULT_CLUSTER = "rain"
DEFAULT_ACCOUNT = "misty-staging"
DEFAULT_PORT = 8080
DEFAULT_HOST = "0.0.0.0"

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CODE_REGEX = re.compile(r"^[0-9]{6}$")


class GatewayError(Exception):
    """Raised when communication with Misty Gateway fails."""

    def __init__(self, status_code: int, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.detail = detail


class MistyClient:
    """Client for communicating with the Misty Gateway API."""

    def __init__(
        self,
        gateway_url: str = DEFAULT_GATEWAY_URL,
        api_key: str = DEFAULT_API_KEY,
        environment: str = DEFAULT_ENVIRONMENT,
        timeout: float = 15.0,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.api_key = api_key
        self.environment = environment
        self.timeout = timeout

    def _request(
        self, method: str, path: str, data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = f"{self.gateway_url}{path}"
        headers = {
            "Accept": "application/json",
            "X-API-Key": self.api_key,
        }
        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read().decode("utf-8")
                return json.loads(content) if content else {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            detail = None
            try:
                err_json = json.loads(err_body)
                if isinstance(err_json, dict):
                    detail = err_json.get("detail")
            except ValueError:
                detail = err_body
            raise GatewayError(
                status_code=exc.code,
                message=f"Misty Gateway returned HTTP {exc.code}",
                detail=detail,
            ) from exc
        except (urllib.error.URLError, OSError, socket.timeout) as exc:
            raise GatewayError(
                status_code=503,
                message=f"Could not connect to Misty Gateway: {exc}",
            ) from exc

    def get_issuer(self) -> Dict[str, Any]:
        """Fetch issuer information from Gateway."""
        return self._request("GET", "/v1/auth/issuer")

    def start_email_login(self, email: str, client_ip: str) -> Dict[str, Any]:
        """Initiate email login challenge."""
        payload = {"email": email.strip().lower(), "client_ip": client_ip}
        return self._request("POST", "/v1/auth/email/start", payload)

    def confirm_email_login(
        self, challenge_id: str, code: str, client_ip: str
    ) -> Dict[str, Any]:
        """Confirm email login challenge with 6-digit code."""
        payload = {
            "challenge_id": challenge_id,
            "code": code.strip(),
            "client_ip": client_ip,
        }
        res = self._request("POST", "/v1/auth/email/confirm", payload)
        expected_issuer = f"misty:{self.environment}"
        if res.get("issuer") != expected_issuer:
            raise GatewayError(
                status_code=403,
                message="Unexpected authentication issuer",
                detail=f"Expected {expected_issuer}, got {res.get('issuer')}",
            )
        return res

    def get_person_status(self, person_id: str) -> Dict[str, Any]:
        """Check active eligibility status of a person by UUID."""
        try:
            val = UUID(person_id)
        except ValueError as exc:
            raise GatewayError(
                status_code=400, message="Invalid person UUID", detail=str(exc)
            ) from exc
        return self._request("GET", f"/v1/auth/people/{val}/status")


class SessionManager:
    """Issues and verifies HMAC-signed session tokens and CSRF tokens."""

    def __init__(self, secret: Optional[bytes] = None):
        self.secret = secret or secrets.token_bytes(32)

    def create_session(self) -> Tuple[str, str]:
        """Returns (session_cookie_value, csrf_token)."""
        session_id = secrets.token_hex(16)
        csrf_token = secrets.token_hex(16)
        payload = f"{session_id}:{csrf_token}".encode("ascii")
        sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        cookie_val = f"{session_id}:{csrf_token}:{sig}"
        return cookie_val, csrf_token

    def verify_session(
        self, cookie_val: Optional[str], csrf_token: Optional[str]
    ) -> bool:
        if not cookie_val or not csrf_token:
            return False
        parts = cookie_val.split(":")
        if len(parts) != 3:
            return False
        session_id, token_in_cookie, sig = parts
        if not hmac.compare_digest(token_in_cookie, csrf_token):
            return False
        payload = f"{session_id}:{token_in_cookie}".encode("ascii")
        expected_sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Request Access · Rain UTMIST</title>
  <style>
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #f6f7fb;
      color: #19233f;
      display: flex;
      justify-content: center;
      padding: 48px 16px;
      margin: 0;
    }
    .container {
      max-width: 480px;
      width: 100%;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 28px;
      box-sizing: border-box;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    h1 {
      font-size: 20px;
      margin: 0 0 6px 0;
    }
    h2 {
      font-size: 15px;
      margin: 0 0 8px 0;
    }
    p {
      font-size: 14px;
      color: #646f88;
      margin: 0 0 20px 0;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 6px;
    }
    input, textarea {
      width: 100%;
      box-sizing: border-box;
      padding: 10px 12px;
      font-size: 14px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      margin-bottom: 14px;
    }
    textarea {
      font-family: monospace;
      font-size: 12px;
      resize: vertical;
      margin-bottom: 6px;
    }
    input:focus, textarea:focus {
      outline: 2px solid #002fcb;
    }
    .help-text {
      font-size: 12px;
      color: #646f88;
      margin-top: -2px;
      margin-bottom: 16px;
      line-height: 1.4;
    }
    button {
      width: 100%;
      padding: 10px;
      font-size: 14px;
      font-weight: 600;
      background: #002fcb;
      color: #ffffff;
      border: none;
      border-radius: 6px;
      cursor: pointer;
    }
    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
    .secondary-btn {
      background: #e2e8f0;
      color: #19233f;
      margin-top: 8px;
    }
    .secondary-btn:hover {
      background: #cbd5e1;
    }
    .alert {
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .alert-error {
      background: #fef2f2;
      color: #991b1b;
      border: 1px solid #fecaca;
    }
    .alert-success {
      background: #f0fdf4;
      color: #166534;
      border: 1px solid #bbf7d0;
    }
    .alert-info {
      background: #eff6ff;
      color: #1e40af;
      border: 1px solid #bfdbfe;
    }
    .code-input {
      font-family: monospace;
      font-size: 20px;
      letter-spacing: 4px;
      text-align: center;
    }
    .details {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 14px;
      margin-top: 14px;
      font-size: 13px;
    }
    .details div {
      margin-bottom: 8px;
    }
    .details div:last-child {
      margin-bottom: 0;
    }
    .details strong {
      display: inline-block;
      width: 130px;
      color: #646f88;
    }
    .mono {
      font-family: monospace;
      word-break: break-all;
    }
    .ssh-box {
      margin-top: 14px;
      background: #f1f5f9;
      padding: 12px;
      border-radius: 6px;
      border: 1px solid #e2e8f0;
    }
    .ssh-box label {
      font-size: 12px;
      color: #475569;
      margin-bottom: 4px;
    }
    .ssh-input-row {
      display: flex;
      gap: 8px;
    }
    .ssh-input-row input {
      margin-bottom: 0;
      font-size: 12px;
      background: #ffffff;
      padding: 6px 10px;
    }
    .ssh-input-row button {
      width: auto;
      padding: 6px 14px;
      font-size: 12px;
      white-space: nowrap;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Request Access</h1>
    <p>Verify your permissions against Misty to obtain UTMIST Slurm compute and SSH access on cluster Rain.</p>

    <div id="alert" style="display: none;"></div>

    <form id="step-1" onsubmit="handleRequestCode(event)">
      <label for="email-input">Email Address</label>
      <input id="email-input" type="email" placeholder="name@mail.utoronto.ca" required autofocus autocomplete="email">
      <button id="send-btn" type="submit">Send Verification Code</button>
    </form>

    <form id="step-2" style="display: none;" onsubmit="handleVerifyCode(event)">
      <div class="alert alert-info">A verification code was sent to <span id="sent-email"></span>.</div>
      <label for="name-input">Full Name (optional)</label>
      <input id="name-input" type="text" placeholder="Ada Lovelace">
      <div class="help-text">Used to customize your Slurm username (e.g. <code>msty-alovelace</code>). If blank, derived from your email.</div>

      <label for="code-input">6-Digit Verification Code</label>
      <input id="code-input" class="code-input" type="text" maxlength="6" pattern="[0-9]{6}" placeholder="123456" required autocomplete="one-time-code">

      <label for="ssh-key-input">SSH Public Key</label>
      <textarea id="ssh-key-input" rows="3" placeholder="ssh-ed25519 AAAAC3... user@example.com" required></textarea>
      <div class="help-text">Paste your OpenSSH public key (e.g. <code>cat ~/.ssh/id_ed25519.pub</code>) to enable SSH access into the box with Slurm.</div>

      <button id="verify-btn" type="submit">Verify & Configure Access</button>
      <button type="button" class="secondary-btn" onclick="resetForm()">Back</button>
    </form>

    <div id="step-3" style="display: none;">
      <div class="alert alert-success">Permissions verified! SSH and Slurm access configured.</div>
      <div class="details">
        <div><strong>Status:</strong> Active in Misty staging</div>
        <div><strong>Person ID:</strong> <span id="res-uuid" class="mono"></span></div>
        <div><strong>Slurm Username:</strong> <span id="res-username" class="mono"></span></div>
        <div><strong>Cluster:</strong> <span id="res-cluster" class="mono"></span></div>
        <div><strong>Account:</strong> <span id="res-account" class="mono"></span></div>
        <div><strong>Shell:</strong> <span class="mono">/bin/bash</span></div>
        <div id="row-fp" style="display: none;"><strong>SSH Key FP:</strong> <span id="res-fp" class="mono"></span></div>
      </div>

      <div class="ssh-box">
        <label>SSH Login Command</label>
        <div class="ssh-input-row">
          <input id="ssh-cmd-text" class="mono" readonly>
          <button type="button" id="copy-btn" onclick="copySshCommand()">Copy</button>
        </div>
      </div>

      <div style="margin-top: 18px; border-top: 1px solid #e2e8f0; padding-top: 14px;">
        <h2>Update SSH Public Key</h2>
        <form onsubmit="handleUpdateSshKey(event)">
          <textarea id="update-ssh-key-input" rows="2" placeholder="ssh-ed25519 AAAAC3... user@example.com" required></textarea>
          <button id="update-key-btn" type="submit" class="secondary-btn" style="margin-top: 4px;">Update SSH Key</button>
        </form>
      </div>

      <button type="button" class="secondary-btn" style="margin-top: 16px;" onclick="resetForm()">Request for Another User</button>
    </div>
  </div>

  <script>
    let currentChallengeId = null;
    let currentPersonId = null;
    let currentUsername = null;

    function showAlert(type, msg) {
      const el = document.getElementById('alert');
      el.className = 'alert alert-' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    function hideAlert() {
      document.getElementById('alert').style.display = 'none';
    }

    async function handleRequestCode(e) {
      e.preventDefault();
      hideAlert();
      const email = document.getElementById('email-input').value.trim();
      const btn = document.getElementById('send-btn');
      btn.disabled = true;
      btn.textContent = 'Sending...';

      try {
        const res = await fetch('/api/request-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email })
        });
        const data = await res.json();
        if (res.ok && data.ok) {
          currentChallengeId = data.challenge_id;
          document.getElementById('sent-email').textContent = email;
          document.getElementById('step-1').style.display = 'none';
          document.getElementById('step-2').style.display = 'block';
          document.getElementById('code-input').focus();
        } else {
          showAlert('error', data.error || 'Failed to request verification code.');
        }
      } catch (err) {
        showAlert('error', 'Network error. Please try again.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Send Verification Code';
      }
    }

    async function handleVerifyCode(e) {
      e.preventDefault();
      hideAlert();
      const code = document.getElementById('code-input').value.trim();
      const sshKey = document.getElementById('ssh-key-input').value.trim();
      const enteredName = document.getElementById('name-input').value.trim();
      const email = document.getElementById('email-input').value.trim();
      const personName = enteredName || email;
      const btn = document.getElementById('verify-btn');
      btn.disabled = true;
      btn.textContent = 'Verifying...';

      try {
        const res = await fetch('/api/verify-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            challenge_id: currentChallengeId,
            code: code,
            name: personName,
            ssh_public_key: sshKey
          })
        });
        const data = await res.json();
        if (res.ok && data.ok) {
          currentPersonId = data.person_id;
          currentUsername = data.slurm_username;

          document.getElementById('res-uuid').textContent = data.person_id;
          document.getElementById('res-username').textContent = data.slurm_username;
          document.getElementById('res-cluster').textContent = data.cluster;
          document.getElementById('res-account').textContent = data.account;

          const host = window.location.hostname || 'rain.local';
          document.getElementById('ssh-cmd-text').value = 'ssh ' + data.slurm_username + '@' + host;

          if (data.ssh_key_fingerprint) {
            document.getElementById('res-fp').textContent = data.ssh_key_fingerprint;
            document.getElementById('row-fp').style.display = 'block';
          } else {
            document.getElementById('row-fp').style.display = 'none';
          }

          document.getElementById('step-2').style.display = 'none';
          document.getElementById('step-3').style.display = 'block';
        } else {
          showAlert('error', data.error || 'Invalid or expired verification code.');
        }
      } catch (err) {
        showAlert('error', 'Network error. Please try again.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Verify & Configure Access';
      }
    }

    async function handleUpdateSshKey(e) {
      e.preventDefault();
      hideAlert();
      const keyInput = document.getElementById('update-ssh-key-input');
      const sshKey = keyInput.value.trim();
      const btn = document.getElementById('update-key-btn');
      btn.disabled = true;
      btn.textContent = 'Updating...';

      try {
        const res = await fetch('/api/ssh-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            person_id: currentPersonId,
            ssh_public_key: sshKey
          })
        });
        const data = await res.json();
        if (res.ok && data.ok) {
          showAlert('success', 'SSH key successfully updated!');
          if (data.fingerprint) {
            document.getElementById('res-fp').textContent = data.fingerprint;
            document.getElementById('row-fp').style.display = 'block';
          }
          keyInput.value = '';
        } else {
          showAlert('error', data.error || 'Failed to update SSH key.');
        }
      } catch (err) {
        showAlert('error', 'Network error updating SSH key.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Update SSH Key';
      }
    }

    function copySshCommand() {
      const input = document.getElementById('ssh-cmd-text');
      input.select();
      navigator.clipboard.writeText(input.value);
      const btn = document.getElementById('copy-btn');
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = orig; }, 2000);
    }

    function resetForm() {
      currentChallengeId = null;
      currentPersonId = null;
      currentUsername = null;
      hideAlert();
      document.getElementById('step-1').style.display = 'block';
      document.getElementById('step-2').style.display = 'none';
      document.getElementById('step-3').style.display = 'none';
      document.getElementById('code-input').value = '';
      document.getElementById('name-input').value = '';
      document.getElementById('ssh-key-input').value = '';
      document.getElementById('update-ssh-key-input').value = '';
      document.getElementById('email-input').focus();
    }
  </script>
</body>
</html>
"""


class AccessPortalHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the Rain access request and permission checking portal."""

    misty_client: MistyClient
    session_manager: SessionManager
    cluster: str
    account: str
    keys_dir: str = rain.DEFAULT_KEYS_DIR

    server_version = "RainAccessPortal/0.1.0"

    def _get_client_ip(self) -> str:
        """Derive validated IPv4 or IPv6 address for the client.

        Misty Gateway strictly requires a valid IP format for rate-limiting.
        """
        raw_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        try:
            addr = ipaddress.ip_address(raw_ip)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(addr)
        except ValueError:
            return "127.0.0.1"

    def _get_cookie(self, name: str) -> Optional[str]:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(cookie_header)
            if name in cookies:
                return cookies[name].value
        except Exception:
            pass
        return None

    def _send_json(
        self,
        status_code: int,
        payload: Dict[str, Any],
        set_cookie: Optional[str] = None,
    ):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie:
            self.send_header(
                "Set-Cookie", f"{set_cookie}; Path=/; HttpOnly; SameSite=Lax"
            )
        self.end_headers()
        self.wfile.write(body)

    def _send_html(
        self, status_code: int, html_str: str, set_cookie: Optional[str] = None
    ):
        body = html_str.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header(
                "Set-Cookie", f"{set_cookie}; Path=/; HttpOnly; SameSite=Lax"
            )
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[Dict[str, Any]]:
        length = self.headers.get("Content-Length")
        if not length:
            return None
        try:
            byte_len = int(length)
            if byte_len > 65536:
                return None
            raw = self.rfile.read(byte_len)
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _verify_csrf(self) -> bool:
        cookie_val = self._get_cookie("rain_session")
        csrf_hdr = self.headers.get("X-CSRF-Token")
        return self.session_manager.verify_session(cookie_val, csrf_hdr)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        path = url.path.rstrip("/")
        if path == "" or path == "/index.html":
            cookie_val = self._get_cookie("rain_session")
            set_cookie = None
            if not cookie_val:
                cookie_val, _ = self.session_manager.create_session()
                set_cookie = f"rain_session={cookie_val}"
            self._send_html(200, HTML_PAGE, set_cookie=set_cookie)
            return

        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return

        if path == "/api/status":
            cookie_val = self._get_cookie("rain_session")
            set_cookie = None
            csrf_token = None
            if cookie_val:
                parts = cookie_val.split(":")
                if len(parts) == 3:
                    csrf_token = parts[1]
            if not csrf_token:
                cookie_val, csrf_token = self.session_manager.create_session()
                set_cookie = f"rain_session={cookie_val}"

            try:
                issuer_info = self.misty_client.get_issuer()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "issuer": issuer_info.get("issuer"),
                        "environment": self.misty_client.environment,
                        "cluster": self.cluster,
                        "account": self.account,
                        "csrf_token": csrf_token,
                    },
                    set_cookie=set_cookie,
                )
            except GatewayError as exc:
                self._send_json(
                    200,
                    {
                        "ok": False,
                        "error": exc.message,
                        "detail": exc.detail,
                        "environment": self.misty_client.environment,
                        "cluster": self.cluster,
                        "account": self.account,
                        "csrf_token": csrf_token,
                    },
                    set_cookie=set_cookie,
                )
            return

        self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        path = url.path.rstrip("/")

        data = self._read_json()
        if data is None:
            self._send_json(400, {"ok": False, "error": "Invalid JSON body"})
            return

        client_ip = self._get_client_ip()

        if path == "/api/request-code":
            email = str(data.get("email", "")).strip().lower()
            if not EMAIL_REGEX.match(email):
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "error": "Please provide a valid email address.",
                    },
                )
                return

            try:
                start_res = self.misty_client.start_email_login(
                    email, client_ip=client_ip
                )
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "challenge_id": start_res.get("challenge_id"),
                        "issuer": start_res.get("issuer"),
                        "message": start_res.get("message"),
                        "expires_in": start_res.get("expires_in", 600),
                    },
                )
            except GatewayError as exc:
                LOG.warning("Start email login failed: %s (%s)", exc.message, exc.detail)
                self._send_json(
                    exc.status_code,
                    {
                        "ok": False,
                        "error": exc.detail or exc.message,
                    },
                )
            return

        if path == "/api/verify-code":
            challenge_id = str(data.get("challenge_id", "")).strip()
            code = str(data.get("code", "")).strip()
            ssh_public_key = data.get("ssh_public_key")

            if not CODE_REGEX.match(code):
                self._send_json(
                    400,
                    {"ok": False, "error": "Verification code must be 6 digits."},
                )
                return

            try:
                UUID(challenge_id)
            except ValueError:
                self._send_json(
                    400, {"ok": False, "error": "Invalid challenge format."}
                )
                return

            sanitized_key = None
            fp = None
            if ssh_public_key:
                valid_key, key_err, sanitized_key, fp = rain.validate_ssh_public_key(
                    str(ssh_public_key)
                )
                if not valid_key:
                    self._send_json(
                        400,
                        {"ok": False, "error": key_err},
                    )
                    return

            try:
                confirm_res = self.misty_client.confirm_email_login(
                    challenge_id=challenge_id, code=code, client_ip=client_ip
                )
                person_id_str = confirm_res.get("person_id")
                person_uuid = UUID(person_id_str)

                # Re-verify active status with Misty
                status_res = self.misty_client.get_person_status(person_id_str)
                if not status_res.get("active"):
                    self._send_json(
                        403,
                        {
                            "ok": False,
                            "error": "Misty account is not currently active.",
                        },
                    )
                    return

                name = data.get("name")
                slurm_user = rain.username(person_uuid, name=name)

                if sanitized_key:
                    rain.save_ssh_key(slurm_user, sanitized_key, keys_dir=self.keys_dir)
                    rain.install_authorized_key(slurm_user, sanitized_key)
                    if os.geteuid() == 0:
                        try:
                            if not rain.local_user_exists(slurm_user, person_uuid):
                                rain.add_local_user(slurm_user, person_uuid)
                                rain.install_authorized_key(slurm_user, sanitized_key)
                        except Exception:
                            pass

                self._send_json(
                    200,
                    {
                        "ok": True,
                        "person_id": str(person_uuid),
                        "email": confirm_res.get("email"),
                        "slurm_username": slurm_user,
                        "cluster": self.cluster,
                        "account": self.account,
                        "issuer": confirm_res.get("issuer"),
                        "status": "approved",
                        "ssh_key_configured": bool(sanitized_key),
                        "ssh_key_fingerprint": fp,
                    },
                )
            except GatewayError as exc:
                LOG.warning(
                    "Confirm email login failed: %s (%s)", exc.message, exc.detail
                )
                self._send_json(
                    exc.status_code,
                    {
                        "ok": False,
                        "error": exc.detail or exc.message,
                    },
                )
            return

        if path == "/api/ssh-key":
            person_id_str = str(data.get("person_id", "")).strip()
            ssh_public_key = data.get("ssh_public_key")

            try:
                person_uuid = UUID(person_id_str)
            except ValueError:
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "error": "Expected a valid canonical 36-character UUID.",
                    },
                )
                return

            if not ssh_public_key:
                self._send_json(
                    400,
                    {"ok": False, "error": "Please provide an SSH public key."},
                )
                return

            valid_key, key_err, sanitized_key, fp = rain.validate_ssh_public_key(
                str(ssh_public_key)
            )
            if not valid_key:
                self._send_json(
                    400,
                    {"ok": False, "error": key_err},
                )
                return

            try:
                status_res = self.misty_client.get_person_status(str(person_uuid))
                if not status_res.get("active"):
                    self._send_json(
                        403,
                        {
                            "ok": False,
                            "error": "Misty account is not currently active.",
                        },
                    )
                    return

                name = data.get("name")
                slurm_user = rain.username(person_uuid, name=name)
                rain.save_ssh_key(slurm_user, sanitized_key, keys_dir=self.keys_dir)
                rain.install_authorized_key(slurm_user, sanitized_key)
                if os.geteuid() == 0:
                    try:
                        if not rain.local_user_exists(slurm_user, person_uuid):
                            rain.add_local_user(slurm_user, person_uuid)
                            rain.install_authorized_key(slurm_user, sanitized_key)
                    except Exception:
                        pass

                self._send_json(
                    200,
                    {
                        "ok": True,
                        "person_id": str(person_uuid),
                        "slurm_username": slurm_user,
                        "fingerprint": fp,
                        "message": "SSH public key saved and configured.",
                    },
                )
            except GatewayError as exc:
                self._send_json(
                    exc.status_code,
                    {
                        "ok": False,
                        "error": exc.detail or exc.message,
                    },
                )
            return

        if path == "/api/check-permissions":
            person_id_str = str(data.get("person_id", "")).strip()
            try:
                person_uuid = UUID(person_id_str)
            except ValueError:
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "error": "Expected a valid canonical 36-character UUID.",
                    },
                )
                return

            try:
                status_res = self.misty_client.get_person_status(str(person_uuid))
                is_active = bool(status_res.get("active"))
                name = data.get("name")
                slurm_user = rain.username(person_uuid, name=name) if is_active else None
                key_info = (
                    rain.get_ssh_key_info(slurm_user, keys_dir=self.keys_dir)
                    if slurm_user
                    else None
                )

                self._send_json(
                    200,
                    {
                        "ok": True,
                        "person_id": str(person_uuid),
                        "active": is_active,
                        "issuer": status_res.get("issuer"),
                        "slurm_username": slurm_user,
                        "cluster": self.cluster,
                        "account": self.account,
                        "ssh_key_configured": key_info is not None,
                        "ssh_key_fingerprint": key_info["fingerprint"]
                        if key_info
                        else None,
                    },
                )
            except GatewayError as exc:
                self._send_json(
                    exc.status_code,
                    {
                        "ok": False,
                        "error": exc.detail or exc.message,
                    },
                )
            return

        self._send_json(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        LOG.info(
            "%s - - [%s] %s",
            self.address_string(),
            self.log_date_time_string(),
            format % args,
        )


def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    gateway_url: str = DEFAULT_GATEWAY_URL,
    api_key: str = DEFAULT_API_KEY,
    environment: str = DEFAULT_ENVIRONMENT,
    cluster: str = DEFAULT_CLUSTER,
    account: str = DEFAULT_ACCOUNT,
    keys_dir: str = rain.DEFAULT_KEYS_DIR,
):
    """Run the access portal web server."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    client = MistyClient(
        gateway_url=gateway_url, api_key=api_key, environment=environment
    )
    session_mgr = SessionManager()

    class BoundHandler(AccessPortalHandler):
        pass

    BoundHandler.misty_client = client
    BoundHandler.session_manager = session_mgr
    BoundHandler.cluster = cluster
    BoundHandler.account = account
    BoundHandler.keys_dir = keys_dir

    server = http.server.ThreadingHTTPServer((host, port), BoundHandler)
    LOG.info("Rain Access Portal listening on http://%s:%d", host, port)
    LOG.info("Misty Gateway URL: %s (env: %s)", gateway_url, environment)
    LOG.info("Slurm Cluster: %s, Account: %s", cluster, account)
    LOG.info("SSH Keys Directory: %s", keys_dir)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Shutting down web portal...")
    finally:
        server.server_close()


def load_env_file(path: Optional[str] = None):
    """Load KEY=VALUE pairs from a .env or sync.env file into os.environ if not already set."""
    candidates = (
        [path] if path else [".env", "sync.env", "/etc/misty-slurm-sync/sync.env"]
    )
    for cand in candidates:
        if cand and os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
                break
            except OSError:
                pass


def main(args=None):
    load_env_file()
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Web portal for requesting Rain compute access."
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("RAIN_WEB_HOST", os.environ.get("HOST", DEFAULT_HOST)),
        help="Bind host",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(
            os.environ.get("RAIN_WEB_PORT", os.environ.get("PORT", str(DEFAULT_PORT)))
        ),
        help="Bind port",
    )
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("MISTY_GATEWAY_URL", DEFAULT_GATEWAY_URL),
        help="Misty Gateway base URL",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("MISTY_GATEWAY_API_KEY", DEFAULT_API_KEY),
        help="Misty Gateway API key",
    )
    parser.add_argument(
        "--environment",
        default=os.environ.get("MISTY_ENVIRONMENT", DEFAULT_ENVIRONMENT),
        help="Misty Environment",
    )
    parser.add_argument(
        "--cluster",
        default=os.environ.get("SLURM_CLUSTER", DEFAULT_CLUSTER),
        help="Slurm cluster name",
    )
    parser.add_argument(
        "--account",
        default=os.environ.get("SLURM_ACCOUNT", DEFAULT_ACCOUNT),
        help="Slurm account name",
    )
    parser.add_argument(
        "--keys-dir",
        default=os.environ.get("RAIN_KEYS_DIR", rain.DEFAULT_KEYS_DIR),
        help="Directory for storing user public SSH keys",
    )

    parsed = parser.parse_args(args)
    run_server(
        host=parsed.host,
        port=parsed.port,
        gateway_url=parsed.gateway_url,
        api_key=parsed.api_key,
        environment=parsed.environment,
        cluster=parsed.cluster,
        account=parsed.account,
        keys_dir=parsed.keys_dir,
    )


if __name__ == "__main__":
    main()
