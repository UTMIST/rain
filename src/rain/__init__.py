"""Add batch identities for active people in the Misty staging directory."""

import argparse
import base64
import grp
import hashlib
import json
import logging
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
from typing import Dict, Optional, Tuple
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

LOG = logging.getLogger("rain")
MAX_ROSTER_BYTES = 8 * 1024 * 1024
LOGIN_SHELL = "/bin/bash"
NOLOGIN = "/usr/sbin/nologin"
UID_MIN, UID_MAX = 30000, 39999
LABEL = re.compile(r"[a-z][a-z0-9_-]{0,30}")
KEY = re.compile(r"[!-~]{16,256}")
DEFAULT_KEYS_DIR = os.environ.get("RAIN_KEYS_DIR", "/var/lib/rain/keys")

SUPPORTED_SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}


class Person(UUID):
    """Misty person UUID with optional name and email metadata."""

    __slots__ = ("name", "email")

    def __init__(self, val, name=None, email=None):
        super().__init__(str(val))
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "email", email)


class SyncError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_roster(raw):
    if len(raw) > MAX_ROSTER_BYTES:
        raise SyncError("staging roster exceeds size limit")
    try:
        rows = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise SyncError("staging roster is not valid JSON") from exc
    if not isinstance(rows, list):
        raise SyncError("staging roster must be a JSON array")
    people = set()
    active = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("active"), bool):
            raise SyncError("invalid staging person (expected boolean active)")
        value = row.get("id")
        display_name = row.get("display_name") or row.get("name")
        primary_email = row.get("primary_email") or row.get("email")
        try:
            person = (
                Person(value, name=display_name, email=primary_email)
                if isinstance(value, str)
                else None
            )
        except ValueError:
            person = None
        if person is None or str(person) != value or person.int == 0:
            raise SyncError("invalid staging person ID (expected canonical UUID)")
        if person in people:
            raise SyncError("duplicate staging person ID")
        people.add(person)
        if row["active"]:
            active.add(person)
    return sorted(active)


def staging_url(value):
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise SyncError("invalid MISTY_STAGING_URL") from exc
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username is not None
        or url.query
        or url.fragment
        or port == 0
        or any(c.isspace() or ord(c) < 32 for c in value)
    ):
        raise SyncError(
            "MISTY_STAGING_URL must be an HTTPS base URL without credentials"
        )
    return value.rstrip("/") + "/people?active_only=true"


def fetch_roster(url):
    credentials = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credentials:
        raise SyncError(
            "load the Misty staging key as systemd credential staging-api-key"
        )
    try:
        key = (
            (Path(credentials) / "staging-api-key").read_text(encoding="ascii").strip()
        )
    except (OSError, UnicodeError) as exc:
        raise SyncError("cannot read systemd credential staging-api-key") from exc
    if not KEY.fullmatch(key) or key.startswith("tt_"):
        raise SyncError(
            "expected a dedicated roster reader key, not an internal Misty key"
        )
    opener = build_opener(NoRedirect(), ProxyHandler({}))
    request = Request(url, headers={"Accept": "application/json", "X-API-Key": key})
    try:
        with opener.open(request, timeout=20) as response:
            return response.read(MAX_ROSTER_BYTES + 1)
    except HTTPError as exc:
        exc.close()
        raise SyncError(f"staging roster request returned HTTP {exc.code}") from exc
    except (URLError, OSError, ValueError) as exc:
        raise SyncError("could not read the staging roster over HTTPS") from exc


def read_export(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o077
            ):
                raise SyncError(
                    "roster export must be a root-owned private regular file"
                )
            return file.read(MAX_ROSTER_BYTES + 1)
    except OSError as exc:
        raise SyncError("could not read the staging roster export") from exc


def slugify_name(name: str) -> str:
    """Convert a person's display name or email into a POSIX username slug."""
    if not name or not isinstance(name, str):
        return ""
    normalized = unicodedata.normalize("NFKD", name)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii").lower().strip()
    if "@" in ascii_text:
        ascii_text = ascii_text.split("@", 1)[0]
    parts = [p for p in re.split(r"[^a-z0-9]+", ascii_text) if p]
    if not parts:
        return ""
    if len(parts) == 1:
        slug = parts[0]
    else:
        first_initial = parts[0][0]
        last_name = parts[-1]
        slug = f"{first_initial}{last_name}"
    return re.sub(r"[^a-z0-9]", "", slug)[:20]


def username(person=None, name=None) -> str:
    """Generate a Slurm username related to the person's name with msty- prefix."""
    slug = None
    if name:
        slug = slugify_name(name)
    elif isinstance(person, str):
        try:
            u = UUID(person)
            person = u
        except ValueError:
            slug = slugify_name(person)

    if not slug and person is not None:
        if isinstance(person, dict):
            raw_name = (
                person.get("display_name")
                or person.get("name")
                or person.get("primary_email")
                or person.get("email")
            )
            if raw_name:
                slug = slugify_name(raw_name)
        elif hasattr(person, "name") and person.name:
            slug = slugify_name(person.name)
        elif hasattr(person, "email") and person.email:
            slug = slugify_name(person.email)

    if slug:
        return f"msty-{slug}"

    if isinstance(person, UUID):
        digest = hashlib.sha256(person.bytes).digest()
        return "msty-" + base64.b32encode(digest[:5]).decode("ascii").lower()

    return "msty-user"


def validate_ssh_public_key(raw_key: str) -> Tuple[bool, str, str, str]:
    """Validate OpenSSH public key format and compute SHA256 fingerprint.

    Returns:
        (is_valid, error_message, sanitized_key, fingerprint)
    """
    if not isinstance(raw_key, str):
        return False, "SSH public key must be a string.", "", ""
    text = raw_key.strip()
    if "PRIVATE KEY" in text:
        return (
            False,
            "Do not upload private keys. Please provide your OpenSSH public key (e.g. ~/.ssh/id_ed25519.pub).",
            "",
            "",
        )
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False, "SSH public key cannot be empty.", "", ""
    if len(lines) > 1:
        return False, "Please provide a single SSH public key line.", "", ""
    line = lines[0]
    if len(line) > 4096:
        return False, "SSH public key is too long (maximum 4096 characters).", "", ""
    parts = line.split()
    if len(parts) < 2:
        return (
            False,
            "Invalid SSH public key format. Expected: <key-type> <base64-key> [comment].",
            "",
            "",
        )
    key_type, key_b64 = parts[0], parts[1]
    if key_type not in SUPPORTED_SSH_KEY_TYPES:
        return (
            False,
            f"Unsupported SSH key type '{key_type}'. Supported: {', '.join(sorted(SUPPORTED_SSH_KEY_TYPES))}.",
            "",
            "",
        )
    try:
        key_bytes = base64.b64decode(key_b64, validate=True)
        if len(key_bytes) < 16:
            return False, "SSH public key data is too short.", "", ""
    except Exception:
        return False, "Invalid base64 payload in SSH public key.", "", ""
    comment = " ".join(parts[2:]) if len(parts) > 2 else ""
    comment = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", comment)[:100].strip()
    sanitized = f"{key_type} {key_b64}" + (f" {comment}" if comment else "")
    fp_digest = hashlib.sha256(key_bytes).digest()
    fp = "SHA256:" + base64.b64encode(fp_digest).decode("ascii").rstrip("=")
    return True, "", sanitized, fp


def save_ssh_key(name: str, key_line: str, keys_dir: str = DEFAULT_KEYS_DIR) -> Path:
    """Save user's public key to the central keys directory."""
    if not LABEL.fullmatch(name):
        raise SyncError(f"invalid username for ssh key: {name}")
    dir_path = Path(keys_dir)
    try:
        dir_path.mkdir(parents=True, exist_ok=True, mode=0o755)
    except OSError:
        fallback = Path.home() / ".rain" / "keys"
        try:
            fallback.mkdir(parents=True, exist_ok=True, mode=0o700)
            dir_path = fallback
        except OSError:
            import tempfile

            dir_path = Path(tempfile.gettempdir()) / "rain_keys"
            dir_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = dir_path / f"{name}.pub"
    key_path.write_text(key_line.strip() + "\n", encoding="utf-8")
    try:
        key_path.chmod(0o644)
    except OSError:
        pass
    return key_path


def install_authorized_key(
    name: str, key_line: str, home_dir: Optional[str] = None
) -> bool:
    """Install public key into user's ~/.ssh/authorized_keys."""
    if not LABEL.fullmatch(name):
        raise SyncError(f"invalid username for authorized_keys: {name}")
    home = Path(home_dir) if home_dir else Path(f"/home/{name}")
    if not home.is_dir():
        try:
            home.mkdir(parents=True, exist_ok=True, mode=0o750)
        except OSError:
            return False
    ssh_dir = home / ".ssh"
    try:
        ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        return False
    auth_file = ssh_dir / "authorized_keys"
    sanitized = key_line.strip()
    try:
        existing = ""
        if auth_file.exists():
            existing = auth_file.read_text(encoding="utf-8", errors="replace")
        lines = [line.strip() for line in existing.splitlines() if line.strip()]
        if sanitized not in lines:
            lines.append(sanitized)
            auth_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            auth_file.chmod(0o600)
            ssh_dir.chmod(0o700)
        except OSError:
            pass

        try:
            entry = pwd.getpwnam(name)
            if os.geteuid() == 0:
                os.chown(ssh_dir, entry.pw_uid, entry.pw_gid)
                os.chown(auth_file, entry.pw_uid, entry.pw_gid)
        except (KeyError, OSError, PermissionError):
            pass
        return True
    except OSError:
        return False


def get_ssh_key_info(
    name: str, keys_dir: str = DEFAULT_KEYS_DIR
) -> Optional[Dict[str, str]]:
    """Return key and fingerprint for a user if registered."""
    candidates = [
        Path(keys_dir) / f"{name}.pub",
        Path.home() / ".rain" / "keys" / f"{name}.pub",
        Path(f"/home/{name}/.ssh/authorized_keys"),
    ]
    for cand in candidates:
        if cand.is_file():
            try:
                content = cand.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    valid, _, san, fp = validate_ssh_public_key(line)
                    if valid:
                        return {"key": san, "fingerprint": fp}
            except OSError:
                pass
    return None


def run(*args):
    try:
        result = subprocess.run(
            args,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.CalledProcessError as exc:
        raise SyncError(
            f"{Path(args[0]).name} {args[1]} failed (exit {exc.returncode})"
        ) from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SyncError(f"could not run {Path(args[0]).name} {args[1]}") from exc
    return result.stdout


SACCTMGR = "/usr/bin/sacctmgr"


def local_user_exists(name, person):
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return False
    try:
        private_group = grp.getgrgid(entry.pw_gid).gr_name == name
    except KeyError:
        private_group = False
    if (
        not private_group
        or not UID_MIN <= entry.pw_uid <= UID_MAX
        or entry.pw_gecos != f"misty-staging={person}"
        or entry.pw_shell != LOGIN_SHELL
        or entry.pw_dir != f"/home/{name}"
    ):
        raise SyncError("refusing to reuse a conflicting Linux user")
    return True


def add_local_user(name, person):
    run(
        "/usr/sbin/useradd",
        "-m",
        "-U",
        "-l",
        "-d",
        f"/home/{name}",
        "-s",
        LOGIN_SHELL,
        "-c",
        f"misty-staging={person}",
        "-K",
        f"UID_MIN={UID_MIN}",
        "-K",
        f"UID_MAX={UID_MAX}",
        "-K",
        f"GID_MIN={UID_MIN}",
        "-K",
        f"GID_MAX={UID_MAX}",
        "--",
        name,
    )


def reconcile(people, cluster, account, dry_run=False, keys_dir=DEFAULT_KEYS_DIR):
    accounts = run(
        SACCTMGR,
        "-nP",
        "show",
        "assoc",
        "where",
        f"Cluster={cluster}",
        f"Account={account}",
        "format=User%32,Partition%32",
    )
    associations = set(tuple(line.split("|")) for line in accounts.splitlines())
    if ("", "") not in associations:
        raise SyncError(
            f"Slurm account {account} is not registered on cluster {cluster}"
        )
    users = dict(
        line.split("|", 1)
        for line in run(
            SACCTMGR, "-nP", "show", "user", "format=User%32,Admin"
        ).splitlines()
        if "|" in line
    )
    ok = True
    changes = 0
    for person in people:
        name = username(person)
        try:
            local_exists = local_user_exists(name, person)
            if name in users and (not local_exists or users[name].lower() != "none"):
                raise SyncError("refusing to reuse a conflicting Slurm user")
            needs_assoc = (name, "") not in associations
            if not local_exists or needs_assoc:
                changes += 1
                if not dry_run:
                    if not local_exists:
                        add_local_user(name, person)
                    if needs_assoc:
                        run(
                            SACCTMGR,
                            "-i",
                            "add",
                            "user",
                            name,
                            f"Cluster={cluster}",
                            f"Account={account}",
                        )
                LOG.info("%s %s", "would provision" if dry_run else "provisioned", name)
            if not dry_run:
                key_info = get_ssh_key_info(name, keys_dir=keys_dir)
                if key_info:
                    install_authorized_key(name, key_info["key"])
        except SyncError as exc:
            LOG.error("%s: %s", name, exc)
            ok = False
    LOG.info(
        "staging roster: %d active, %d needing changes, %s",
        len(people),
        changes,
        "complete" if ok else "incomplete",
    )
    return ok


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "web":
        from rain import web

        return web.main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one sync and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="preview one sync without writes"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    once = args.once or args.dry_run
    url = os.environ.get("MISTY_STAGING_URL")
    export = os.environ.get("MISTY_STAGING_ROSTER")
    cluster = os.environ.get("SLURM_CLUSTER", "rain")
    account = os.environ.get("SLURM_ACCOUNT", "misty-staging")
    interval = os.environ.get("MISTY_SYNC_INTERVAL", "300")
    try:
        if not LABEL.fullmatch(cluster) or not LABEL.fullmatch(account):
            raise SyncError("invalid Slurm cluster or account name")
        if (
            not re.fullmatch(r"[0-9]{1,5}", interval)
            or not 30 <= int(interval) <= 86400
        ):
            raise SyncError("sync interval must be 30–86400 seconds")
        if url and export:
            raise SyncError("configure exactly one staging roster source")
        if url:
            endpoint = staging_url(url)

            def read():
                return fetch_roster(endpoint)
        elif export:
            if not Path(export).is_absolute():
                raise SyncError("roster export path must be absolute")

            def read():
                return read_export(export)
        else:
            if once:
                raise SyncError("no Misty staging source configured")
            LOG.warning(
                "waiting for a Misty staging URL or roster export; no users will be created"
            )
            while True:
                time.sleep(3600)
    except SyncError as exc:
        LOG.error("configuration: %s", exc)
        return 2

    while True:
        try:
            ok = reconcile(parse_roster(read()), cluster, account, dry_run=args.dry_run)
        except SyncError as exc:
            LOG.error("sync failed: %s", exc)
            ok = False
        if once:
            return 0 if ok else 1
        time.sleep(int(interval))
