"""Add batch identities for active people in the Misty staging directory."""

import argparse
import base64
import grp
import json
import logging
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

LOG = logging.getLogger("rain")
MAX_ROSTER_BYTES = 8 * 1024 * 1024
NOLOGIN = "/usr/sbin/nologin"
UID_MIN, UID_MAX = 30000, 39999
LABEL = re.compile(r"[a-z][a-z0-9_-]{0,30}")
KEY = re.compile(r"[!-~]{16,256}")


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
        try:
            person = UUID(value) if isinstance(value, str) else None
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


def username(person):
    return "msty-" + base64.b32encode(person.bytes).decode("ascii").rstrip("=").lower()


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
        or entry.pw_shell != NOLOGIN
        or entry.pw_dir != "/nonexistent"
    ):
        raise SyncError("refusing to reuse a conflicting Linux user")
    return True


def add_local_user(name, person):
    run(
        "/usr/sbin/useradd",
        "-M",
        "-U",
        "-l",
        "-d",
        "/nonexistent",
        "-s",
        NOLOGIN,
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


def reconcile(people, cluster, account, dry_run=False):
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
