# Misty staging → Slurm

`rain.service` runs the `rain` command with Python 3.10+ and no runtime dependencies.
Every five minutes it reads the Misty staging roster and, for each active person,
creates a local batch identity and a Slurm association on cluster `rain`, account
`misty-staging`. Usernames are `msty-` plus the lowercase, unpadded base32 of the
Misty person UUID. They are stable across name and email changes. The service
does not grant SSH access, set passwords, assign admin roles, create home
directories, or delete existing users. Offboarding is a separate admin action.

## Build and test

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked rain --help
uv build
```

The Linux Nix flake builds the same Python package and runs its tests. Use
`nix build` for `result/bin/rain`, `nix run . -- --help` to try the command, or
`nix develop` for a shell with Python and uv. Enable the `nix-command` and
`flakes` experimental features if your Nix installation requires it. Keep
roster exports and credentials outside the checkout and out of the Nix store.

## Deploy on the Slurm host

Build with `uv build` and copy the wheel and [`deploy/rain.service`](deploy/rain.service)
to the Ubuntu Slurm host. Run the following as root from the directory containing
those files, with uv available. Slurm, SlurmDBD, and MUNGE are host services;
neither uv nor Nix is needed to run the installed unit.

```sh
install -d -m 0755 /usr/local/lib/misty-slurm-sync
# Only create the virtual environment on the first install.
test -x /usr/local/lib/misty-slurm-sync/venv/bin/python || \
  uv venv --no-project --python /usr/bin/python3 /usr/local/lib/misty-slurm-sync/venv
uv --offline pip install --no-deps \
  --python /usr/local/lib/misty-slurm-sync/venv/bin/python ./rain-0.1.0-py3-none-any.whl
install -m 0644 rain.service /etc/systemd/system/rain.service
systemctl daemon-reload
systemctl enable rain.service
systemctl restart rain.service
```

Use the wheel for the intended release. Leave `/etc/misty-slurm-sync/` intact
on upgrades; for a new install, create it as root with mode `0700` and use
[`deploy/sync.env.example`](deploy/sync.env.example) as a starting point.

## Connect a staging roster

In [`../misty`](../misty), the staging `team-tracking` service has
`GET /people?active_only=true` (`people:read`), but lives on Railway's private
network. The public gateway currently has no roster endpoint. Neither deploy
the internal directory publicly nor copy internal keys or database credentials
to this host. Use one of these sources in `/etc/misty-slurm-sync/sync.env`:

- **Export:** Set `MISTY_STAGING_ROSTER=/etc/misty-slurm-sync/people.json`.
  An authorized staging operator or scheduled exporter can fetch the roster
  inside Railway, keep only `id` and `active`, and publish the complete JSON
  array atomically. Stage the file under a different name with owner `root`
  and mode `0600` in the same directory, then rename it over `people.json`.
  The service reads the latest file on each pass. Example shape (dummy ID):
  ```json
  [{"id":"550e8400-e29b-41d4-a716-446655440000","active":true}]
  ```
- **HTTPS:** Set `MISTY_STAGING_URL=https://<approved-staging-roster-host>`
  (a base URL, optionally with a path prefix). This requires a purpose-built
  staging roster relay or gateway operation, not supplied by this repo. It
  must provide the same JSON array at `GET /people?active_only=true` using
  a dedicated read-only `X-API-Key`. Store that key in
  `/etc/misty-slurm-sync/staging-api-key` as root, mode `0600`, and use
  `sudo systemctl edit rain.service` to add:
  ```ini
  [Service]
  LoadCredential=staging-api-key:/etc/misty-slurm-sync/staging-api-key
  ```

Restart after configuration changes and check the result:

```sh
sudo systemctl restart rain.service
journalctl -u rain.service -n 30 --no-pager
sudo sacctmgr -nP show assoc where Cluster=rain Account=misty-staging format=User%32,Account%32
```

With neither source configured, the unit runs but creates no users. With a
source configured, malformed or unavailable input creates no users that pass;
the service logs the error and retries. Repeated successful passes don't
recreate existing users. Stopping the service does not remove accounts or
change accounting history.

To preview a local export before enabling it:

```sh
sudo env MISTY_STAGING_ROSTER=/etc/misty-slurm-sync/people.json \
  /usr/local/lib/misty-slurm-sync/venv/bin/rain --dry-run
```
