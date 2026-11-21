# Misty staging → Slurm

`rain.service` runs the `rain` command with Python 3.10+ and no runtime dependencies.
Every five minutes it reads the Misty staging roster and, for each active person,
creates a local user account and a Slurm association on cluster `rain`, account
`misty-staging`. Usernames are `msty-` plus a clean slug derived from the person's name
(e.g. `msty-alovelace` for Ada Lovelace), falling back to an 8-character base32 hash if
no name is provided. Users get SSH access to the cluster with login shell `/bin/bash`
and home directory `/home/<username>`. The service does not set passwords, assign
admin roles, or delete existing users. Offboarding is a separate admin action.

## Build and test

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked rain --help
uv run --locked rain web --help
uv build
```

The Linux Nix flake builds the same Python package and runs its tests. Use
`nix build` for `result/bin/rain`, `nix run . -- --help` to try the command, or
`nix develop` for a shell with Python and uv. Enable the `nix-command` and
`flakes` experimental features if your Nix installation requires it. Keep
roster exports and credentials outside the checkout and out of the Nix store.

## Deploy on the Slurm host

Use the automated deploy script [`deploy/deploy.sh`](deploy/deploy.sh):

```sh
# Deploy directly on the local Slurm host (elevates with sudo):
./deploy/deploy.sh

# Or deploy to a remote Slurm node over SSH:
./deploy/deploy.sh <user@slurm-host>
```

The script automatically builds the release wheel, provisions the Python environment in `/usr/local/lib/misty-slurm-sync/venv`, installs `rain` and `rain-web`, configures `/etc/misty-slurm-sync` and `/var/lib/rain/keys`, installs both systemd services (`rain.service` and `rain-web.service`), reloads the systemd daemon, and restarts the services.

Leave `/etc/misty-slurm-sync/` intact on upgrades; for a new install, edit `/etc/misty-slurm-sync/sync.env` (seeded from [`deploy/sync.env.example`](deploy/sync.env.example)) to configure your staging credentials and cluster options.

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

## Access portal webpage

Rain includes a lightweight, zero-dependency self-service web portal for requesting compute access and verifying permissions against Misty staging:

```sh
# Start with rain web
rain web --port 8080

# Or run with uv
uv run rain-web --port 8080
```

The portal connects to the Misty Gateway (`MISTY_GATEWAY_URL`) using an external consumer key (`MISTY_GATEWAY_API_KEY`):
- **Request access flow:** Users enter their UTMIST primary email. Misty Gateway dispatches a 6-digit confirmation code (`/v1/auth/email/start`). Submitting the code together with their OpenSSH public key (`/v1/auth/email/confirm`) verifies membership, validates the `misty:staging` issuer, and confirms current active status (`/v1/auth/people/{person_id}/status`).
- **Slurm and SSH identity:** The user's stable Slurm username related to their name (`msty-<name>`, e.g. `msty-alovelace`), cluster (`rain`), account (`misty-staging`), and login shell (`/bin/bash`) are configured. Their provided SSH public key is installed in `~/.ssh/authorized_keys` and `/var/lib/rain/keys/<username>.pub` for direct SSH login into the box with Slurm.
- **Key management:** Users can add or update their SSH public key anytime directly from the portal interface.
- **Direct permission check:** Operators or users can directly query any Misty Person UUID to verify active status and SSH key configuration in the staging directory.
- **Systemd service:** Deploy with [`deploy/rain-web.service`](deploy/rain-web.service).
