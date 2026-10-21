# Indo Raya Tenaga NTP Server Dashboard

Web dashboard for a chrony NTP server: live server health, NTP client statistics
grouped by subnet, and time-history charts derived from chrony's own logs.

The application is based on the open-source **TICC-DASH** project by Anoniemerd
([github.com/anoniemerd/ticc-dash](https://github.com/anoniemerd/ticc-dash),
[ticc-dash.org](https://ticc-dash.org)), MIT licensed, rebranded and extended
for Indo Raya Tenaga.

## Features

- NTP server health: sync state, stratum, reference source, offset, frequency
- Client overview cards (healthy, warning, stale) that open a popup listing the
  matching clients
- Clients grouped by subnet, collapsed by default
- Time History: tracking/statistics charts plus a paginated table
  (20 rows per page) with a separate UTC+7 timestamp column
- Built-in documentation page
- No CDN dependencies, so it works on an isolated network

## Architecture

chrony runs **on the host**. The container never touches the system clock; it
only queries chronyd and reads its logs.

| Host path | Container path | Mode | Purpose |
| --- | --- | --- | --- |
| `/run/chrony` | `/run/chrony` | rw | `chronyc` command socket |
| `/var/log/chrony` | `/var/log/chrony` | ro | Time History |

Host requirements:

- chrony 4.3 (Debian 12 ships the same version as the container)
- chrony logging enabled in `/etc/chrony/chrony.conf`:

  ```
  log tracking measurements statistics
  ```

- a `_chrony` user, whose uid/gid the container runs as

The container runs as the host's `_chrony` user because `chronyc clients` is
only permitted for root or the chrony user. It uses a read-only root filesystem,
drops all capabilities, and publishes only on host loopback.

## Run

```sh
docker compose up -d --build --wait
docker compose ps
docker compose logs -f
```

The dashboard listens on `127.0.0.1:5005` and is not exposed directly. Put a
reverse proxy in front of it:

```nginx
location / {
    proxy_pass http://127.0.0.1:5005;
}
```

### Host uid/gid

`docker-compose.yml` uses `user: "113:122"`, the Debian `_chrony` account.
Check yours with:

```sh
id _chrony
```

and adjust the compose file if it differs.

### Building behind a restrictive firewall

The compose file sets `build.network: host` because the build must reach the
Debian and PyPI mirrors, and the host firewall may drop forwarded bridge
traffic. Remove it if your Docker bridge has working egress.

## Development

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python ticc-dash.py          # serves on 0.0.0.0:5000
```

`chronyc` and chrony's logs must be available on the machine for live data.

## Credits and license

Based on **TICC-DASH** by Anoniemerd:

- https://github.com/anoniemerd/ticc-dash
- https://ticc-dash.org
- MIT License, Copyright (c) 2025 anoniemerd

Modifications for Indo Raya Tenaga are released under the same MIT License.
See [LICENSE](LICENSE).
