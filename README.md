# Rakis server connector

Connect your server to Rakis, keep it visible after logout, and review optional
configuration warnings in your dashboard. The connector runs as your normal user
and manages only its own connection service. It cannot apply fixes or control your
server's workloads.

## Install or upgrade

Requires Python 3.12+ and [pipx](https://pipx.pypa.io/stable/installation/).

```sh
pipx install https://github.com/rebehzat/rakis-connector/releases/download/v0.3.0/rakis_connector-0.3.0-py3-none-any.whl
```

If you already installed the connector, use `pipx install --force` with the same
URL, then restart it with `rakis background start`. Your saved connection stays
on your server. Wheels and SHA-256 checksums are available in
[Releases](https://github.com/rebehzat/rakis-connector/releases).

## Connect and keep running

Add your server in the dashboard and create a connection key. Run:

```sh
rakis connect --api-url https://api.rakis.com.tr
rakis background start
rakis background status
```

Enter the key at the masked prompt. For self-hosted Rakis, use your own HTTPS API
address. Do not put connection keys in command arguments or issues.

Background operation requires Linux with systemd. Do not use sudo: the service runs
with your account's permissions, and credentials stay in a private saved file.
The connector verifies user lingering so it can survive logout and start after a
reboot. If your host permits it, lingering is enabled for your own account without
root. Some hosts require an administrator to enable it once; the connector explains
that requirement rather than claiming it can stay running without it.

## Optional configuration and AI review

Enable **Include configuration checks** when creating the key, then choose a folder:

```sh
rakis connect --api-url https://api.rakis.com.tr --config-root /path/to/configuration --ai
rakis background start
```

Omit `--ai` for local rule checks only. Repeat `--config-root` for up to eight folders.
The connector reads only files your account can access. It recognizes common
configuration formats and reports bounded heuristic warnings, including insecure
permissions, credential-like assignments, disabled TLS, debug settings, permissive
CORS, privileged containers and public listeners. Skipped files remain outside its
coverage; these checks do not establish complete server security.

Raw configuration, passwords, environment values and matching text stay local.
Rakis receives fixed warning identifiers and limited file metadata. Optional AI
receives anonymous warning identifiers, without file contents or filenames, and
adds guidance for recorded warnings. It uses your workspace's AI token allowance
and never executes fixes. Follow its queued or completed result in the dashboard.

To request one AI review using your saved folders:

```sh
rakis scan --ai
```

This can retry an incomplete AI review after the service is restored. Reviews that
are already queued, running or successful remain deduplicated. Background checks
never automatically retry incomplete AI, so unchanged observations do not repeatedly
spend tokens. A one-time `scan --ai` does not enable AI for future background checks.

## Check or stop

```sh
rakis status
rakis background stop
rakis disconnect
```

`status` checks the saved connection once. `background stop` stops only the connector
and keeps its key. `disconnect` stops the managed background connector before
removing its saved key. Stop any separately started foreground connector with Ctrl+C
and revoke the key in the dashboard to remove access completely.

`rakis run` starts the saved connection in your current terminal; closing that
terminal stops it. To inspect background status, use `systemctl --user status
rakis-connector` or `journalctl --user -u rakis-connector`.

Only the client distribution is public here. The server API requires a valid
connection key. Proprietary software, all rights reserved; public distribution is
not an open-source license.


## Develop and build

The source here is the standalone connector. Python 3.12+ is required.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python build_public_release.py
python -m pytest
python -m ruff check .
```

The build writes an allowlist-checked wheel, SHA-256 checksum, and release metadata
to `dist/`. It does not publish a release. The `acsc_cli` module and legacy `acsc`
entry point remain compatible with existing installations. Tests use synthetic
fixtures and mocked API/service calls; no Rakis account is required.

Public source availability does not grant an open-source license. The existing
proprietary terms remain in effect. Server AI prompts, model routing, analysis
pipelines, scan engines, customer data and deployment configuration are excluded.
