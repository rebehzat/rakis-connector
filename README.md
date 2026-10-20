# Rakis server connector

Connect your server to Rakis, keep it visible after logout, and review optional
configuration warnings in your dashboard. The connector runs as your normal user
and manages only its own connection service. It cannot apply fixes or control your
server's workloads.

## Install or upgrade

Requires Python 3.12+ and [pipx](https://pipx.pypa.io/stable/installation/).

```sh
pipx install https://github.com/rebehzat/rakis-connector/releases/download/v0.4.0/rakis_connector-0.4.0-py3-none-any.whl
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

Before enabling lingering, start checks the user service directory. If your account
owns it, the connector adds owner access and removes group/other write permission.
If another account owns it, the error reports the owner and gives a command to repair
only that directory. Run `rakis` again as your normal user, without `sudo`.

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

## Optional device protection

Enable **Include device protection scanning** when creating the key, then
choose the files and folders to check:

```sh
rakis connect --api-url https://api.rakis.com.tr --device-path /srv/www
rakis background start
```

Repeat `--device-path` for up to sixteen files or folders. `--device-path` and
`--config-root` can be used together. The connector downloads the ClamAV
signature database itself into a private local cache
(`~/.cache/rakis/clamav/`, readable only by your account) and refreshes it at
most once a day. Your server does not need ClamAV installed and the
connector never sends anything to a third party for scanning.

To run a one-off device scan:

```sh
rakis device scan --path /srv/www
rakis device scan --path /srv/www --path /home/me/downloads
```

Without `--path` the saved device paths are used. The command prints a short
summary: files scanned, detections and the signature database version. The
background connector repeats the device scan next to the configuration check
and uploads a new report only when the report changed.

The connector reads only files your account can read, never follows links and
never leaves the chosen paths. Rakis receives the signature name, a relative
path label such as `root-1/www/shell.php`, the file size, the match type and
the coverage counters. File content, file hashes and the list of scanned files
never leave the server; only the names of the known-bad signatures do. The
connector never deletes, quarantines or repairs a file. Detections appear in
the dashboard.

**Coverage limitation:** the connector matches whole-file hashes (MD5, SHA1 and
SHA256) and nucleic section hashes against the signature database. It does not
evaluate ClamAV bytecode (`.cvd`/`.cld`) signatures, does not match `.ftm` magic
files, does not unpack archives, does not run heuristic or behavioural analysis
and does not use a `clamd` daemon. A file that only matches a bytecode, magic
or heuristic signature is not reported, so a clean device scan is not proof that
the server is free of malware. Files that are links, special files, too large,
unreadable or outside the chosen paths stay outside the coverage, and the
report then marks the coverage as partial.

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
