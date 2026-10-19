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

## Optional agent enrollment and host checks

Enrollment is opt in. It proves to the dashboard that this server controls its own
public address, and lets the connector send read-only host checks. Create an
enrollment token for the server in the dashboard, then run on that server:

```bash
rakis enroll --api-url https://api.example --org-id ORG_ID --asset-id ASSET_ID
```

The token is read from a masked prompt (or `RAKIS_ENROLL_TOKEN`). The connector
generates an Ed25519 key on this server, signs the one-time challenge the
dashboard issues for the address it sees, and stores the key and the released
agent token in a private `agent.json` (0600) next to `config.json`. Neither is ever
printed.

```bash
rakis host-checks --dry-run   # print the report locally, send nothing
rakis host-checks             # send the report to the dashboard
rakis attest                  # re-prove the address before it lapses
```

Host checks run only a fixed list of read-only queries (`dpkg-query` or `rpm`,
`ss`, `sshd -T`, `nft`, `ufw`, `iptables`) with no shell, a minimal environment,
a timeout and an output cap. The dashboard never sends commands and nothing in a
response decides what runs. Only installed package names and versions, listening
sockets, an allowlist of effective sshd settings and a firewall summary are sent.
Queries that need root report "not collected" when the connector runs as a normal
user, unless you opt in to the sudoers drop-in below. When enrolled, `rakis run` (and the background service) attests once a day
and sends host checks every six hours.

### Inbound reachability (for agent-proof port checks)

Port checks on a server proven only by enrollment also need proof that the
address reaches this server inbound (not just a shared NAT it sends through):

```bash
rakis reachability            # one check; exit 0 on success
rakis reachability --remember # after a success, repeat it daily from background runs
```

The dashboard picks a port in 47800-47899 and a one-time nonce. The connector
listens on that port for up to a minute, serves one signed line to whoever
connects, reads nothing and closes. Allow inbound TCP 47800-47899 to this
server while the check runs. The dashboard never sends a target or command.

### Optional: root-only queries without running as root

`sshd -T`, `nft`, `ufw` and `iptables` need root. The connector never runs as
root and never changes sudo configuration. If you want those sections, you can
install a sudoers drop-in yourself that allows your connector user to run
exactly these four read-only command lines and nothing else:

```text
USER ALL=(root) NOPASSWD: /usr/sbin/sshd -T, /usr/sbin/nft list ruleset, /usr/sbin/ufw status verbose, /usr/sbin/iptables -S
```

```bash
rakis sudoers-file > rakis-hostcheck          # prints the drop-in for your user; writes nothing
sudo visudo -cf rakis-hostcheck               # syntax check
sudo install -m 0440 -o root -g root rakis-hostcheck /etc/sudoers.d/rakis-hostcheck
rakis host-checks --dry-run --sudo-queries on # see what would be sent
rakis host-checks --sudo-queries on --remember  # also use it for background runs
```

`docs/sudoers/rakis-hostcheck.example` is the same file for the user `rakis`.
Check the program paths with `command -v sshd nft ufw iptables` first; a
program at another path is simply not granted. The connector calls only
`/usr/bin/sudo -n -- <one of the four lines>`, never prompts, and falls back
to the unprivileged attempt when sudo is not granted. Remove the file with
`sudo rm /etc/sudoers.d/rakis-hostcheck` to stop.

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
