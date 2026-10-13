# Rakis connector

Install the passive server connector without access to Rakis's private repository.
Requires Python 3.12+ and [pipx](https://pipx.pypa.io/stable/installation/).

```sh
pipx install https://github.com/rebehzat/rakis-connector/releases/download/v0.2.0/rakis_connector-0.2.0-py3-none-any.whl
```

In your Rakis dashboard, add a server and create a connection key. To inspect
configuration, enable **Include configuration checks** for that key, then run:

```sh
rakis connect --api-url https://api.rakis.com.tr --config-root /etc --watch
```

Enter the key at the masked prompt. Use your own HTTPS API address for self-hosted
Rakis. Omit `--config-root` for connection updates only. Repeat the option to choose
up to eight configuration folders.

The connector reads local configuration and sends fixed risk identifiers plus file
metadata. Raw contents, environment values, password values and matched text stay
on the server. It does not execute commands, change configuration, or control the
server. The dashboard handles findings and revoking access.

Supported filenames include dotenv, YAML, JSON, TOML, INI, nginx, Apache, systemd,
Docker, Kubernetes, Terraform and XML. Checks cover common risky patterns, including
embedded credentials, insecure permissions, disabled TLS, debug mode, wildcard CORS,
privileged containers and public listeners. They are bounded heuristic checks, not
an exhaustive security assessment. Skipped files and partial coverage are reported.
Configuration inspection currently requires POSIX safe file access.

The default limits are 250 files, 256 KiB per file and 16 MiB per inspection. Symlinks,
hardlinks, private key files, binary files and virtual system roots are excluded.
No raw configuration is uploaded and these checks make no paid AI calls.

```sh
rakis status
rakis disconnect
```

`disconnect` removes the saved local key; stop the running connector and revoke its
key in the dashboard to end access completely. Tokens expire and remain bound to
one server. Existing `acsc` installations expose the same commands after upgrading;
the old scan/control commands have been removed.

Download the wheel and SHA-256 checksum from [Releases](https://github.com/rebehzat/rakis-connector/releases).
Only the client distribution is public here. The Rakis backend repository stays
private. Public installation is separate from server API access: connecting requires
a Rakis backend release that supports connection/configuration tokens.

Proprietary software, all rights reserved. Public distribution is not an open-source
license. Do not share connection keys in issues or command arguments.
