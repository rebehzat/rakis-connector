"""Public server connector. All security actions belong in the dashboard."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from acsc_cli import agent
from acsc_cli.background import BackgroundError, manage, stop_if_installed
from acsc_cli.client import Client, ClientError
from acsc_cli.config import Config, disconnect, load, save
from acsc_cli.configuration import inspect
from acsc_cli.hostcheck import collector, privileged

HOST_CHECK_EVERY_S = 6 * 3600
ATTEST_EVERY_S = 24 * 3600


def _interval(value: str) -> int:
    try:
        interval = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("interval must be between 30 and 300 seconds") from None
    if not 30 <= interval <= 300:
        raise argparse.ArgumentTypeError("interval must be between 30 and 300 seconds")
    return interval


def _collect(use_sudo: bool) -> dict[str, Any]:
    return collector.collect(privileged.runner()) if use_sudo else collector.collect()


def _agent_tick(
    identity: agent.AgentIdentity, last_checks: float, last_attest: float
) -> tuple[float, float]:
    """Periodic opt-in agent work. Failures are reported and retried next period."""
    now = time.monotonic()
    if now - last_attest >= ATTEST_EVERY_S:
        last_attest = now
        try:
            due = agent.attest(identity)
            print(json.dumps({"attested": True, "reverify_due_at": due}), flush=True)
        except ClientError as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr, flush=True)
    if now - last_checks >= HOST_CHECK_EVERY_S:
        last_checks = now
        try:
            result = agent.publish_host_checks(identity, _collect(identity.sudo_queries))
            print(json.dumps({"host_checks": result}), flush=True)
        except ClientError as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr, flush=True)
    return last_checks, last_attest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rakis", description="Connect this server to Rakis. Manage security in your dashboard."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        / "rakis"
        / "config.json",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    connect = sub.add_parser("connect", help="connect with a server token from the dashboard")
    connect.add_argument("--api-url", required=True)
    connect.add_argument("--allow-local-http", action="store_true")
    connect.add_argument("--no-store", action="store_true")
    connect.add_argument(
        "--config-root",
        action="append",
        default=[],
        help="opt in to read-only local configuration checks in this folder",
    )
    connect.add_argument(
        "--watch", action="store_true", help="keep the connection alive until stopped"
    )
    connect.add_argument("--interval", type=_interval, default=60)
    connect.add_argument(
        "--ai", action="store_true", help="opt in to AI review of safe configuration warnings"
    )
    scan = sub.add_parser(
        "scan", help="inspect saved configuration folders; never scan server networks"
    )
    scan.add_argument(
        "--ai", action="store_true", help="request AI review of safe warnings for this check"
    )
    run = sub.add_parser("run", help="keep a saved connection alive in the foreground")
    run.add_argument("--interval", type=_interval, default=60)
    background = sub.add_parser("background", help="manage your non-root background connector")
    background.add_argument("action", choices=["start", "status", "stop"])
    background.add_argument("--interval", type=_interval, default=60)
    enroll = sub.add_parser(
        "enroll", help="opt in: prove this server's address with a dashboard enrollment token"
    )
    enroll.add_argument("--api-url", required=True)
    enroll.add_argument("--org-id", type=uuid.UUID, required=True)
    enroll.add_argument("--asset-id", type=uuid.UUID, required=True)
    enroll.add_argument("--allow-local-http", action="store_true")
    sub.add_parser("attest", help="re-prove this server's address with the enrolled key")
    host = sub.add_parser(
        "host-checks", help="send read-only package, listener, sshd and firewall checks"
    )
    host.add_argument(
        "--dry-run", action="store_true", help="print the report locally and send nothing"
    )
    host.add_argument(
        "--sudo-queries",
        choices=["on", "off"],
        help="use the optional sudoers drop-in for root-only read queries",
    )
    host.add_argument(
        "--remember", action="store_true", help="save --sudo-queries for background runs"
    )
    sudoers = sub.add_parser(
        "sudoers-file", help="print the optional least-privilege sudoers drop-in; installs nothing"
    )
    sudoers.add_argument("--user", help="user the connector runs as (default: current user)")
    sub.add_parser("status", help="check the saved connection without starting any work")
    sub.add_parser("disconnect", help="remove the local token; revoke it in the dashboard")
    args = parser.parse_args(argv)
    client = None
    try:
        if args.command == "background":
            print(json.dumps(manage(args.action, args.config, args.interval)))
            return 0
        if args.command == "scan":
            cfg = load(args.config, use_environment=False)
            if not cfg.config_roots:
                raise BackgroundError(
                    "Select configuration folders first with connect --config-root"
                )
            client = Client(cfg)
            print(
                json.dumps(
                    client.configuration(
                        inspect(cfg.config_roots),
                        ai=args.ai or cfg.ai_configuration,
                        retry_ai=args.ai,
                    )
                )
            )
            return 0
        identity_path = agent.default_path(args.config)
        if args.command == "enroll":
            credential = SecretStr(
                os.environ.get("RAKIS_ENROLL_TOKEN") or getpass.getpass("Agent enrollment token: ")
            )
            identity = agent.enroll(
                api_url=args.api_url,
                org_id=args.org_id,
                asset_id=args.asset_id,
                enrollment_token=credential,
                allow_local_http=args.allow_local_http,
            )
            agent.save_identity(identity_path, identity)
            print(json.dumps({"enrolled": True, "asset_id": str(identity.asset_id)}))
            return 0
        if args.command == "attest":
            due = agent.attest(agent.load_identity(identity_path))
            print(json.dumps({"attested": True, "reverify_due_at": due}))
            return 0
        if args.command == "sudoers-file":
            print(privileged.sudoers_text(args.user or getpass.getuser()), end="")
            return 0
        if args.command == "host-checks":
            if args.remember and args.sudo_queries is None:
                raise BackgroundError("--remember needs --sudo-queries on or off")
            stored: agent.AgentIdentity | None = None
            if not args.dry_run or args.remember or identity_path.exists():
                stored = agent.load_identity(identity_path)
            use_sudo = (
                args.sudo_queries == "on"
                if args.sudo_queries is not None
                else bool(stored and stored.sudo_queries)
            )
            if stored is not None and args.remember:
                stored = stored.model_copy(update={"sudo_queries": use_sudo})
                agent.save_identity(identity_path, stored)
            report = _collect(use_sudo)
            if args.dry_run:
                print(json.dumps(agent.report(report)))
                return 0
            assert stored is not None
            print(json.dumps(agent.publish_host_checks(stored, report)))
            return 0
        if args.command == "disconnect":
            stop_if_installed(args.config)
            disconnect(args.config)
            print(json.dumps({"disconnected": True, "token_revocation": "dashboard"}))
            return 0
        if args.command in {"connect", "run"}:
            if args.command == "connect":
                if args.ai and not args.config_root:
                    raise BackgroundError(
                        "AI review requires a chosen folder: use --config-root with --ai"
                    )
                credential = SecretStr(
                    os.environ.get("RAKIS_CONNECT_TOKEN")
                    or getpass.getpass("Server connection token: ")
                )
                cfg = Config(
                    api_url=args.api_url,
                    token=credential,
                    allow_local_http=args.allow_local_http,
                    config_roots=args.config_root,
                    ai_configuration=args.ai,
                )
            else:
                cfg = load(args.config, use_environment=False)
            observations = inspect(cfg.config_roots) if cfg.config_roots else None
            client = Client(cfg)
            result = client.heartbeat()
            if args.command == "connect" and not args.no_store:
                save(args.config, cfg)
            print(
                json.dumps({**result, "stored": args.command == "run" or not args.no_store}),
                flush=True,
            )
            if observations is not None:
                print(
                    json.dumps(client.configuration(observations, ai=cfg.ai_configuration)),
                    flush=True,
                )
            enrolled = (
                agent.load_identity(identity_path)
                if args.command == "run" and identity_path.exists()
                else None
            )
            last_checks = last_attest = float("-inf")
            while args.command == "run" or args.watch:
                if enrolled is not None:
                    last_checks, last_attest = _agent_tick(enrolled, last_checks, last_attest)
                time.sleep(args.interval)
                print(json.dumps(client.heartbeat()), flush=True)
                if cfg.config_roots:
                    current = inspect(cfg.config_roots)
                    if current != observations:
                        print(
                            json.dumps(client.configuration(current, ai=cfg.ai_configuration)),
                            flush=True,
                        )
                        observations = current
            return 0
        client = Client(load(args.config))
        print(json.dumps(client.status()))
        return 0
    except ClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return exc.code
    except (OSError, ValueError, EOFError) as exc:
        print(
            json.dumps(
                {
                    "error": str(exc)
                    if isinstance(exc, BackgroundError)
                    else "Invalid or unavailable connection configuration"
                }
            ),
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        if client:
            client.close()
