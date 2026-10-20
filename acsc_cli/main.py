"""Public server connector. All security actions belong in the dashboard."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from pydantic import SecretStr

from acsc_cli.background import BackgroundError, manage, stop_if_installed
from acsc_cli.clamav import ClamavDatabase, ClamavError
from acsc_cli.client import Client, ClientError
from acsc_cli.config import Config, disconnect, load, save
from acsc_cli.configuration import inspect
from acsc_cli.device import MAX_ROOTS
from acsc_cli.device import scan as device_scan

# The device scan hashes every chosen file. It repeats on its own slower
# cadence so a background connector does not keep a busy server busy.
DEVICE_RESCAN_SECONDS = 600


def _interval(value: str) -> int:
    try:
        interval = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("interval must be between 30 and 300 seconds") from None
    if not 30 <= interval <= 300:
        raise argparse.ArgumentTypeError("interval must be between 30 and 300 seconds")
    return interval


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
        "--device-path",
        action="append",
        default=[],
        help="opt in to local malware signature checks for this file or folder",
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
    device = sub.add_parser(
        "device", help="device protection with a local malware signature database"
    )
    device_commands = device.add_subparsers(dest="device_command", required=True)
    device_scan_parser = device_commands.add_parser(
        "scan", help="scan chosen files and folders for known malware signatures"
    )
    device_scan_parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="file or folder to scan; repeat for more than one",
    )
    run = sub.add_parser("run", help="keep a saved connection alive in the foreground")
    run.add_argument("--interval", type=_interval, default=60)
    background = sub.add_parser("background", help="manage your non-root background connector")
    background.add_argument("action", choices=["start", "status", "stop"])
    background.add_argument("--interval", type=_interval, default=60)
    sub.add_parser("status", help="check the saved connection without starting any work")
    sub.add_parser("disconnect", help="remove the local token; revoke it in the dashboard")
    args = parser.parse_args(argv)
    client = None
    database = None
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
        if args.command == "device":
            cfg = load(args.config, use_environment=False)
            paths = args.path or cfg.device_paths
            if not paths:
                raise BackgroundError(
                    "Select device paths first with connect --device-path "
                    "or rakis device scan --path"
                )
            if len(paths) > MAX_ROOTS:
                raise BackgroundError("Choose at most sixteen device paths")
            database = ClamavDatabase()
            report = device_scan(paths, database)
            client = Client(cfg)
            result = client.device_scan(report)
            print(
                json.dumps(
                    {
                        "job_id": result["job_id"],
                        "status": result["status"],
                        "changed": result["changed"],
                        "files_scanned": report["files_scanned"],
                        "directories_scanned": report["directories_scanned"],
                        "skipped_files": report["skipped_files"],
                        "complete": report["complete"],
                        "detections": len(report["detections"]),
                        "signature_db_version": report["signature_db"]["version"],
                    }
                )
            )
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
                if len(args.device_path) > MAX_ROOTS:
                    raise BackgroundError("Choose at most sixteen device paths")
                credential = SecretStr(
                    os.environ.get("RAKIS_CONNECT_TOKEN")
                    or getpass.getpass("Server connection token: ")
                )
                cfg = Config(
                    api_url=args.api_url,
                    token=credential,
                    allow_local_http=args.allow_local_http,
                    config_roots=args.config_root,
                    device_paths=args.device_path,
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
            if cfg.device_paths:
                database = ClamavDatabase()
                device_report = device_scan(cfg.device_paths, database)
                print(json.dumps(client.device_scan(device_report)), flush=True)
            else:
                device_report = None
            last_device_scan = time.monotonic()
            while args.command == "run" or args.watch:
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
                if (
                    cfg.device_paths
                    and time.monotonic() - last_device_scan >= DEVICE_RESCAN_SECONDS
                ):
                    # Hashing every chosen file is work for the server. The
                    # device scan repeats on its own slower cadence.
                    current = device_scan(cfg.device_paths, database)
                    last_device_scan = time.monotonic()
                    if current != device_report:
                        print(json.dumps(client.device_scan(current)), flush=True)
                        device_report = current
            return 0
        client = Client(load(args.config))
        print(json.dumps(client.status()))
        return 0
    except ClientError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return exc.code
    except ClamavError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
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
        if database:
            database.close()
