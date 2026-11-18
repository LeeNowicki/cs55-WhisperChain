"""Server command line: init, init-admin, run.

    python -m whisperchain.server init
    python -m whisperchain.server init-admin
    python -m whisperchain.server run
"""

import argparse
import sys
from pathlib import Path

from whisperchain.common.prompt import prompt_new_secret
from whisperchain.server.config import ServerPaths
from whisperchain.server.initialize import create_admin, initialize_data_dir


def cmd_init(args) -> int:
    paths = initialize_data_dir(args.data_dir)
    print(f"Initialized server data in {paths.data_dir}")
    print(f"TLS certificate (give this to clients): {paths.tls_cert}")
    return 0


def cmd_init_admin(args) -> int:
    paths = ServerPaths(args.data_dir)
    if not paths.db.exists():
        print("Server is not initialized; run `init` first.", file=sys.stderr)
        return 1
    # No defaults anywhere: the operator must choose both values.
    username = input("Admin username: ").strip()
    password = prompt_new_secret("password", "Admin password (min 12 chars): ")
    create_admin(paths, username, password)
    print(f"Admin account '{username}' created.")
    return 0


def cmd_run(args) -> int:
    import uvicorn

    from whisperchain.server.app import create_app

    paths = ServerPaths(args.data_dir)
    if not paths.tls_cert.exists() or not paths.tls_key.exists():
        print("TLS certificate missing; run `init` first.", file=sys.stderr)
        return 1
    app = create_app(paths.data_dir)
    print(f"WhisperChain+ server on https://{args.host}:{args.port}")
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=str(paths.tls_cert),
        ssl_keyfile=str(paths.tls_key),
        access_log=False,       # access logs would record client IPs per request
        log_level="warning",
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m whisperchain.server")
    parser.add_argument(
        "--data-dir", type=Path, default=Path("server_data"),
        help="server data directory (default: ./server_data)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create database, secrets, and TLS certificate").set_defaults(
        func=cmd_init
    )
    sub.add_parser("init-admin", help="create an Admin account (host only)").set_defaults(
        func=cmd_init_admin
    )
    run = sub.add_parser("run", help="start the HTTPS server")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8443)
    run.set_defaults(func=cmd_run)
    return parser


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    args.data_dir = args.data_dir.expanduser()
    try:
        return args.func(args)
    except (ValueError, FileExistsError) as exc:
        # Plain message, no stack trace (and never any secret values).
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
