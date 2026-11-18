"""WhisperChain+ command-line client.

    python -m whisperchain.client [global flags] <command> ...

Global flags: --config-dir, --server URL, --ca-cert PATH, --insecure-dev.

Each `cmd_...` function below handles one command: it collects input
(prompting for secrets), calls the matching function in client/commands/,
and prints the result.
"""

import argparse
import sys
from pathlib import Path

from whisperchain.client.api import ApiClient, build_client_factory
from whisperchain.client.commands import account, admin, keys, messages, moderation, tokens
from whisperchain.client.commands import audit as audit_cmd
from whisperchain.client.display import sanitize
from whisperchain.client.errors import ClientError
from whisperchain.client.store import ClientStore, default_config_dir
from whisperchain.common import constants as C
from whisperchain.common.fingerprint import format_fingerprint
from whisperchain.common.prompt import prompt_new_secret, prompt_secret


def make_api(args, store: ClientStore, with_session: bool = False) -> ApiClient:
    """Build an ApiClient from saved config, overridden by global flags."""
    config = store.load_config()

    # A flag given on the command line wins over the saved setting.
    if args.server:
        server_url = args.server
    else:
        server_url = config.get("server_url")
    if args.ca_cert:
        ca_cert = args.ca_cert
    else:
        ca_cert = config.get("ca_cert")

    factory = build_client_factory(server_url, ca_cert, args.insecure_dev)

    token = None
    if with_session:
        session = store.load_session()
        if session is not None:
            token = session["token"]
    return ApiClient(factory, token=token)


def ask_yes_no(question: str) -> bool:
    """Ask on the terminal; only "y" (any case) counts as yes."""
    answer = input(question)
    return answer.strip().lower() == "y"


def fingerprint_or_none(fp) -> str:
    """Formatted fingerprint, or "(none)" if there is no fingerprint."""
    if fp:
        return format_fingerprint(fp)
    return "(none)"


# --- command handlers ---------------------------------------------------------

def cmd_configure(args, store):
    config = account.configure(store, args.server, args.ca_cert, args.send_delay)
    print(f"Saved configuration in {store.config_path}")
    for key in sorted(config):
        print(f"  {key}: {config[key]}")


def cmd_register(args, store):
    account.ensure_can_register(store)  # fail before asking for any secrets
    api = make_api(args, store)
    # Two different secrets: the password (sent to the server to log in) and
    # the passphrase (encrypts the private key locally; never sent anywhere).
    password = prompt_new_secret("password", "Account password (min 12 chars): ")
    passphrase = prompt_new_secret("passphrase", "Key passphrase (min 12 chars, different): ")
    print("Generating RSA-3072 key pair (this can take a few seconds)...")
    result = account.register(store, api, args.invite, args.username, password, passphrase)
    print(f"Registered '{result['username']}' with roles: {', '.join(result['roles'])}")
    print(f"Key ID:          {result['key_id']}")
    print(f"Key fingerprint: {format_fingerprint(result['fingerprint'])}")
    print("Keep your key passphrase safe: a lost private key means a lost inbox.")


def cmd_login(args, store):
    username = args.username
    if not username:
        identity = store.load_identity()
        if identity is None:
            raise ClientError("no saved identity; pass --username")
        username = identity["username"]
    api = make_api(args, store)
    password = prompt_secret("password", f"Password for {username}: ")
    result = account.login(store, api, username, password)
    print(f"Logged in as '{username}' (roles: {', '.join(result['roles'])})")


def cmd_admin_invite(args, store):
    result = admin.invite(make_api(args, store, with_session=True), args.role)
    # Shown once: the server stores only a hash and cannot show it again.
    print(f"Invite code (roles: {', '.join(result['roles'])}; expires {result['expires_at']}):")
    print(f"  {result['invite_code']}")
    print("Give this to the new user over a trusted channel. It works once.")


def cmd_admin_users(args, store):
    users = admin.list_users(make_api(args, store, with_session=True))
    # ljust(n) pads text with spaces on the right to n characters, and
    # rjust(n) on the left, so the columns line up.
    print("ID".rjust(4) + "  " + "USERNAME".ljust(32) + " " + "ACTIVE".ljust(7) + " ROLES")
    for user in users:
        if user["active"]:
            active = "yes"
        else:
            active = "no"
        roles = ", ".join(user["roles"])
        print(str(user["id"]).rjust(4) + "  " + user["username"].ljust(32) + " " + active.ljust(7) + " " + roles)


def cmd_admin_set_roles(args, store):
    result = admin.set_roles(make_api(args, store, with_session=True), args.username, args.role)
    print(f"Roles for '{args.username}' are now: {', '.join(result['roles'])}")


def cmd_admin_revoke_key(args, store):
    admin.revoke_key(make_api(args, store, with_session=True), args.key_id)
    print(f"Key {args.key_id} revoked. It no longer appears in the directory.")


def cmd_admin_start_round(args, store):
    result = admin.start_round(make_api(args, store, with_session=True))
    print(f"Round {result['round']} is now open. Tokens from earlier rounds no longer work.")


def cmd_admin_deactivate(args, store):
    admin.deactivate(make_api(args, store, with_session=True), args.username)
    print(f"Deactivated '{args.username}'. Their existing sessions stop working immediately.")


def cmd_token_request(args, store):
    result = tokens.request_token(store, make_api(args, store, with_session=True))
    print(f"Round {result['round']}: {result['status']}.")


def cmd_token_status(args, store):
    status = tokens.token_status(store, make_api(args, store))
    if status["open_round"] is None:
        print("Open round: (none)")
    else:
        print(f"Open round: {status['open_round']}")

    if len(status["tokens"]) == 0 and len(status["pending"]) == 0:
        print("No local tokens.")
    for token in status["tokens"]:
        if token["usable"]:
            state = "unspent, usable"
        else:
            state = "round closed, unusable"
        print(f"  round {token['round']}: {state}")
    for round_number in status["pending"]:
        print(f"  round {round_number}: request pending (run `token request` again to finish)")


def cmd_send(args, store):
    # Deliberately NOT make_api(..., with_session=True): the send path never
    # touches session.json, so nothing about our login can leak into it.
    api = make_api(args, store)
    message = args.message
    if message is None:
        if store.load_outbox() is None:
            message = input("Message: ")
        else:
            message = ""  # an earlier unconfirmed message will be resubmitted instead

    # Called by messages.send() just before it starts waiting.
    def on_wait(seconds):
        print(f"Waiting {round(seconds)} s before submitting, so the send time does not "
              "line up with your token request (use --now to skip)...", flush=True)

    result = messages.send(store, api, args.to, message, now=args.now, on_wait=on_wait)
    if result["status"] == "resubmitted":
        print(sanitize(f"Resubmitted your earlier unconfirmed message to {result['recipient']}; "
                       "it is now delivered. Your new message was NOT sent (one token per round)."))
    else:
        print(sanitize(f"Message sent anonymously to {result['recipient']}."))


def cmd_inbox(args, store):
    api = make_api(args, store, with_session=True)

    if args.show is None:
        # Just list the messages; nothing is decrypted.
        entries = messages.list_inbox(api)
        if len(entries) == 0:
            print("Inbox is empty.")
            return
        for entry in entries:
            print(f"  {entry['id']}  round {entry['round']}  {entry['status']}")
        print("Use `inbox --show ID` to decrypt a message.")
        return

    passphrase = prompt_secret("passphrase", "Key passphrase: ")
    result = messages.read_message(store, api, args.show, passphrase)
    print(f"Message {result['id']} (round {result['round']}):")
    if result["error"] is None:
        print(result["text"])
    else:
        print(f"[{result['error']}]")


def cmd_flag(args, store):
    api = make_api(args, store, with_session=True)
    passphrase = prompt_secret("passphrase", "Key passphrase: ")
    if args.reason is None:
        reason = ""
    else:
        reason = args.reason

    # Called by moderation.flag() once it knows which moderators get a copy.
    def confirm(moderator_names, skipped):
        for name in skipped:
            print(sanitize(f"WARNING: moderator {name}'s key does not match your pin; they will NOT get a copy."))
        if len(moderator_names) > 0:
            print(sanitize("These moderators will be able to read this message: " + ", ".join(moderator_names)))
        else:
            print("No moderator will be able to read this message (it is undecryptable or no trusted moderators).")
        if args.yes:
            return True
        return ask_yes_no("Flag it? [y/N]: ")

    result = moderation.flag(store, api, args.message_id, passphrase, reason, confirm)
    print(f"Flagged (flag id {result['flag_id']}); {result['moderator_copies']} moderator copies.")


def cmd_mod_queue(args, store):
    flags = moderation.queue(make_api(args, store, with_session=True))
    if len(flags) == 0:
        print("No flags.")
    for flag in flags:
        line = (f"  {flag['id']}  round {flag['round']}  " + flag["status"].ljust(9)
                + f"  {flag['created_at']}  {flag['reason']}")
        print(sanitize(line))


def cmd_mod_review(args, store):
    api = make_api(args, store, with_session=True)
    passphrase = prompt_secret("passphrase", "Key passphrase: ")
    result = moderation.review(store, api, args.flag_id, passphrase)
    print(sanitize(f"Flag {result['id']} (round {result['round']}, {result['status']}): reason: {result['reason']}"))
    if result["text"] is not None:
        print(result["text"])
    else:
        print(f"[{result['note']}]")


def cmd_mod_freeze(args, store):
    moderation.freeze(make_api(args, store, with_session=True), args.flag_id)
    print("Token frozen and flag marked actioned. (This cannot identify or block the sender in future rounds.)")


def cmd_mod_dismiss(args, store):
    moderation.dismiss(make_api(args, store, with_session=True), args.flag_id)
    print("Flag dismissed.")


def cmd_keys_sync(args, store):
    session = store.load_session()
    # Only Recipients may read moderator keys (needed for flagging); asking
    # without the permission would just produce an ACCESS_DENIED entry.
    include_moderators = False
    if session is not None and "Recipient" in session.get("roles", []):
        include_moderators = True

    results = keys.sync(store, make_api(args, store, with_session=True), include_moderators)
    something_changed = False
    for result in results:
        line = ("  [" + result["list"].ljust(10) + "] " + result["username"].ljust(32) + " "
                + result["status"].ljust(17) + " " + format_fingerprint(result["fingerprint"]))
        print(sanitize(line))
        if result["status"] == keys.STATUS_CHANGED or result["status"] == keys.STATUS_INVALID:
            something_changed = True
    print(f"Directory synced: {len(results)} entries.")
    if something_changed:
        print("\n*** WARNING: some keys CHANGED or are INVALID. Sending to those users is blocked.\n"
              "*** Compare fingerprints with them out of band before running `keys trust USER`.")


def cmd_keys_fingerprint(args, store):
    info = keys.fingerprint_info(store, args.username)
    print(sanitize(f"User:        {info['username']}"))
    print(f"Key ID:      {info['key_id']}")
    print(f"Fingerprint: {format_fingerprint(info['fingerprint'])}")
    if info["pinned"] != info["fingerprint"]:
        print(f"*** DOES NOT MATCH PIN: {fingerprint_or_none(info['pinned'])}")


def cmd_keys_trust(args, store):
    # Called by keys.trust() with the old (pinned) and new fingerprints.
    def confirm(old, new):
        print(sanitize(f"Key for {args.username} has changed."))
        print(f"  pinned (old): {fingerprint_or_none(old)}")
        print(f"  current (new): {format_fingerprint(new)}")
        print("Only accept if you confirmed the NEW fingerprint with this person out of band.")
        return ask_yes_no("Trust the new key? [y/N]: ")

    if keys.trust(store, args.username, confirm):
        print(sanitize(f"Now trusting the new key for {args.username}."))
    else:
        print("Pin unchanged.")


def print_entries(entries):
    for entry in entries:
        line = (str(entry["seq"]).rjust(6) + "  " + entry["timestamp"] + "  "
                + entry["action"].ljust(17) + " " + entry["role"].ljust(20) + " " + entry["detail"])
        # sanitize(): entries come from the server; never let them inject
        # terminal control sequences.
        print(sanitize(line))


def cmd_audit_verify(args, store):
    result = audit_cmd.verify(store, make_api(args, store, with_session=True))
    print(f"Audit log OK: {result['entries']} entries verified "
          f"(hash chain, signatures, checkpoint). Checkpoint now at seq {result['checkpoint_seq']}.")


def cmd_audit_show(args, store):
    entries = audit_cmd.show(make_api(args, store, with_session=True), args.tail)
    print_entries(entries)


def cmd_alerts(args, store):
    entries = audit_cmd.alerts(make_api(args, store, with_session=True))
    if len(entries) == 0:
        print("No alerts.")
    print_entries(entries)


# --- argument parser ----------------------------------------------------------

def add_global_flags(parser: argparse.ArgumentParser, is_main_parser: bool) -> None:
    """Add --config-dir, --server, --ca-cert and --insecure-dev to `parser`.

    These are added to the main parser AND to every subcommand, so they work
    in either position (`--server X configure` or `configure --server X`).

    On subcommands the default is argparse.SUPPRESS, which means "if the
    flag is not given here, do not set it at all". Otherwise a subcommand's
    default (None) would overwrite a value given before the subcommand.
    """
    if is_main_parser:
        default_none = None
        default_false = False
    else:
        default_none = argparse.SUPPRESS
        default_false = argparse.SUPPRESS

    parser.add_argument("--config-dir", type=Path, default=default_none,
                        help="client state directory (default: ~/.whisperchain)")
    parser.add_argument("--server", default=default_none,
                        help="server URL, e.g. https://localhost:8443")
    parser.add_argument("--ca-cert", default=default_none,
                        help="path to the server's TLS certificate (pinned)")
    parser.add_argument("--insecure-dev", action="store_true", default=default_false,
                        help="allow plain http:// (development only)")


def add_command(subparsers, name: str, help_text: str, handler, common):
    """Create one subcommand. `handler` is the cmd_... function that runs it;
    argparse stores it as args.func and main() calls it."""
    parser = subparsers.add_parser(name, parents=[common], help=help_text)
    parser.set_defaults(func=handler)
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m whisperchain.client")
    add_global_flags(parser, is_main_parser=True)
    # `common` is never used on its own; every subcommand copies its flags
    # through `parents=[common]`.
    common = argparse.ArgumentParser(add_help=False)
    add_global_flags(common, is_main_parser=False)
    commands = parser.add_subparsers(dest="command", required=True)

    # --- account ---
    p = add_command(commands, "configure", "save server URL and CA certificate path", cmd_configure, common)
    p.add_argument("--send-delay", nargs=2, type=float, metavar=("MIN", "MAX"),
                   help="random delay range in seconds before an anonymous send (default 5 60)")

    p = add_command(commands, "register", "create an account using an invite code", cmd_register, common)
    p.add_argument("--invite", required=True, help="invite code from an Admin")
    p.add_argument("--username", required=True)

    p = add_command(commands, "login", "log in and save a session", cmd_login, common)
    p.add_argument("--username", help="defaults to the registered username")

    # --- admin <subcommand> ---
    admin_parser = commands.add_parser("admin", help="Admin tools")
    admin_commands = admin_parser.add_subparsers(dest="admin_command", required=True)
    roles_help = "role to grant (repeatable): Sender, Recipient, Moderator"

    p = add_command(admin_commands, "invite", "create a single-use invite code", cmd_admin_invite, common)
    p.add_argument("--role", action="append", required=True, help=roles_help)  # "append": may repeat

    add_command(admin_commands, "users", "list accounts", cmd_admin_users, common)

    p = add_command(admin_commands, "set-roles", "replace a user's roles", cmd_admin_set_roles, common)
    p.add_argument("username")
    p.add_argument("--role", action="append", required=True, help=roles_help)

    p = add_command(admin_commands, "deactivate", "deactivate an account", cmd_admin_deactivate, common)
    p.add_argument("username")

    p = add_command(admin_commands, "revoke-key", "revoke a public key by key id", cmd_admin_revoke_key, common)
    p.add_argument("key_id")

    add_command(admin_commands, "start-round", "close the current round and open a new one",
                cmd_admin_start_round, common)

    # --- token <subcommand> ---
    token_parser = commands.add_parser("token", help="anonymous sending tokens")
    token_commands = token_parser.add_subparsers(dest="token_command", required=True)
    add_command(token_commands, "request", "get this round's token", cmd_token_request, common)
    add_command(token_commands, "status", "show local tokens", cmd_token_status, common)

    # --- messaging ---
    p = add_command(commands, "send", "send an anonymous message", cmd_send, common)
    p.add_argument("--to", required=True, help="recipient username")
    p.add_argument("--message", help="message text (prompted if omitted)")
    p.add_argument("--now", action="store_true", help="skip the random delay")

    p = add_command(commands, "inbox", "list or decrypt your messages", cmd_inbox, common)
    p.add_argument("--show", metavar="ID", help="decrypt and show one message")

    p = add_command(commands, "flag", "flag a message in your inbox for moderators", cmd_flag, common)
    p.add_argument("message_id")
    p.add_argument("--reason", help=f"why (max {C.FLAG_REASON_MAX_CHARS} characters)")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    # --- mod <subcommand> ---
    mod_parser = commands.add_parser("mod", help="moderator tools")
    mod_commands = mod_parser.add_subparsers(dest="mod_command", required=True)
    add_command(mod_commands, "queue", "list flags", cmd_mod_queue, common)
    p = add_command(mod_commands, "review", "decrypt and show a flagged message", cmd_mod_review, common)
    p.add_argument("flag_id")
    p = add_command(mod_commands, "freeze", "freeze the flagged message's token", cmd_mod_freeze, common)
    p.add_argument("flag_id")
    p = add_command(mod_commands, "dismiss", "dismiss a flag", cmd_mod_dismiss, common)
    p.add_argument("flag_id")

    # --- keys <subcommand> ---
    keys_parser = commands.add_parser("keys", help="public-key directory and pinning")
    keys_commands = keys_parser.add_subparsers(dest="keys_command", required=True)
    add_command(keys_commands, "sync", "download directory, check pins", cmd_keys_sync, common)
    p = add_command(keys_commands, "fingerprint", "show own or a cached user's fingerprint",
                    cmd_keys_fingerprint, common)
    p.add_argument("username", nargs="?")  # nargs="?": optional positional argument
    p = add_command(keys_commands, "trust", "accept a changed key after checking it", cmd_keys_trust, common)
    p.add_argument("username")

    # --- audit <subcommand>, alerts ---
    audit_parser = commands.add_parser("audit", help="audit log tools")
    audit_commands = audit_parser.add_subparsers(dest="audit_command", required=True)
    add_command(audit_commands, "verify", "verify hash chain, signatures, and checkpoint", cmd_audit_verify, common)
    p = add_command(audit_commands, "show", "print audit entries", cmd_audit_show, common)
    p.add_argument("--tail", type=int, help="only the last N entries")
    add_command(commands, "alerts", "show ALERT entries", cmd_alerts, common)
    return parser


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)

    # expanduser(): "~" inside a quoted shell variable reaches us unexpanded,
    # and would otherwise create a directory literally named "~".
    if args.config_dir:
        config_dir = Path(args.config_dir).expanduser()
    else:
        config_dir = default_config_dir()
    store = ClientStore(config_dir)
    if args.ca_cert:
        args.ca_cert = str(Path(args.ca_cert).expanduser())

    try:
        args.func(args, store)  # the cmd_... function chosen by argparse
        return 0
    except (ClientError, ValueError) as exc:
        # One plain line; no stack trace and never any secret.
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
