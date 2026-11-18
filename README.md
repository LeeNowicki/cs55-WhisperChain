# WhisperChain+

Anonymous messaging with role-based control and accountability (CS55 project).

Senders get one blind-signed token per round and use it to send end-to-end
encrypted messages that the server cannot link back to them. Recipients
read and can flag messages, Moderators review flagged content, and Admins
manage accounts and rounds. Every action is recorded in a signed,
hash-chained audit log that holds no user identities.

The system is a FastAPI **server** plus an argparse **command-line client**.
The client never touches the server's database.


## AI Usage Attribution

I used Claude Sonnet 5.5 for ideation and planning. 


## Requirements

- Python 3.11 or newer
- Works on Linux / WSL, macOS and Windows (the examples below use bash)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Dependencies: `fastapi`, `uvicorn`, `cryptography`, `PyJWT`, `argon2-cffi`,
`httpx` (and `pytest` for development).

## Quick look: run the demo

```bash
python scripts/demo.py          # full scripted walkthrough, about 15 seconds
python scripts/tamper_demo.py   # edits the audit log behind the server's back; verify catches it
```

`demo.py` starts a real HTTPS server in a temporary directory and drives
real CLI users through the whole flow:

1. The Admin opens a round and invites three Senders, a Recipient and a Moderator.
2. Each Sender sends one anonymous message; the Recipient reads and flags them all.
3. The Moderator reviews them, freezes one and dismisses another.
4. The flagging triggers alerts, and the audit log is verified and saved to
   `docs/sample_audit_log.txt`.

Add `--keep` to keep the temporary directory.

## Server

Run these from the repository root with the virtual environment active:

```bash
python -m whisperchain.server init         # database, secrets, self-signed TLS certificate
python -m whisperchain.server init-admin   # asks for the Admin username and password (min 12 chars)
python -m whisperchain.server run          # https://127.0.0.1:8443  (--host / --port to change)
```

`run` keeps running in the foreground. Leave it in its own terminal (or add
`&` to run it in the background), and use a second terminal for the client.
Stop it with Ctrl+C (or `kill %1` if backgrounded).

Server state lives in `./server_data/` (use `--data-dir` before the command
to change it). It contains secrets and is git-ignored:

| Path | Contents |
|---|---|
| `whisperchain.db` | SQLite database |
| `secrets/jwt_secret` | session-token signing secret |
| `secrets/audit_ed25519.pem` | audit-log signing key |
| `keys/round_<n>.pem` | each round's token-signing key |
| `tls/cert.pem`, `tls/key.pem` | self-signed TLS certificate and key |

`init` refuses to run over an existing installation. Give clients a copy of
`tls/cert.pem`. They pin it, so it is the only certificate they will trust.
Admin accounts can only be created with `init-admin` on the server machine.

## Client walkthrough

Each user keeps their state in a config directory (default
`~/.whisperchain`). Use `--config-dir` to run several users on one machine.
These shell variables keep the examples short:

```bash
source .venv/bin/activate       # in every new terminal
WC="python -m whisperchain.client"
ADMIN="$WC --config-dir $HOME/wc-admin"
ALICE="$WC --config-dir $HOME/wc-alice"
BOB="$WC --config-dir $HOME/wc-bob"
MOD="$WC --config-dir $HOME/wc-mod"
```

The examples assume you are in the repository root, so that
`server_data/tls/cert.pem` is the server's certificate.

### 1. Configure and log in as Admin

```bash
$ADMIN configure --server https://localhost:8443 --ca-cert server_data/tls/cert.pem
$ADMIN login --username root          # the name you gave init-admin
$ADMIN admin start-round              # open round 1
$ADMIN admin invite --role Sender     # prints a one-time invite code
$ADMIN admin invite --role Recipient
$ADMIN admin invite --role Moderator
```

### 2. Users register and log in

```bash
$ALICE configure --server https://localhost:8443 --ca-cert server_data/tls/cert.pem
$ALICE register --invite CODE --username alice
$ALICE login
```

`register` asks for an account password and a **different** key passphrase
(both at least 12 characters, typed twice). The RSA-3072 key pair is
generated locally, and the private key is saved encrypted with the
passphrase. It also prints your **key ID** and **fingerprint**. Repeat for
`bob` (Recipient) and `mod` (Moderator), each with their own invite code
and `--config-dir`.

Sessions last 45 minutes. When a command says "not logged in or session
expired", run `login` again. Also log in again after an Admin changes your
roles, so `keys sync` knows about them.

### 3. Send anonymously

```bash
$ALICE keys sync                          # download public keys; first sight of a user pins their key
$ALICE token request                      # one blind-signed token for this round
$ALICE send --to bob --message "hello"    # waits a random 5-60 s, then sends with no login attached
```

- **`--now`:** skips the delay (for testing). `configure --send-delay MIN MAX` changes the range.
- **Message size:** at most 1000 bytes of UTF-8.
- **One message per round:** each Sender has one token per round.
- **Interrupted sends:** run `send` again. It resubmits the exact same encrypted
  message (saved in `outbox.json`) instead of sending a new one.

### 4. Read and flag

```bash
$BOB inbox                                 # list message ids
$BOB inbox --show MESSAGE_ID               # decrypt one (asks for the key passphrase)
$BOB flag MESSAGE_ID --reason "abusive"    # lets the moderators read this one message
```

Decrypted text is never written to disk. Flagging re-encrypts that one
message's key to each Moderator whose key matches your pins.

### 5. Moderate

```bash
$MOD mod queue                 # flags: id, round, status, reason (no recipient or sender info)
$MOD mod review FLAG_ID        # decrypt the flagged message with your key copy
$MOD mod freeze FLAG_ID        # freeze that message's token and mark the flag actioned
$MOD mod dismiss FLAG_ID
```

Freezing records the decision and keeps that exact token unusable. It cannot
block the sender in later rounds, because their next token cannot be linked
to this one.

### 6. Audit

```bash
$MOD audit verify             # check hash chain, signatures and saved checkpoint
$MOD audit show --tail 20
$MOD alerts                   # only ALERT entries
```

`audit verify` runs entirely on the client. It pins the server's audit
public key the first time it sees it. It saves a checkpoint only when
verification passes, and that checkpoint is what catches entries being cut
off the end of the log.

## Command reference

Global flags (before or after the command): `--config-dir DIR`,
`--server URL`, `--ca-cert PATH`, `--insecure-dev` (allows plain `http://`,
for development only; otherwise it is refused).

| Command | Who | Purpose |
|---|---|---|
| `configure [--server URL] [--ca-cert PATH] [--send-delay MIN MAX]` | anyone | save settings |
| `register --invite CODE --username NAME` | anyone | create an account with a new local key |
| `login [--username NAME]` | anyone | start a 45-minute session |
| `keys sync` | logged in | download the key directory, check pins |
| `keys fingerprint [USER]` | anyone | show your own or a cached fingerprint |
| `keys trust USER` | anyone | accept a changed key after checking it out of band |
| `token request`, `token status` | Sender | get and inspect this round's token |
| `send --to USER [--message TEXT] [--now]` | token holder | anonymous send |
| `inbox [--show ID]` | Recipient | list or decrypt messages |
| `flag ID [--reason TEXT] [--yes]` | Recipient | flag a message for moderation |
| `mod queue / review ID / freeze ID / dismiss ID` | Moderator | moderation |
| `audit verify / audit show [--tail N] / alerts` | Moderator, Admin | audit log |
| `admin invite --role R [--role R2]` | Admin | create an invite (Sender/Recipient/Moderator) |
| `admin users` | Admin | list accounts |
| `admin set-roles USER --role R [...]` | Admin | replace an account's roles |
| `admin deactivate USER` | Admin | deactivate an account (takes effect immediately) |
| `admin revoke-key KEY_ID` | Admin | revoke a public key (find the id with `keys fingerprint USER` after `keys sync`, or from the user's `register` output) |
| `admin start-round` | Admin | close the current round, open the next |

## Local client files

| File | Contents |
|---|---|
| `config.json` | server URL, CA certificate path, send delay |
| `private_key.pem` | your RSA private key, encrypted with your passphrase |
| `identity.json` | your username, key id and fingerprint |
| `session.json` | your current session token |
| `directory_cache.json`, `pins.json` | cached public keys and trusted fingerprints |
| `tokens/` | unspent tokens (and an in-progress request, if any) |
| `outbox.json` | a built but not yet confirmed send |
| `audit_pubkey.pin`, `audit_checkpoint.json` | audit-log key pin and last verified position |

**A lost private key means a lost inbox.** The server never has a copy of
your private key or passphrase and cannot recover your messages, by design.
Back up the config directory if you need to keep them.

## Tests

With the virtual environment active, from the repository root:

```bash
pytest                                   # everything; about 2-3 minutes
pytest -q tests/test_messages.py         # one file
pytest -q -k replay                      # tests whose name contains "replay"
pytest -q tests/test_rbac.py::test_every_route_is_public_or_permissioned   # one test
```

The tests build a fresh server in a temporary directory for each test and
talk to it in-process (FastAPI `TestClient`), so no server needs to be
running and nothing outside `/tmp` is touched.

| File | What it checks |
|---|---|
| `tests/test_scaffold.py` | app starts, schema and append-only triggers, `init`, `init-admin`, TLS certificate |
| `tests/test_accounts.py` | invites, key validation, proof of possession, register/login, JWT, rate limits, client key storage |
| `tests/test_rbac.py` | permission map, role x endpoint status-code matrix, default-deny route coverage, deactivation / role changes take effect immediately, admin rules, ownership 404s |
| `tests/test_audit.py` | events logged, no identities in the log, atomic audit, chain verification, tampered / deleted / truncated entries detected, audit key pinning |
| `tests/test_keys.py` | directory contents, key revocation, trust-on-first-use pins, changed-key blocking, `keys trust` |
| `tests/test_tokens.py` | blind-signature math, rounds, one token per round, retry-safe issuance, pending-file recovery, schema unjoinability |
| `tests/test_messages.py` | envelope crypto (bit flips, wrong key/round), anonymous send (no `Authorization` header), validation order, replay vs. retry, rollback, inbox, sanitization |
| `tests/test_moderation.py` | flag / review / freeze / dismiss end to end, undecryptable flags, moderator sees no identities, every alert rule |

### Manual TLS check

The tests skip TLS. To check it by hand, start the server (see above) and,
in another terminal:

```bash
python -m whisperchain.client --config-dir $HOME/wc-admin configure \
    --server https://localhost:8443 --ca-cert server_data/tls/cert.pem
python -m whisperchain.client --config-dir $HOME/wc-admin login --username root
```

A successful login shows that the pinned certificate was accepted. Pointing
`--ca-cert` at a different certificate gives "could not reach the server
(network or TLS error)", and an `http://` URL is refused. `python
scripts/demo.py` also runs everything over real TLS.

### Regenerating the docs

```bash
python scripts/demo.py              # rewrites docs/sample_audit_log.txt
```

## Troubleshooting and starting over

- **"too many requests; slow down":** the server allows 10 logins and 10
  registration requests (each `register` makes 2) per minute per IP address,
  and 30 sends. Wait a minute.
- **"no round is open":** an Admin must run `admin start-round` first.
- **"no token for round N":** run `token request`. Each Sender gets one token
  per round, so a second message needs the Admin to start a new round.
- **"... does NOT match the pinned fingerprint":** the server is presenting a
  different key for that user. Compare fingerprints with them out of band
  before `keys trust USER`.
- **Start completely fresh:** stop the server, then delete `server_data/`
  and the client config directories (e.g. `rm -rf server_data
  $HOME/wc-admin $HOME/wc-alice $HOME/wc-bob $HOME/wc-mod`). Then run `init`
  and `init-admin` again. Old client directories don't work with a new
  server, because their pins and certificate belong to the old one.

## Platform notes

- **File permissions:** on Linux, macOS and WSL, secret files are created
  with mode `0600` and the client config directory with `0700`. On native
  Windows these POSIX modes are mostly ignored, and the files instead rely on
  the user-profile directory already being private to that Windows user.
- **Passwords and passphrases** are always read with a hidden prompt, never
  from command-line arguments. The only exception is the scripted demo, which
  sets `WC_DEMO_MODE=1` and reads them from `WC_DEMO_PASSWORD` /
  `WC_DEMO_PASSPHRASE`.
- **Clock adjustments:** session tokens tolerate 30 seconds of clock skew,
  because the WSL2 clock can step backwards when it re-syncs with Windows.

## Repository layout

```
whisperchain/common/    shared code: constants, encoding, envelope, blind signatures, audit chain
whisperchain/server/    FastAPI app, schema, auth/permissions, audit, alerts, routes/
whisperchain/client/    CLI (__main__.py), API client, local store, commands/
scripts/                demo.py, tamper_demo.py
tests/                  pytest suites
docs/                   sample audit log
```
