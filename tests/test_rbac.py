"""Stage 3: permission map, require(), default deny, admin routes, ownership."""

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.routing import APIRoute

from conftest import PASSPHRASE, PASSWORD, api_client, auth_header
from whisperchain.client.commands import account
from whisperchain.client.commands import admin as admin_cmd
from whisperchain.client.errors import ApiError
from whisperchain.client.store import ClientStore
from whisperchain.server import db
from whisperchain.server.app import create_app
from whisperchain.server.auth import require
from whisperchain.server.ownership import get_owned_message
from whisperchain.server.permissions import PERMISSIONS, PUBLIC_ROUTES, list_api_routes, route_permissions

# ---------------------------------------------------------------------------
# The permission map itself must match the specification exactly.
# ---------------------------------------------------------------------------

def test_permission_map_matches_spec():
    assert PERMISSIONS == {
        "Sender": {"directory:read", "token:request"},
        "Recipient": {"directory:read", "moderator_keys:read", "inbox:read", "message:flag"},
        "Moderator": {"directory:read", "flag:queue", "flag:review", "flag:resolve", "audit:read"},
        "Admin": {"directory:read", "invite:create", "user:list", "user:set_roles",
                  "user:deactivate", "key:revoke", "round:start", "audit:read"},
    }


def test_require_rejects_unknown_permission():
    with pytest.raises(ValueError):
        require("invite:craete")  # typo is caught when the app is built


# ---------------------------------------------------------------------------
# Role x endpoint status-code matrix.
# Each row: method, path, JSON body, and which test accounts are allowed.
# Allowed accounts are written out by hand here, independently of
# PERMISSIONS, so a mistake in the map shows up as a failing test.
# "{victim}" / "{victim_key}" in a path are filled in with real ids.
# ---------------------------------------------------------------------------

NO_ID = "00000000-0000-4000-8000-000000000000"  # valid-looking id that does not exist (allowed callers get 404)

ENDPOINTS = [
    {"method": "POST", "path": "/admin/invites", "body": {"roles": ["Sender"]}, "allowed": ["admin"]},
    {"method": "GET", "path": "/admin/users", "body": None, "allowed": ["admin"]},
    {"method": "POST", "path": "/admin/users/{victim}/roles", "body": {"roles": ["Sender"]}, "allowed": ["admin"]},
    {"method": "POST", "path": "/admin/users/{victim}/deactivate", "body": None, "allowed": ["admin"]},
    {"method": "GET", "path": "/audit", "body": None, "allowed": ["moderator", "admin"]},
    {"method": "GET", "path": "/directory", "body": None,
     "allowed": ["sender", "recipient", "moderator", "both", "admin"]},
    {"method": "GET", "path": "/directory/moderators", "body": None, "allowed": ["recipient", "both"]},
    {"method": "POST", "path": "/admin/keys/{victim_key}/revoke", "body": None, "allowed": ["admin"]},
    {"method": "POST", "path": "/admin/rounds/start", "body": None, "allowed": ["admin"]},
    {"method": "POST", "path": "/tokens/issue", "body": {"round": 1, "blinded": "AQ=="}, "allowed": ["sender", "both"]},
    {"method": "GET", "path": "/inbox", "body": None, "allowed": ["recipient", "both"]},
    {"method": "POST", "path": "/messages/" + NO_ID + "/flag", "body": {"reason": "x"}, "allowed": ["recipient", "both"]},
    {"method": "GET", "path": "/mod/flags", "body": None, "allowed": ["moderator"]},
    {"method": "GET", "path": "/mod/flags/" + NO_ID, "body": None, "allowed": ["moderator"]},
    {"method": "POST", "path": "/mod/flags/" + NO_ID + "/freeze", "body": None, "allowed": ["moderator"]},
    {"method": "POST", "path": "/mod/flags/" + NO_ID + "/dismiss", "body": None, "allowed": ["moderator"]},
]
CALLERS = ["anonymous", "sender", "recipient", "moderator", "both", "admin"]


def endpoint_names() -> list[str]:
    """Readable names for each matrix row, shown by pytest (e.g. "GET /inbox")."""
    names = []
    for endpoint in ENDPOINTS:
        names.append(endpoint["method"] + " " + endpoint["path"])
    return names


def fill_in_ids(path: str, ids: dict) -> str:
    """Replace "{name}" placeholders in a path with the real id from `ids`."""
    for name in ids:
        path = path.replace("{" + name + "}", str(ids[name]))
    return path


# Two parametrize lines: pytest runs this test once for EVERY combination of
# caller and endpoint (6 x 16 = 96 runs).
@pytest.mark.parametrize("caller", CALLERS)
@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=endpoint_names())
def test_rbac_matrix(world, caller, endpoint):
    url = fill_in_ids(endpoint["path"], world["ids"])
    headers = auth_header(world["tokens"][caller])
    response = world["client"].request(endpoint["method"], url, json=endpoint["body"], headers=headers)
    if caller == "anonymous":
        assert response.status_code == 401
    elif caller in endpoint["allowed"]:
        # Allowed: any answer except "not logged in" / "forbidden".
        assert response.status_code != 401, response.text
        assert response.status_code != 403, response.text
    else:
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# Default deny: every route is public on purpose or declares a permission.
# ---------------------------------------------------------------------------

def coverage_problems(app: FastAPI) -> list[str]:
    problems = []
    for path, route in list_api_routes(app.routes):
        if not isinstance(route, APIRoute):
            problems.append(f"unexpected non-API route: {path}")
            continue
        permissions = route_permissions(route)
        for method in route.methods:
            is_public = (method, path) in PUBLIC_ROUTES
            if is_public and len(permissions) > 0:
                problems.append(f"{method} {path} is public but also requires {permissions}")
            if not is_public and len(permissions) == 0:
                problems.append(f"{method} {path} has no permission and is not public")
    return problems


def test_route_walk_sees_all_routes(app):
    found = []
    for path, route in list_api_routes(app.routes):
        for method in route.methods:
            found.append((method, path))
    # Guard against the walk silently missing included routers.
    assert ("POST", "/login") in found
    assert ("GET", "/admin/users") in found


def test_every_route_is_public_or_permissioned(app):
    assert coverage_problems(app) == []


def test_coverage_check_catches_unprotected_route(server_paths):
    app = create_app(server_paths.data_dir)

    @app.get("/oops")
    def oops():
        return {}

    assert coverage_problems(app) == ["GET /oops has no permission and is not public"]


# ---------------------------------------------------------------------------
# Authentication failures
# ---------------------------------------------------------------------------

BAD_HEADERS = [
    {},
    {"Authorization": "Bearer garbage"},
    {"Authorization": "Basic abc"},
    {"Authorization": "Bearer"},
]


@pytest.mark.parametrize("header", BAD_HEADERS)
def test_bad_credentials_get_401(world, header):
    assert world["client"].get("/admin/users", headers=header).status_code == 401


# ---------------------------------------------------------------------------
# Roles and active status come from the DB on every request
# ---------------------------------------------------------------------------

def add_probe_route(app, permission):
    """Add a test-only route, /probe/<permission>, guarded by `permission`."""
    @app.get(f"/probe/{permission}")
    def probe(user=Depends(require(permission))):
        return {"id": user.id}


def probe_status(world, permission, token) -> int:
    return world["client"].get(f"/probe/{permission}", headers=auth_header(token)).status_code


def test_deactivation_takes_effect_immediately(fresh_world):
    w = fresh_world
    add_probe_route(w["app"], "token:request")
    sender_token = w["tokens"]["victim"]
    assert probe_status(w, "token:request", sender_token) == 200

    url = f"/admin/users/{w['ids']['victim']}/deactivate"
    response = w["client"].post(url, headers=auth_header(w["tokens"]["admin"]))
    assert response.status_code == 200
    # Same, still-unexpired token: now refused.
    assert probe_status(w, "token:request", sender_token) == 401
    # And they cannot log in again.
    login = w["client"].post("/login", json={"username": "victim", "password": PASSWORD})
    assert login.status_code == 401


def test_role_change_takes_effect_immediately(fresh_world):
    w = fresh_world
    add_probe_route(w["app"], "token:request")
    add_probe_route(w["app"], "inbox:read")
    token = w["tokens"]["victim"]  # currently a Sender
    assert probe_status(w, "token:request", token) == 200
    assert probe_status(w, "inbox:read", token) == 403

    url = f"/admin/users/{w['ids']['victim']}/roles"
    w["client"].post(url, json={"roles": ["Recipient"]}, headers=auth_header(w["tokens"]["admin"]))
    assert probe_status(w, "token:request", token) == 403
    assert probe_status(w, "inbox:read", token) == 200


def test_multi_role_account_gets_union(world):
    add_probe_route(world["app"], "token:request")
    add_probe_route(world["app"], "inbox:read")
    token = world["tokens"]["both"]
    assert probe_status(world, "token:request", token) == 200
    assert probe_status(world, "inbox:read", token) == 200


# ---------------------------------------------------------------------------
# Admin rules
# ---------------------------------------------------------------------------

def test_admin_cannot_create_admin_invite(world):
    headers = auth_header(world["tokens"]["admin"])
    response = world["client"].post("/admin/invites", json={"roles": ["Admin"]}, headers=headers)
    assert response.status_code == 400


def test_admin_cannot_grant_admin(world):
    url = f"/admin/users/{world['ids']['sender']}/roles"
    headers = auth_header(world["tokens"]["admin"])
    response = world["client"].post(url, json={"roles": ["Admin"]}, headers=headers)
    assert response.status_code == 400


def test_admin_accounts_cannot_be_changed_over_network(world):
    admin_id = world["ids"]["root"]
    headers = auth_header(world["tokens"]["admin"])
    response = world["client"].post(f"/admin/users/{admin_id}/roles", json={"roles": ["Sender"]}, headers=headers)
    assert response.status_code == 400
    response = world["client"].post(f"/admin/users/{admin_id}/deactivate", headers=headers)
    assert response.status_code == 400


def test_unknown_user_is_404(world):
    headers = auth_header(world["tokens"]["admin"])
    assert world["client"].post("/admin/users/9999/deactivate", headers=headers).status_code == 404


def test_user_list_has_no_secrets(world):
    response = world["client"].get("/admin/users", headers=auth_header(world["tokens"]["admin"]))
    for user in response.json()["users"]:
        assert sorted(user) == ["active", "id", "roles", "username"]  # only these fields


def find_user(users: list, username: str) -> dict:
    for user in users:
        if user["username"] == username:
            return user
    raise AssertionError(f"{username} not in the user list")


def test_admin_invite_flow_through_client(fresh_world, tmp_path, user_keys):
    """Admin creates an invite with the CLI functions; a new user registers with it."""
    app = fresh_world["app"]
    admin_api = api_client(app, fresh_world["tokens"]["admin"])
    created = admin_cmd.invite(admin_api, ["Moderator"])

    store = ClientStore(tmp_path / "newmod")
    result = account.register(store, api_client(app), created["invite_code"], "newmod",
                              PASSWORD, PASSPHRASE, private_key=user_keys[5])
    assert result["roles"] == ["Moderator"]

    admin_cmd.set_roles(admin_api, "newmod", ["Moderator", "Recipient"])
    newmod = find_user(admin_cmd.list_users(admin_api), "newmod")
    assert newmod["roles"] == ["Moderator", "Recipient"]

    admin_cmd.deactivate(admin_api, "newmod")
    newmod = find_user(admin_cmd.list_users(admin_api), "newmod")
    assert newmod["active"] is False


def test_non_admin_client_gets_403(world):
    api = api_client(world["app"], world["tokens"]["sender"])
    with pytest.raises(ApiError) as exc:
        admin_cmd.list_users(api)
    assert exc.value.status == 403


# ---------------------------------------------------------------------------
# Ownership: other people's messages are 404, not 403
# ---------------------------------------------------------------------------

def test_get_owned_message(world):
    conn = db.connect(world["paths"].db)
    owner = world["ids"]["recipient"]
    key_id = conn.execute("SELECT key_id FROM public_keys WHERE user_id = ?", (owner,)).fetchone()[0]
    conn.execute("INSERT OR IGNORE INTO rounds (round, status, token_n, token_e) VALUES (1, 'open', 'n', 'e')")
    conn.execute(
        "INSERT INTO messages (id, recipient_id, key_id, round, envelope, envelope_hash, token_hash, status) "
        "VALUES ('m1', ?, ?, 1, x'00', 'eh', 'th', 'delivered')", (owner, key_id))

    assert get_owned_message(conn, "m1", owner)["id"] == "m1"

    # Someone else's message, and a message that does not exist: both 404.
    with pytest.raises(HTTPException) as exc:
        get_owned_message(conn, "m1", world["ids"]["both"])
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        get_owned_message(conn, "missing", owner)
    assert exc.value.status_code == 404
    conn.close()
