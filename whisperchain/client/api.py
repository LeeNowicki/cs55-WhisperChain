"""HTTP access to the server.

Every network call goes through an httpx.Client produced by an injected
`client_factory`. The real CLI passes a factory that builds TLS-pinned
clients; tests pass a small function that returns a FastAPI TestClient,
so they run fully in-process.
"""

import ssl
from pathlib import Path

import httpx

from whisperchain.client.errors import ApiError, ClientError, NetworkError


def build_client_factory(server_url: str, ca_cert: str | None, insecure_dev: bool = False):
    """Return a function that creates a new, correctly configured httpx.Client."""
    if not server_url:
        raise ClientError("no server URL configured; run `configure --server URL ...`")
    if server_url.startswith("https://"):
        if not ca_cert or not Path(ca_cert).is_file():
            raise ClientError("no CA certificate configured; run `configure --ca-cert PATH`")
        # The context trusts ONLY the server's own self-signed certificate
        # (no system CAs), i.e. the certificate is pinned.
        verify = ssl.create_default_context(cafile=str(ca_cert))
    elif server_url.startswith("http://"):
        # Plain HTTP exposes passwords and tokens on the wire: allowed only
        # when the user explicitly asks for it during development.
        if not insecure_dev:
            raise ClientError("refusing plain http:// (use https, or --insecure-dev for local testing)")
        verify = False
    else:
        raise ClientError("server URL must start with https://")

    # A function defined inside another function can still use the outer
    # function's variables (server_url, verify). We return the function
    # itself (not a client), so callers can make a fresh client whenever
    # they need one by calling factory().
    def factory() -> httpx.Client:
        # trust_env=False: ignore proxy and CA-bundle environment variables
        # so nothing outside our config can change who we trust.
        return httpx.Client(base_url=server_url, verify=verify, timeout=30.0, trust_env=False)

    return factory


def _error_details(response: httpx.Response) -> tuple[str, str | None]:
    """(human message, reject reason or None) from an error response."""
    detail = None
    try:
        body = response.json()
        if isinstance(body, dict) and "detail" in body:
            detail = body["detail"]
    except ValueError:
        pass  # the body was not JSON
    if isinstance(detail, str):
        return detail, None
    if isinstance(detail, dict) and isinstance(detail.get("message"), str):
        # Our send route answers {"message": ..., "reason": ...}.
        return detail["message"], detail.get("reason")
    if response.status_code == 422:
        return "the server rejected the request as malformed", None
    return f"server error (HTTP {response.status_code})", None


def call(client: httpx.Client, method: str, path: str, json: dict | None = None,
         params: dict | None = None) -> dict:
    """Send one request, return the JSON body, or raise a ClientError subclass.

    json:   the request body (for POST)
    params: query-string values, e.g. {"after_seq": 0} -> ?after_seq=0
    """
    try:
        response = client.request(method, path, json=json, params=params)
    except httpx.TransportError:
        # Covers connection refused, TLS failures, timeouts. We cannot know
        # whether the server applied the request.
        raise NetworkError("could not reach the server (network or TLS error)") from None
    if response.status_code >= 400:
        message, reason = _error_details(response)
        raise ApiError(response.status_code, message, reason)
    return response.json()


class ApiClient:
    """Two kinds of connection:

    - `public`: no credentials, for register/login and other public routes.
    - `auth`: carries the session JWT, for permissioned routes.
    - `make_anon_client()`: a brand-new client with no credentials and no
      shared cookies or connections, used for anonymous sending.
    """

    def __init__(self, client_factory, token: str | None = None):
        self._factory = client_factory
        self._token = token
        self._public = None
        self._auth = None

    @property
    def public(self) -> httpx.Client:
        if self._public is None:
            self._public = self._factory()
        return self._public

    @property
    def auth(self) -> httpx.Client:
        if self._token is None:
            raise ClientError("not logged in; run `login` first")
        if self._auth is None:
            self._auth = self._factory()
            self._auth.headers["Authorization"] = f"Bearer {self._token}"
        return self._auth

    def make_anon_client(self) -> httpx.Client:
        return self._factory()

    # --- public endpoints -------------------------------------------------------
    def health(self) -> dict:
        return call(self.public, "GET", "/health")

    def register_challenge(self, public_key_b64: str) -> dict:
        return call(self.public, "POST", "/register/challenge", json={"public_key": public_key_b64})

    def register(self, fields: dict) -> dict:
        return call(self.public, "POST", "/register", json=fields)

    def login(self, username: str, password: str) -> dict:
        return call(self.public, "POST", "/login", json={"username": username, "password": password})

    # --- admin endpoints (JWT) ----------------------------------------------------
    def admin_create_invite(self, roles: list[str]) -> dict:
        return call(self.auth, "POST", "/admin/invites", json={"roles": roles})

    def admin_list_users(self) -> dict:
        return call(self.auth, "GET", "/admin/users")

    def admin_set_roles(self, user_id: int, roles: list[str]) -> dict:
        return call(self.auth, "POST", f"/admin/users/{user_id}/roles", json={"roles": roles})

    def admin_deactivate(self, user_id: int) -> dict:
        return call(self.auth, "POST", f"/admin/users/{user_id}/deactivate")

    # --- audit ---------------------------------------------------------------------
    def audit_public_key(self) -> dict:
        return call(self.public, "GET", "/audit/public-key")

    def audit_page(self, after_seq: int, limit: int) -> dict:
        return call(self.auth, "GET", "/audit", params={"after_seq": after_seq, "limit": limit})

    # --- directory -------------------------------------------------------------------
    def directory(self) -> dict:
        return call(self.auth, "GET", "/directory")

    def moderator_directory(self) -> dict:
        return call(self.auth, "GET", "/directory/moderators")

    def admin_revoke_key(self, key_id: str) -> dict:
        return call(self.auth, "POST", f"/admin/keys/{key_id}/revoke")

    # --- rounds and tokens ------------------------------------------------------------
    def current_round(self) -> dict:
        return call(self.public, "GET", "/round/current")

    def issue_token(self, round_number: int, blinded_b64: str) -> dict:
        return call(self.auth, "POST", "/tokens/issue", json={"round": round_number, "blinded": blinded_b64})

    def admin_start_round(self) -> dict:
        return call(self.auth, "POST", "/admin/rounds/start")

    # --- messages ---------------------------------------------------------------------
    def send_message(self, body: dict) -> dict:
        """Anonymous send: a brand-new client with NO Authorization header and
        no shared connection or cookies with our logged-in session."""
        with self.make_anon_client() as anon:
            return call(anon, "POST", "/messages", json=body)

    def inbox(self) -> dict:
        return call(self.auth, "GET", "/inbox")

    # --- moderation ---------------------------------------------------------------------
    def flag_message(self, message_id: str, reason: str, wrapped_keys: dict) -> dict:
        return call(self.auth, "POST", f"/messages/{message_id}/flag",
                    json={"reason": reason, "wrapped_keys": wrapped_keys})

    def mod_queue(self) -> dict:
        return call(self.auth, "GET", "/mod/flags")

    def mod_review(self, flag_id: str) -> dict:
        return call(self.auth, "GET", f"/mod/flags/{flag_id}")

    def mod_freeze(self, flag_id: str) -> dict:
        return call(self.auth, "POST", f"/mod/flags/{flag_id}/freeze")

    def mod_dismiss(self, flag_id: str) -> dict:
        return call(self.auth, "POST", f"/mod/flags/{flag_id}/dismiss")
