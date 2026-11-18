"""Admin commands. The server enforces every rule; the client only makes the
calls convenient (e.g. accepting a username instead of a numeric id)."""

from whisperchain.client.api import ApiClient
from whisperchain.client.errors import ClientError


def invite(api: ApiClient, roles: list[str]) -> dict:
    return api.admin_create_invite(roles)


def list_users(api: ApiClient) -> list[dict]:
    return api.admin_list_users()["users"]


def _user_id_for(api: ApiClient, username: str) -> int:
    for user in list_users(api):
        if user["username"] == username:
            return user["id"]
    raise ClientError(f"no such user: {username}")


def set_roles(api: ApiClient, username: str, roles: list[str]) -> dict:
    return api.admin_set_roles(_user_id_for(api, username), roles)


def deactivate(api: ApiClient, username: str) -> dict:
    return api.admin_deactivate(_user_id_for(api, username))


def revoke_key(api: ApiClient, key_id: str) -> dict:
    return api.admin_revoke_key(key_id)


def start_round(api: ApiClient) -> dict:
    return api.admin_start_round()
