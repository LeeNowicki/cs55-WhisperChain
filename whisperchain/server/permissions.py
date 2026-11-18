"""Role -> permission map: the single source of truth for access control.

A user may hold several roles; their permissions are the union of the
permissions of each role. Anything not granted here is denied.
"""

from fastapi.routing import APIRoute

PERMISSIONS = {
    "Sender": {"directory:read", "token:request"},
    "Recipient": {"directory:read", "moderator_keys:read", "inbox:read", "message:flag"},
    "Moderator": {"directory:read", "flag:queue", "flag:review", "flag:resolve", "audit:read"},
    "Admin": {
        "directory:read", "invite:create", "user:list", "user:set_roles",
        "user:deactivate", "key:revoke", "round:start", "audit:read",
    },
}


def _collect_all_permissions() -> frozenset:
    """Every permission that appears anywhere in the map above."""
    everything = set()
    for role in PERMISSIONS:
        for permission in PERMISSIONS[role]:
            everything.add(permission)
    return frozenset(everything)


ALL_PERMISSIONS = _collect_all_permissions()

# Routes that deliberately require no login, as (method, path).
# Default deny: every route must either be listed here or declare a
# permission with require(...). A test walks app.routes and enforces this.
PUBLIC_ROUTES = {
    ("GET", "/health"),
    ("GET", "/round/current"),
    ("GET", "/audit/public-key"),
    ("POST", "/register/challenge"),
    ("POST", "/register"),
    ("POST", "/login"),
    # Anonymous send: authorized by the one-time blind-signed token in the
    # body (a capability), NOT by who you are.
    ("POST", "/messages"),
}


def role_granting(roles, permission: str) -> str | None:
    """The first (alphabetical) of the user's roles that grants `permission`,
    or None if none of their roles grants it."""
    for role in sorted(roles):
        if role in PERMISSIONS and permission in PERMISSIONS[role]:
            return role
    return None


def permissions_for(roles) -> set[str]:
    """Union of the permissions of every role the user holds."""
    granted = set()
    for role in roles:
        if role in PERMISSIONS:
            for permission in PERMISSIONS[role]:
                granted.add(permission)
    return granted


def list_api_routes(routes, prefix: str = "") -> list:
    """Return a list of (full_path, route) pairs for every endpoint,
    descending into included routers. Used by the default-deny test and the
    RBAC-matrix generator.

    Newer FastAPI versions keep `include_router(...)` results as wrapper
    objects with an `original_router` instead of copying the routes into
    app.routes, so we handle both layouts. A wrapper can contain further
    wrappers, so this function calls itself for them (recursion).
    """
    found = []
    for route in routes:
        if isinstance(route, APIRoute):
            # A normal endpoint.
            found.append((prefix + route.path, route))
        elif hasattr(route, "original_router"):
            # A wrapper around an included router: look inside it.
            child_prefix = prefix
            if hasattr(route, "include_context") and route.include_context.prefix:
                child_prefix = prefix + route.include_context.prefix
            inner_routes = list_api_routes(route.original_router.routes, child_prefix)
            for pair in inner_routes:
                found.append(pair)
        else:
            # Anything else (static files, websockets) is unexpected in this
            # app; report it so the default-deny test notices.
            if hasattr(route, "path"):
                path = route.path
            else:
                path = str(route)
            found.append((prefix + path, route))
    return found


def route_permissions(route) -> list[str]:
    """Every permission declared via require(...) anywhere in a route's
    dependency tree (require() attaches `.permission` to its dependency).

    Dependencies can have their own dependencies, so we keep a "to do" list
    and work through it until it is empty.
    """
    found = []
    to_check = list(route.dependant.dependencies)
    while len(to_check) > 0:
        dependency = to_check.pop()
        if hasattr(dependency.call, "permission"):
            found.append(dependency.call.permission)
        for inner in dependency.dependencies:
            to_check.append(inner)
    return found
