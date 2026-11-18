"""token request / token status.

One token per Sender per round. The token is {t, s}: a random secret t and
the server's (unblinded) signature s on FDH(t). Spending it later proves
"some Sender was allowed to send this round" without saying which one.
"""

from whisperchain.client.api import ApiClient
from whisperchain.client.errors import ApiError, ClientError
from whisperchain.client.store import ClientStore
from whisperchain.common import blind
from whisperchain.common.encoding import b64_to_int, b64d, b64e, int_to_b64


def request_token(store: ClientStore, api: ApiClient) -> dict:
    """Get this round's token. Safe to re-run after a crash or lost response."""
    current = api.current_round()
    round_number = current["round"]
    n, e = b64_to_int(current["n"]), b64_to_int(current["e"])

    existing = store.load_token(round_number)
    if existing is not None:
        return {"round": round_number, "status": "already have a token for this round"}

    pending = store.load_pending(round_number)
    if pending is not None and pending["n"] == current["n"]:
        # A previous attempt may have reached the server. Re-send the SAME
        # blinded value: the server recognises it and returns the same
        # signature instead of refusing us as a second request.
        t = b64d(pending["t"])
        r = b64_to_int(pending["r"])
        blinded = b64_to_int(pending["blinded"])
    else:
        t = blind.new_token_secret()
        m = blind.fdh(t, n)
        blinded, r = blind.blind(m, n, e)
        # Write BEFORE sending, so a lost response can be recovered.
        store.save_pending(round_number, {
            "round": round_number, "n": current["n"], "e": current["e"],
            "t": b64e(t), "r": int_to_b64(r), "blinded": int_to_b64(blinded),
        })

    try:
        result = api.issue_token(round_number, int_to_b64(blinded))
    except ApiError as exc:
        if exc.status in (400, 409):
            # The server examined this blinded value and refused it (already
            # have a token this round, round changed, ...), so it will never
            # be signed: drop the pending file. On 401/403/429 we keep it,
            # because an EARLIER attempt with it may still have succeeded.
            store.delete_pending(round_number)
        raise

    s = blind.unblind(b64_to_int(result["blind_signature"]), r, n)
    # Never store a token we have not verified ourselves.
    if not blind.verify_token(t, s, n, e):
        raise ClientError("the server returned an invalid signature; token not saved")

    store.save_token(round_number, {"round": round_number, "t": b64e(t), "s": int_to_b64(s)})
    store.delete_pending(round_number)  # r is no longer needed: destroy it
    return {"round": round_number, "status": "token received"}


def token_status(store: ClientStore, api: ApiClient) -> dict:
    """Local tokens, and whether each is still usable (its round is open)."""
    try:
        open_round = api.current_round()["round"]
    except ApiError as exc:
        if exc.status != 404:
            raise
        open_round = None
    token_rounds, pending_rounds = store.list_token_rounds()
    token_list = []
    for round_number in token_rounds:
        # A token only works in the round it was issued for.
        usable = (round_number == open_round)
        token_list.append({"round": round_number, "usable": usable})
    return {"open_round": open_round, "tokens": token_list, "pending": pending_rounds}
