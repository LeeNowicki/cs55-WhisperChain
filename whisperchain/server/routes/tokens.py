"""Round info and blind-token issuance."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from whisperchain.common import blind
from whisperchain.common.encoding import b64_to_int, int_to_b64
from whisperchain.server import db, rounds
from whisperchain.server.auth import CurrentUser, require

router = APIRouter()


class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The round the client blinded for. If the Admin started a new round in
    # the meantime, we refuse instead of signing with a key the client did
    # not use (the client could not unblind that signature).
    round: int
    blinded: str = Field(max_length=600)  # base64 of a 2048-bit integer


@router.get("/round/current")
def current_round(conn=Depends(db.get_db)):
    """Public: everyone needs the round number and its token public key."""
    row = rounds.get_open_round(conn)
    if row is None:
        raise HTTPException(status_code=404, detail="no round is open")
    return {"round": row["round"], "n": row["token_n"], "e": row["token_e"]}


@router.post("/tokens/issue")
def issue_token(
    body: IssueRequest,
    request: Request,
    user: CurrentUser = Depends(require("token:request")),
    conn=Depends(db.get_db),
):
    try:
        blinded = b64_to_int(body.blinded)
    except ValueError:
        raise HTTPException(status_code=400, detail="blinded value is not valid base64")
    # Normalised text form, so the retry comparison below is exact.
    blinded_text = int_to_b64(blinded)

    with db.write_transaction(conn):
        row = rounds.get_open_round(conn)
        if row is None:
            raise HTTPException(status_code=409, detail="no round is open")
        if row["round"] != body.round:
            raise HTTPException(status_code=409, detail="the round has changed; request a token again")
        n, _e = rounds.public_numbers(row)
        if blinded <= 0 or blinded >= n:
            raise HTTPException(status_code=400, detail="blinded value out of range")

        existing = conn.execute(
            "SELECT blinded FROM issued WHERE round = ? AND user_id = ?", (row["round"], user.id)
        ).fetchone()
        if existing is not None and existing["blinded"] != blinded_text:
            # One token per Sender per round: a DIFFERENT blinded value
            # would be a second token.
            raise HTTPException(status_code=409, detail="you already received a token this round")

        if existing is None:
            # `issued` records only (round, user, blinded value). Thanks to
            # blinding, none of these can be matched to the token later spent.
            conn.execute(
                "INSERT INTO issued (round, user_id, blinded) VALUES (?, ?, ?)",
                (row["round"], user.id, blinded_text),
            )
            request.app.state.audit.append_audit(
                conn, "TOKEN_ISSUED", user.acting_role, f"round: {row['round']}"
            )
        # else: the SAME blinded value again = the client is retrying after a
        # lost response. Recompute and return the same signature; nothing new
        # is issued, so nothing new is stored or audited.

        private_key = rounds.load_round_private_key(request.app.state.paths, row["round"])
        d = private_key.private_numbers().d
        signature = blind.sign_blinded(blinded, d, n)

    return {"round": row["round"], "blind_signature": int_to_b64(signature)}
