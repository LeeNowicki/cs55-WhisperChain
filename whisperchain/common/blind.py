"""RSA blind signatures for anonymous sending tokens.

AI-Usage Attribution: I used Claude Sonnet 5.5 to ideate on this process, and the bulk of it is from that model. 

Why blind signatures: the server must check that a Sender is allowed a token
(one per round) without being able to recognise that token later when it is
spent. The client "blinds" a value before the server signs it, then removes
the blinding. The result is a valid signature on a value the server has
never seen, so the spent token cannot be linked to the issuance.

This is the ONLY non-library cryptography in the project. It uses Python's
built-in pow() for modular arithmetic and `secrets` for randomness.

    client:  m = FDH(t)                       t = 32 random bytes
             blinded = m * r^e mod n          r = random, invertible mod n
    server:  s' = blinded^d mod n             (= m^d * r mod n)
    client:  s = s' * r^-1 mod n              (= m^d mod n, a normal RSA signature on m)
    anyone:  s^e mod n == FDH(t)              verifies with the public key only
"""

import hashlib
import math
import secrets

from whisperchain.common.constants import FDH_LABEL, TOKEN_T_BYTES


def _byte_length(n: int) -> int:
    return (n.bit_length() + 7) // 8


def fdh(t: bytes, n: int) -> int:
    """Full-domain hash of t into the range [0, n).

    SHA-256 only gives 32 bytes, but RSA needs a value about as large as n
    (a short hash would make textbook RSA signatures forgeable). So we run
    SHA-256 in counter mode until we have k-1 bytes, where k is n's length.
    k-1 bytes is always smaller than n, because n's top byte is non-zero.
    """
    k = _byte_length(n)
    output = b""
    counter = 0
    while len(output) < k - 1:
        output += hashlib.sha256(FDH_LABEL + counter.to_bytes(4, "big") + t).digest()
        counter += 1
    return int.from_bytes(output[: k - 1], "big")


def new_token_secret() -> bytes:
    return secrets.token_bytes(TOKEN_T_BYTES)


def blind(m: int, n: int, e: int) -> tuple[int, int]:
    """Return (blinded, r). r must be kept secret: with r, the blinded value
    and the final token could be linked."""
    while True:
        r = secrets.randbelow(n - 2) + 2           # 2 <= r < n
        if math.gcd(r, n) == 1:                    # r must have an inverse mod n
            blinded = (m * pow(r, e, n)) % n       # pow(r, e, n) = r^e mod n
            return blinded, r
        # Otherwise (practically never happens) try another random r.


def sign_blinded(blinded: int, d: int, n: int) -> int:
    """Server side. The range check stops trivial inputs (0, n, n+1, ...) that
    would produce meaningless or revealing signatures."""
    if blinded <= 0 or blinded >= n:
        raise ValueError("blinded value out of range")
    return pow(blinded, d, n)


def unblind(blind_signature: int, r: int, n: int) -> int:
    """Client side: remove the blinding factor r."""
    return (blind_signature * pow(r, -1, n)) % n


def verify_token(t: bytes, s: int, n: int, e: int) -> bool:
    """True if s is a valid signature on FDH(t) under the public key (n, e)."""
    if s <= 0 or s >= n:
        return False
    return pow(s, e, n) == fdh(t, n)


def token_hash(t: bytes) -> str:
    """The identifier stored when a token is spent (never t itself)."""
    return hashlib.sha256(t).hexdigest()
