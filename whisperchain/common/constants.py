"""Single source of truth for every size, label, and limit in WhisperChain+.

Both the server and the client import from here, so the two sides can never
disagree about (for example) how long an envelope is.
"""

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
ROLE_SENDER = "Sender"
ROLE_RECIPIENT = "Recipient"
ROLE_MODERATOR = "Moderator"
ROLE_ADMIN = "Admin"
ALL_ROLES = (ROLE_SENDER, ROLE_RECIPIENT, ROLE_MODERATOR, ROLE_ADMIN)
# Roles an invite may grant. Admin is excluded: Admin can only be created
# on the server host with `init-admin`, never over the network.
INVITABLE_ROLES = (ROLE_SENDER, ROLE_RECIPIENT, ROLE_MODERATOR)

# ---------------------------------------------------------------------------
# User keys (RSA-OAEP encryption key, one per user)
# ---------------------------------------------------------------------------
USER_KEY_BITS = 3072
RSA_PUBLIC_EXPONENT = 65537
# A 3072-bit SPKI DER key is about 422 bytes; 1024 leaves room but stops
# someone from uploading a huge blob as a "key".
MAX_PUBLIC_KEY_DER_BYTES = 1024

# ---------------------------------------------------------------------------
# Message envelope v1 (fixed size so length leaks nothing about content)
# ---------------------------------------------------------------------------
ENVELOPE_VERSION = 1
VERSION_BYTES = 1
KEY_ID_BYTES = 16                      # raw bytes of a UUID
WRAPPED_KEY_BYTES = USER_KEY_BITS // 8  # RSA-OAEP output = modulus size = 384
CONTENT_KEY_BYTES = 32                 # AES-256
NONCE_BYTES = 12                       # standard AES-GCM nonce size
GCM_TAG_BYTES = 16

LENGTH_PREFIX_BYTES = 2                # big-endian length of the real message
PLAINTEXT_BLOCK_BYTES = 1024           # every message is padded to this
MAX_MESSAGE_BYTES = 1000               # UTF-8 bytes allowed from the user
CIPHERTEXT_BYTES = PLAINTEXT_BLOCK_BYTES + GCM_TAG_BYTES  # 1040

ENVELOPE_BYTES = (
    VERSION_BYTES + KEY_ID_BYTES + WRAPPED_KEY_BYTES + NONCE_BYTES + CIPHERTEXT_BYTES
)  # 1453

# Sanity checks: fail at import time if someone edits a size inconsistently.
assert LENGTH_PREFIX_BYTES + MAX_MESSAGE_BYTES <= PLAINTEXT_BLOCK_BYTES
assert ENVELOPE_BYTES == 1453

# ---------------------------------------------------------------------------
# Blind-signature tokens
# ---------------------------------------------------------------------------
ROUND_KEY_BITS = 2048                  # per-round token signing key
TOKEN_T_BYTES = 32                     # random token secret chosen by client
FDH_LABEL = b"WhisperChain token v1"   # domain separation for the hash

# ---------------------------------------------------------------------------
# Accounts, sessions, registration
# ---------------------------------------------------------------------------
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024             # stops absurdly large hashing inputs
# Usernames: letters, digits, underscore, dot, dash; 3 to 32 characters.
USERNAME_PATTERN = r"^[A-Za-z0-9_.-]{3,32}$"

JWT_ALGORITHM = "HS256"
JWT_LIFETIME_MINUTES = 45
JWT_SECRET_BYTES = 32
# Tolerated clock adjustment when checking token times. The system clock can
# step backwards (WSL2 re-syncing with Windows was measured jumping ~2 s),
# which would otherwise make a brand-new token look "issued in the future".
JWT_CLOCK_SKEW_SECONDS = 30

INVITE_CODE_BYTES = 24                 # secrets.token_urlsafe(24)
INVITE_EXPIRY_DAYS = 7

CHALLENGE_BYTES = 32                   # proof-of-possession challenge
CHALLENGE_TTL_SECONDS = 300            # 5 minutes

# ---------------------------------------------------------------------------
# Rate limits (requests per window, per IP)
# ---------------------------------------------------------------------------
RATE_WINDOW_SECONDS = 60
RATE_LIMIT_LOGIN = 10
RATE_LIMIT_REGISTER = 10
RATE_LIMIT_SEND = 30

# ---------------------------------------------------------------------------
# Messaging and moderation
# ---------------------------------------------------------------------------
MAX_SEND_REQUEST_BYTES = 8192          # envelope b64 is ~1.9 KB; plenty of room
SEND_DELAY_MIN_SECONDS = 5
SEND_DELAY_MAX_SECONDS = 60
FLAG_REASON_MAX_CHARS = 200
SPEND_REJECT_AUDIT_INTERVAL_SECONDS = 60

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
AUDIT_GENESIS_HASH = "0" * 64
AUDIT_PAGE_LIMIT = 500
