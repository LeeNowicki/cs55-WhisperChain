"""audit verify / audit show / alerts.

Verification runs entirely on the client: the server only supplies the raw
entries and its public key, so a compromised server cannot simply claim
"the log is fine".
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from whisperchain.client.api import ApiClient
from whisperchain.client.errors import ClientError
from whisperchain.client.store import ClientStore
from whisperchain.common import constants as C
from whisperchain.common.audit_chain import verify_chain
from whisperchain.common.encoding import b64d


class AuditVerificationError(ClientError):
    def __init__(self, seq, reason):
        super().__init__(f"AUDIT LOG VERIFICATION FAILED at seq {seq}: {reason}")
        self.seq = seq
        self.reason = reason


def fetch_all_entries(api: ApiClient) -> list[dict]:
    """Download every entry, page by page, in seq order."""
    entries, after_seq = [], 0
    while True:
        page = api.audit_page(after_seq, C.AUDIT_PAGE_LIMIT)["entries"]
        entries.extend(page)
        if len(page) < C.AUDIT_PAGE_LIMIT:
            return entries
        last_entry = page[len(page) - 1]
        after_seq = last_entry["seq"]


def pinned_public_key(store: ClientStore, api: ApiClient) -> Ed25519PublicKey:
    """Trust-on-first-use pin of the audit key.

    If the server ever presents a different key, someone could be trying to
    pass off a rewritten log signed with a new key: refuse loudly.
    """
    served = api.audit_public_key()["public_key"]
    pinned = store.load_audit_pin()
    if pinned is None:
        store.save_audit_pin(served)
    elif pinned != served:
        raise ClientError(
            "the server's audit public key has CHANGED since it was first pinned; "
            "refusing to trust this log"
        )
    return Ed25519PublicKey.from_public_bytes(b64d(served))


def verify(store: ClientStore, api: ApiClient) -> dict:
    """Verify the whole log, check it against our checkpoint, then move the
    checkpoint forward. Raises AuditVerificationError on any problem."""
    public_key = pinned_public_key(store, api)
    entries = fetch_all_entries(api)

    bad_seq, reason = verify_chain(entries, public_key)
    if bad_seq is not None:
        raise AuditVerificationError(bad_seq, reason)

    # The chain alone cannot detect someone cutting entries off the END (or
    # rolling the whole DB back): what remains is still a valid chain. Our
    # saved checkpoint remembers how far the log reached last time.
    checkpoint = store.load_audit_checkpoint()
    if checkpoint is not None:
        cp_seq = checkpoint["seq"]
        if len(entries) < cp_seq:
            raise AuditVerificationError(
                cp_seq, f"log has only {len(entries)} entries but was verified up to seq {cp_seq} "
                        "before (truncated or rolled back)")
        if entries[cp_seq - 1]["entry_hash"] != checkpoint["entry_hash"]:
            raise AuditVerificationError(cp_seq, "entry differs from the saved checkpoint (log rewritten)")

    # Only a fully verified log may move the checkpoint.
    if len(entries) == 0:
        return {"entries": 0, "checkpoint_seq": 0}
    last_entry = entries[len(entries) - 1]
    store.save_audit_checkpoint({"seq": last_entry["seq"], "entry_hash": last_entry["entry_hash"]})
    return {"entries": len(entries), "checkpoint_seq": last_entry["seq"]}


def show(api: ApiClient, tail: int | None = None) -> list[dict]:
    """All entries, or only the last `tail` of them."""
    entries = fetch_all_entries(api)
    if tail is None or tail <= 0 or tail >= len(entries):
        return entries
    first_index = len(entries) - tail
    return entries[first_index:]


def alerts(api: ApiClient) -> list[dict]:
    alert_entries = []
    for entry in fetch_all_entries(api):
        if entry["action"] == "ALERT":
            alert_entries.append(entry)
    return alert_entries
