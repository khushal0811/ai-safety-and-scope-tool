"""Per-install HMAC authentication for the local Vallum daemon's audit responses.

The CLI treats a daemon response as an authorization decision, so a response is trusted only
when it carries a valid signature. The key is a random 32-byte secret stored in the user's
state directory with owner-only permissions. Both the daemon and the CLI read the same file.
"""

import hashlib
import hmac
import os
import secrets
from typing import Optional

SIGNATURE_HEADER = "X-Vallum-Signature"
_KEY_FILENAME = "daemon.key"


def _state_dir() -> str:
    return os.getenv("VALLUM_STATE_DIR", os.path.expanduser("~/.vallum"))


def get_daemon_secret() -> bytes:
    """Return the per-install secret, creating it (mode 0600) on first use."""
    directory = _state_dir()
    path = os.path.join(directory, _KEY_FILENAME)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return bytes.fromhex(f.read().strip())

    os.makedirs(directory, mode=0o700, exist_ok=True)
    key = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process created the key first: use that one
        with open(path, "r", encoding="utf-8") as f:
            return bytes.fromhex(f.read().strip())
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key.hex())
    return key


def sign_body(body: bytes) -> str:
    """HMAC-SHA256 of a response body, hex encoded."""
    return hmac.new(get_daemon_secret(), body, hashlib.sha256).hexdigest()


def verify_body(body: bytes, signature: Optional[str]) -> bool:
    """True only if the signature matches the body under the local secret (constant-time compare)."""
    if not signature:
        return False
    try:
        expected = sign_body(body)
    except (OSError, ValueError):
        return False
    return hmac.compare_digest(signature, expected)
