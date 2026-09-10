"""Ed25519 key that signs the proxy's own approval records.

What it protects: the pinned Merkle roots in trust.db. If trust.db is edited
by anything that does not hold this key, the stored signature stops verifying
and the proxy reports TAMPERED instead of trusting the edited record.

What it does NOT do: prove anything about an upstream server's identity.
Servers never see this key and never sign anything.

The private key is never transmitted and never logged. Anyone who can read
.trust_key can forge approvals, so it is only as safe as the file.
"""

# TODO: move the private key into the OS keyring (Windows Credential Manager,
# macOS Keychain, Secret Service) instead of a file sitting next to trust.db.

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_PATH = Path(__file__).resolve().parent / ".trust_key"


def load_or_create_key(path: Path = KEY_PATH) -> Ed25519PrivateKey:
    """Load the signing key, generating it (owner-only file) on first run."""
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} does not contain an Ed25519 private key")
        return key

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_owner_only(path, pem)
    return key


def sign(key: Ed25519PrivateKey, message: bytes) -> bytes:
    return key.sign(message)


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _write_owner_only(path: Path, data: bytes) -> None:
    # O_EXCL: never overwrite an existing key. Mode 0o600 is enforced by POSIX;
    # on Windows it only controls the read-only flag, so we set an ACL instead.
    # Permissions are restricted while the file is still empty, before any key
    # bytes are written.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        if sys.platform == "win32":
            _restrict_to_current_user_windows(path)
        with os.fdopen(fd, "wb") as file:
            fd = -1  # now owned by the file object
            file.write(data)
    except BaseException:
        if fd != -1:
            os.close(fd)
        path.unlink(missing_ok=True)
        raise


def _restrict_to_current_user_windows(path: Path) -> None:
    """The Windows equivalent of 0600: drop inherited ACEs, grant only the current user."""
    user = os.environ["USERNAME"]
    domain = os.environ.get("USERDOMAIN")
    principal = f"{domain}\\{user}" if domain else user
    result = subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:F"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise OSError(f"could not restrict permissions on {path}: {(result.stderr or result.stdout).strip()}")
