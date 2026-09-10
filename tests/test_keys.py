import os
import stat
import subprocess
import sys

import pytest

from proxy import keys


def test_key_is_created_once_and_reloaded(tmp_path):
    path = tmp_path / ".trust_key"
    first = keys.load_or_create_key(path)
    second = keys.load_or_create_key(path)
    assert path.exists()
    assert first.public_key() == second.public_key()


def test_sign_and_verify(tmp_path):
    key = keys.load_or_create_key(tmp_path / ".trust_key")
    other = keys.load_or_create_key(tmp_path / ".other_key")
    signature = keys.sign(key, b"root")
    assert keys.verify(key.public_key(), b"root", signature)
    assert not keys.verify(key.public_key(), b"root2", signature)
    assert not keys.verify(other.public_key(), b"root", signature)
    assert not keys.verify(key.public_key(), b"root", b"\x00" * 3)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_key_file_is_0600_on_posix(tmp_path):
    path = tmp_path / ".trust_key"
    keys.load_or_create_key(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_key_file_grants_only_current_user_on_windows(tmp_path):
    path = tmp_path / ".trust_key"
    keys.load_or_create_key(path)
    listing = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    entries = [line for line in listing.splitlines() if ":(" in line]
    assert len(entries) == 1, listing
    assert os.environ["USERNAME"].lower() in entries[0].lower()
