# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Tests for scripts/korg-move-expired.py.
#
# wotmate leaves expired keys out of its database and never touches
# their files again, so without this helper they sit in keys/ looking
# live forever. These tests build a small pgpkeys tree around Santosh
# Shilimkar's real key, which expired on 2026-10-28, and run the helper
# with gpg's clock set to either side of that date.
#
# Run with: uv run --no-project --with pytest pytest scripts/tests
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
from typing import Protocol, cast

import pytest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / 'korg-move-expired.py'
KEYID = '726C1CE741A7973F'
OTHER = '63291AE98A867C23'  # a key that never expires
KEYDATA = (HERE / 'fixtures' / f'{KEYID}.asc').read_bytes()

BEFORE = '20261001T000000'
AFTER = '20261029T000000'

# One link per UID email, as wotmate's --gen-b4-keyring makes them
LINKS = {
    'kernel.org/ssantosh': KEYID,
    'ti.com/santosh.shilimkar': KEYID,
    'kernel.org/other': OTHER,
}

needs_gpg = pytest.mark.skipif(shutil.which('gpg') is None, reason='gpg is not installed')


class _Mover(Protocol):
    def move_expired(self, pgpkeys: Path, gnupghome: Path) -> list[str]: ...
    def drop_renewed(self, pgpkeys: Path) -> list[str]: ...


def _load_mover() -> _Mover:
    # Dash in the filename blocks a plain import.
    spec = importlib.util.spec_from_file_location('korg_move_expired', SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return cast(_Mover, mod)


km = _load_mover()


@pytest.fixture
def pgpkeys(tmp_path: Path) -> Path:
    """A pgpkeys tree with Santosh's key, its graphs and b4 links, plus a
    link to an unrelated key that must be left alone."""
    root = tmp_path / 'pgpkeys'
    (root / 'keys').mkdir(parents=True)
    (root / 'graphs').mkdir()
    (root / 'keys' / f'{KEYID}.asc').write_bytes(KEYDATA)
    for ext in ('svg', 'txt'):
        (root / 'graphs' / f'{KEYID}.{ext}').write_text('graph')
    for addr, keyid in LINKS.items():
        link = root / '.keyring' / 'openpgp' / addr / 'default'
        link.parent.mkdir(parents=True)
        link.symlink_to(f'../../../../keys/{keyid}.asc')
    return root


@pytest.fixture
def gnupghome(tmp_path: Path) -> Path:
    home = tmp_path / 'gnupg'
    home.mkdir(mode=0o700)
    subprocess.run(
        ['gpg', '--homedir', str(home), '--batch', '--quiet', '--import'],
        input=KEYDATA,
        capture_output=True,
        check=True,
    )
    return home


def set_clock(gnupghome: Path, when: str) -> None:
    # gpg reads long options from gpg.conf, and the '!' stops the clock
    (gnupghome / 'gpg.conf').write_text(f'faked-system-time {when}!\n')


def link_target(pgpkeys: Path, addr: str) -> str:
    return os.readlink(pgpkeys / '.keyring' / 'openpgp' / addr / 'default')


@needs_gpg
def test_move_expired(pgpkeys: Path, gnupghome: Path) -> None:
    set_clock(gnupghome, AFTER)

    assert km.move_expired(pgpkeys, gnupghome) == [KEYID]

    # The key itself is kept byte for byte, so b4 can still check old
    # attestations, but its trust path graphs mean nothing anymore
    assert not (pgpkeys / 'keys' / f'{KEYID}.asc').exists()
    assert (pgpkeys / 'keys' / 'expired' / f'{KEYID}.asc').read_bytes() == KEYDATA
    assert not list((pgpkeys / 'graphs').iterdir())
    for addr in ('kernel.org/ssantosh', 'ti.com/santosh.shilimkar'):
        assert link_target(pgpkeys, addr) == f'../../../../keys/expired/{KEYID}.asc'
        assert (pgpkeys / '.keyring' / 'openpgp' / addr / 'default').exists()
    assert link_target(pgpkeys, 'kernel.org/other') == f'../../../../keys/{OTHER}.asc'

    # A clean --regenerate run must not report changes
    assert km.move_expired(pgpkeys, gnupghome) == []


@needs_gpg
def test_move_expired_leaves_valid_keys(pgpkeys: Path, gnupghome: Path) -> None:
    set_clock(gnupghome, BEFORE)

    assert km.move_expired(pgpkeys, gnupghome) == []
    assert (pgpkeys / 'keys' / f'{KEYID}.asc').read_bytes() == KEYDATA
    assert link_target(pgpkeys, 'kernel.org/ssantosh') == f'../../../../keys/{KEYID}.asc'


@needs_gpg
def test_move_expired_skips_files_not_in_keyring(pgpkeys: Path, gnupghome: Path) -> None:
    # keys/ and the keyring come from the same import, so a file without a
    # key means something else went wrong; leave it for a human to look at.
    set_clock(gnupghome, AFTER)
    stray = pgpkeys / 'keys' / '0000000000000000.asc'
    stray.write_bytes(KEYDATA)

    assert km.move_expired(pgpkeys, gnupghome) == [KEYID]
    assert stray.exists()


def test_drop_renewed(pgpkeys: Path) -> None:
    # After a renewal wotmate exports the key to keys/ again, but it only
    # fixes the links for UIDs still on the key. A UID the holder dropped
    # keeps pointing into expired/, and would dangle once the stale copy
    # there is removed.
    expired = pgpkeys / 'keys' / 'expired'
    expired.mkdir()
    (expired / f'{KEYID}.asc').write_bytes(b'stale')
    (expired / f'{OTHER}.asc').write_bytes(b'still expired')
    dropped_uid = pgpkeys / '.keyring' / 'openpgp' / 'ti.com/santosh.shilimkar' / 'default'
    dropped_uid.unlink()
    dropped_uid.symlink_to(f'../../../../keys/expired/{KEYID}.asc')
    still_expired = pgpkeys / '.keyring' / 'openpgp' / 'kernel.org/other' / 'default'
    still_expired.unlink()
    still_expired.symlink_to(f'../../../../keys/expired/{OTHER}.asc')

    assert km.drop_renewed(pgpkeys) == [KEYID]
    assert [p.name for p in expired.iterdir()] == [f'{OTHER}.asc']
    assert (pgpkeys / 'keys' / f'{KEYID}.asc').read_bytes() == KEYDATA
    assert link_target(pgpkeys, 'ti.com/santosh.shilimkar') == f'../../../../keys/{KEYID}.asc'
    assert link_target(pgpkeys, 'kernel.org/other') == f'../../../../keys/expired/{OTHER}.asc'


def test_drop_renewed_without_expired_dir(pgpkeys: Path) -> None:
    # Nothing has expired yet in a fresh checkout
    assert km.drop_renewed(pgpkeys) == []
