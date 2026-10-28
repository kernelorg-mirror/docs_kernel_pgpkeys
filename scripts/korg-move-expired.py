#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Keep keys/ limited to live keys, by moving expired ones to keys/expired/.
#
# wotmate leaves expired keys out of its database, so it never touches
# their files again and they would sit in keys/ looking live forever.
# Moving them keeps the key itself (b4 still needs it to check old
# attestations, so the .keyring links follow it), while their trust path
# graphs are deleted, since an expired key is no longer part of the WoT.
#
# A key that gets renewed is exported to keys/ again by wotmate, with
# fresh graphs, so its stale copy in keys/expired/ is removed and any
# links still pointing at it go back to keys/. That happens on every
# run, so a renewal lands in one commit.
#
# Usage: korg-move-expired.py [--move-expired --gnupghome <dir>] <pgpkeys>
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def expired_keyids(gnupghome: Path) -> set[str]:
    cmd = ['gpg', '--homedir', str(gnupghome), '--batch', '--with-colons', '--list-keys']
    out = subprocess.run(cmd, capture_output=True, check=True).stdout
    keyids: set[str] = set()
    for line in out.decode(errors='replace').splitlines():
        fields = line.split(':')
        # A key that is both revoked and expired shows as revoked; those
        # are dropped by hand, not kept around
        if fields[0] == 'pub' and fields[1] == 'e':
            keyids.add(fields[4])
    return keyids


def repoint_links(pgpkeys: Path, keyids: set[str], to_expired: bool) -> None:
    # Links are relative (../../../../keys/<KID>.asc), so only the last
    # directory changes and the rest of the target is kept as it is
    for dirpath, _, filenames in os.walk(pgpkeys / '.keyring'):
        for name in filenames:
            link = Path(dirpath, name)
            if not link.is_symlink():
                continue
            target = Path(os.readlink(link))
            if target.stem not in keyids:
                continue
            if to_expired and target.parent.name == 'keys':
                newtarget = target.parent / 'expired' / target.name
            elif not to_expired and target.parent.name == 'expired':
                newtarget = target.parent.parent / target.name
            else:
                continue
            link.unlink()
            link.symlink_to(newtarget)


def move_expired(pgpkeys: Path, gnupghome: Path) -> list[str]:
    keysdir = pgpkeys / 'keys'
    moved = sorted(kid for kid in expired_keyids(gnupghome) if (keysdir / f'{kid}.asc').exists())
    if not moved:
        return []
    (keysdir / 'expired').mkdir(exist_ok=True)
    for kid in moved:
        (keysdir / f'{kid}.asc').rename(keysdir / 'expired' / f'{kid}.asc')
        for ext in ('svg', 'txt'):
            (pgpkeys / 'graphs' / f'{kid}.{ext}').unlink(missing_ok=True)
    repoint_links(pgpkeys, set(moved), to_expired=True)
    return moved


def drop_renewed(pgpkeys: Path) -> list[str]:
    expired = pgpkeys / 'keys' / 'expired'
    if not expired.is_dir():
        return []
    dropped = sorted(p.stem for p in expired.glob('*.asc') if (pgpkeys / 'keys' / p.name).exists())
    for kid in dropped:
        (expired / f'{kid}.asc').unlink()
    # wotmate only fixes the links for UIDs still on the renewed key, so
    # any others would dangle now
    repoint_links(pgpkeys, set(dropped), to_expired=False)
    return dropped


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Move expired keys to keys/expired/ and drop renewed ones from it.',
    )
    parser.add_argument(
        '--move-expired',
        action='store_true',
        help='also move keys that have expired (needs --gnupghome)',
    )
    parser.add_argument(
        '--gnupghome',
        type=Path,
        help='GnuPG home with every key from keys/ imported',
    )
    parser.add_argument('pgpkeys', type=Path, help='the pgpkeys.git working tree')
    args = parser.parse_args()
    if args.move_expired and args.gnupghome is None:
        parser.error('--move-expired needs --gnupghome')
    try:
        for kid in drop_renewed(args.pgpkeys):
            print(f'Renewed {kid}, dropped keys/expired/{kid}.asc')
        if args.move_expired:
            for kid in move_expired(args.pgpkeys, args.gnupghome):
                print(f'Expired {kid}, moved to keys/expired/{kid}.asc')
    except (OSError, subprocess.CalledProcessError) as ex:
        print(f'korg-move-expired: {ex}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
