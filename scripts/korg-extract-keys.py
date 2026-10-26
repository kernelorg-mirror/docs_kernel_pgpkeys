#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Pull every armoured PGP public key block out of a key submission
# email and print them to stdout, ready for `gpg --import`.
#
# gpg only finds armour in plain text, so keys sent as attachments or
# in base64 / quoted-printable encoded parts were silently ignored when
# the raw .eml was handed to gpg directly. Decoding each MIME part first
# catches them all. Exits non-zero when nothing is found, so a broken
# submission can't slip through unnoticed.
#
# Usage: korg-extract-keys.py msg.eml | gpg --import
from __future__ import annotations

import argparse
import email
import email.policy
import re
import sys

KEY_RE = re.compile(
    r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----',
    re.DOTALL,
)


def extract_keys(raw: bytes) -> list[str]:
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    keys: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        # Mail clients wrap armour in markup in HTML alternatives, and one
        # mangled block makes gpg abort the whole import. The plain-text
        # alternative carries the same key.
        if part.get_content_type() == 'text/html':
            continue
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            continue
        # Armour is pure ASCII, so undecodable bytes elsewhere in the part
        # can be replaced without touching the key.
        text = payload.decode('ascii', errors='replace').replace('\r\n', '\n')
        keys.extend(KEY_RE.findall(text))
    return keys


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Print every armoured PGP public key block found in an email.',
    )
    parser.add_argument('eml', help='key submission email')
    args = parser.parse_args()
    try:
        with open(args.eml, 'rb') as fh:
            keys = extract_keys(fh.read())
    except OSError as ex:
        parser.error(str(ex))
    if not keys:
        print(f'{args.eml}: no PGP public key blocks found', file=sys.stderr)
        return 1
    sys.stdout.write('\n'.join(keys) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
