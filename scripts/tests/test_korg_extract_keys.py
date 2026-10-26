# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Tests for scripts/korg-extract-keys.py.
#
# Key submissions arrive in whatever shape the sender's mail client
# produces: inline armour, attachments, base64 or quoted-printable
# transfer encodings. gpg only spots armour in plain text, so anything
# encoded used to be skipped silently. These tests feed the same real
# key through each shape and check that it survives intact.
#
# Run with: uv run --no-project --with pytest pytest scripts/tests
from __future__ import annotations

import email
import email.policy
import importlib.util
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol, cast

import pytest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / 'korg-extract-keys.py'
# Michal Wilczynski's real submission to keys@: the key is a base64
# application/pgp-keys attachment, which gpg could not see in the raw mail.
MICHAL_EML = HERE / 'fixtures' / 'michal-wilczynski-base64.eml'
MICHAL_FPR = 'CDB15B3219FE00E577C7E3FA65BA97B9EE9C1459'


class _Extractor(Protocol):
    def extract_keys(self, raw: bytes) -> list[str]: ...


def _load_extractor() -> _Extractor:
    # Dash in the filename blocks a plain import.
    spec = importlib.util.spec_from_file_location('korg_extract_keys', SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return cast(_Extractor, mod)


kek = _load_extractor()


@pytest.fixture(scope='module')
def armour() -> str:
    # Decoded independently of the code under test, so a bug there
    # can't hide by also corrupting the expected value.
    msg = email.message_from_bytes(MICHAL_EML.read_bytes())
    for part in msg.walk():
        if part.get_content_type() == 'application/pgp-keys':
            payload = part.get_payload(decode=True)
            assert isinstance(payload, bytes)
            return payload.decode('ascii')
    raise AssertionError('fixture has no application/pgp-keys part')


def _submission(
    body: str, cte: str | None = None, attachment: str | None = None, attach_cte: str = 'base64'
) -> bytes:
    msg = EmailMessage()
    msg['From'] = 'Dev <dev@example.org>'
    msg['To'] = 'keys@linux.kernel.org'
    msg['Subject'] = 'dev@example.org'
    msg.set_content(body, cte=cte)
    if attachment is not None:
        msg.add_attachment(
            attachment.encode('ascii'),
            maintype='application',
            subtype='pgp-keys',
            filename='key.asc',
            cte=attach_cte,
        )
    return msg.as_bytes(policy=email.policy.SMTP)


def _run_cli(path: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True)


@pytest.mark.parametrize(
    'make_raw',
    [
        pytest.param(lambda a: MICHAL_EML.read_bytes(), id='real-base64-attachment'),
        pytest.param(
            lambda a: _submission('Here is my key.\n', attachment=a, attach_cte='quoted-printable'),
            id='qp-attachment',
        ),
        # QP turns every '=' in the armour (padding, CRC line) into '=3D'.
        pytest.param(lambda a: _submission(a, cte='quoted-printable'), id='qp-inline'),
        pytest.param(lambda a: _submission(a, cte='base64'), id='base64-inline'),
        # What `gpg -a --export | mail` from README.rst produces.
        pytest.param(lambda a: _submission(a, cte='7bit'), id='7bit-inline'),
        # A saved .asc instead of an .eml must keep working.
        pytest.param(lambda a: a.encode('ascii'), id='bare-armour'),
    ],
)
def test_submission_shapes(armour: str, make_raw: Callable[[str], bytes]) -> None:
    """Every common way of mailing a key yields the exact armoured block."""
    assert kek.extract_keys(make_raw(armour)) == [armour.strip()]


def test_multiple_keys_all_returned(armour: str) -> None:
    """Some people export every key they have; none may be dropped."""
    # Distinct content so a dedup bug can't make one copy look like two.
    other = armour.replace('\n\n', '\nComment: second key\n\n', 1)
    raw = _submission(other, cte='quoted-printable', attachment=armour)
    assert kek.extract_keys(raw) == [other.strip(), armour.strip()]


def test_html_part_ignored(armour: str) -> None:
    """HTML markup inside armour would break gpg's import of every block."""
    msg = EmailMessage()
    msg.set_content(armour)
    msg.add_alternative('<pre>' + armour.replace('\n', '<br>\n') + '</pre>', subtype='html')
    assert kek.extract_keys(msg.as_bytes()) == [armour.strip()]


def test_no_key_is_an_error(tmp_path: Path) -> None:
    """A submission without a key must fail loudly, not import nothing."""
    eml = tmp_path / 'msg.eml'
    eml.write_bytes(_submission('I forgot to attach my key.\n'))
    res = _run_cli(eml)
    assert res.returncode == 1
    assert res.stdout == b''
    assert b'no PGP public key' in res.stderr


@pytest.mark.skipif(not shutil.which('gpg'), reason='gpg not installed')
def test_cli_output_imports_into_gpg(tmp_path: Path) -> None:
    """End to end: CLI output on the real mail is importable by gpg."""
    res = _run_cli(MICHAL_EML)
    assert res.returncode == 0
    gnupghome = str(tmp_path / 'gnupg')
    os.mkdir(gnupghome, 0o700)
    try:
        subprocess.run(
            ['gpg', '--batch', '-q', '--homedir', gnupghome, '--import'],
            input=res.stdout,
            capture_output=True,
            check=True,
        )
        listing = subprocess.run(
            ['gpg', '--batch', '--homedir', gnupghome, '--with-colons', '-k'],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    finally:
        subprocess.run(
            ['gpgconf', '--homedir', gnupghome, '--kill', 'gpg-agent'], capture_output=True
        )
    assert f'fpr:::::::::{MICHAL_FPR}:' in listing
