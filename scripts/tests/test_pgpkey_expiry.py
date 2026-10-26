# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Tests for scripts/pgpkey-expiry.py.
#
# The fixtures are real keys from this repo, trimmed to their
# self-signatures with "gpg --export-options export-minimal": sq only
# looks at those to decide whether a key is usable. They are keys that
# all current sq releases judge the same way; where releases disagree,
# as on DSA keys, the tests use sq output instead.
#
# Run with: uv run --no-project --with pytest pytest scripts/tests
from __future__ import annotations

import dataclasses
import importlib.machinery
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'fixtures'
SQ = shutil.which('sq')

# The dash in the file name rules out a plain import
_loader = importlib.machinery.SourceFileLoader(
    'pgpkey_expiry', str(HERE.parent / 'pgpkey-expiry.py')
)
_spec = importlib.util.spec_from_loader('pgpkey_expiry', _loader)
assert _spec is not None
pe = importlib.util.module_from_spec(_spec)
# dataclasses look up their own module in sys.modules
sys.modules['pgpkey_expiry'] = pe
_loader.exec_module(pe)

needs_sq = pytest.mark.skipif(SQ is None, reason='sq is not installed')

# One user per kind of key we have to handle
EXPIRING = '7E5F579280705609CB71CE04726C1CE741A7973F'  # [CS] primary, expires 2026-10-28
SUBKEY = '1D534C48C1D77177ADC309CB63291AE98A867C23'  # [C] never, [S] subkey 2027-04-09
SHA1 = '135A215986519D68DA5BC3F1958A4C04730462CC'  # SHA-1 binding on the primary
SHA1SUB = 'EE8BFB86BA22B26689DD33E9653928BBBB2638F1'  # SHA-1 subkey and UID bindings
NOSIGN = '61D3A531213E6BBFDC724AD0BC617823EE0B0057'  # [C] primary and an [E] subkey

USERS = {
    'expiring': EXPIRING,
    'subkey': SUBKEY,
    'sha1': SHA1,
    'sha1sub': SHA1SUB,
    'nosign': NOSIGN,
}

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def utc(
    year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0
) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def fixture_key(fpr: str) -> bytes:
    return (FIXTURES / f'{fpr[-16:]}.asc').read_bytes()


@needs_sq
@pytest.mark.parametrize(
    ('fpr', 'now', 'usable', 'expires', 'reason'),
    [
        pytest.param(EXPIRING, T0, True, utc(2026, 10, 28, 17, 44, 33), '', id='expiring'),
        pytest.param(
            EXPIRING, utc(2026, 11, 1), False, None, 'Expired on 2026-10-28', id='expired'
        ),
        # The primary key never expires, so the signing subkey decides
        pytest.param(SUBKEY, T0, True, utc(2027, 4, 9, 21, 58, 33), '', id='subkey-expiry'),
        pytest.param(SHA1, T0, False, None, 'SHA1 is not considered secure', id='sha1'),
        # sq only says "No binding signature" for the primary here; the
        # cause is in the subkey block, on a "because:" continuation line
        pytest.param(
            SHA1SUB,
            T0,
            False,
            None,
            '(SubkeyBinding) requiring second pre-image resistance, because SHA1',
            id='sha1-subkey',
        ),
        pytest.param(NOSIGN, T0, False, None, 'no signing key', id='no-signing-key'),
    ],
)
def test_inspect_key(
    fpr: str, now: datetime, usable: bool, expires: datetime | None, reason: str
) -> None:
    """Real keys get the verdict sq would give them, with a useful reason."""
    status = pe.inspect_key(fixture_key(fpr), now, SQ)
    assert status.fpr == fpr
    assert status.usable is usable
    assert status.expires == expires
    assert reason in status.reason


def _inspect_text(primary_expires: str, subkeys: list[str]) -> str:
    """sq inspect output for a [C] primary with [S] subkeys"""
    text = (
        '-: OpenPGP Certificate.\n\n'
        f'      Fingerprint: {"A" * 40}\n'
        f'  Expiration time: {primary_expires} UTC (creation time + 2years)\n'
        '        Key flags: certification\n'
    )
    for n, expires in enumerate(subkeys):
        text += (
            f'\n           Subkey: {str(n) * 40}\n'
            f'  Expiration time: {expires} UTC (creation time + 2years)\n'
            '        Key flags: signing\n'
        )
    return text


@pytest.mark.parametrize(
    ('text', 'expires'),
    [
        pytest.param(
            _inspect_text('2026-11-01 00:00:00', ['2027-11-01 00:00:00']),
            utc(2026, 11, 1),
            id='primary-caps-subkey',
        ),
        pytest.param(
            _inspect_text('2030-01-01 00:00:00', ['2026-11-01 00:00:00', '2027-11-01 00:00:00']),
            utc(2027, 11, 1),
            id='latest-signing-subkey-wins',
        ),
    ],
)
def test_key_status_expiry(text: str, expires: datetime) -> None:
    """A key signs until its last signing (sub)key expires, and a subkey
    can't outlive the primary key that binds it. No real key in pgpkeys
    has the first case, so these use made-up sq output."""
    status = pe.key_status(pe.parse_inspect(text))
    assert status.usable
    assert status.expires == expires


@pytest.mark.parametrize(
    ('text', 'reason'),
    [
        # SHA-1 user ID bindings and a modern subkey binding: the subkey
        # only repeats that the primary key has no binding, and the cause
        # is in the user ID block. No key in pgpkeys looks like this yet.
        pytest.param(
            '-: OpenPGP Certificate.\n\n'
            f'      Fingerprint: {"A" * 40}\n'
            '                   Invalid: No binding signature at time 2026-10-01T00:00:00Z\n'
            f'\n           Subkey: {"B" * 40}\n'
            '                   Invalid: primary key: No binding signature at time '
            '2026-10-01T00:00:00Z\n'
            '\n           UserID: Alice <alice@example.org>\n'
            '                   Invalid: Policy rejected non-revocation signature '
            '(PositiveCertification) requiring second pre-image resistance\n'
            '                   because: SHA1 is not considered secure\n',
            'Policy rejected non-revocation signature (PositiveCertification) '
            'requiring second pre-image resistance, because SHA1 is not considered secure',
            id='skips-repeats',
        ),
        # A DSA key as sq 1.4 and later see it; sq 1.3 still accepts
        # DSA for signing
        pytest.param(
            '-: OpenPGP Certificate.\n\n'
            f'      Fingerprint: {"A" * 40}\n'
            '                   Invalid: Policy rejected asymmetric algorithm: '
            'DSA3072 is not considered secure\n'
            f'\n           Subkey: {"B" * 40}\n'
            '                   Invalid: primary key: Policy rejected asymmetric algorithm, '
            'because DSA3072 is not considered secure\n',
            'Policy rejected asymmetric algorithm: DSA3072 is not considered secure',
            id='algorithm',
        ),
    ],
)
def test_why_unusable(text: str, reason: str) -> None:
    """The report names the cause sq gives, not the knock-on effects it
    lists first or repeats for every subkey. These use sq output, as no
    key in pgpkeys gets these verdicts from every sq release we run."""
    status = pe.key_status(pe.parse_inspect(text))
    assert not status.usable
    assert status.reason == reason


@pytest.mark.parametrize(
    ('left', 'threshold'),
    [
        (timedelta(days=31), None),
        (timedelta(days=30), 30),
        (timedelta(days=11), 30),
        (timedelta(days=10), 10),
        (timedelta(days=4), 10),
        (timedelta(days=3), 3),
        (timedelta(hours=1), 3),
    ],
)
def test_due_threshold(left: timedelta, threshold: int | None) -> None:
    """Each window starts on the day its threshold names."""
    assert pe.due_threshold(T0 + left, T0) == threshold


def _status(days: float | None, usable: bool = True) -> Any:
    expires = None if days is None else T0 + timedelta(days=days)
    return pe.KeyStatus(EXPIRING, usable, expires, '')


def _state(days: float, threshold: int) -> dict[str, Any]:
    expires = (T0 + timedelta(days=days)).isoformat()
    return {EXPIRING: {'expires': expires, 'threshold': threshold}}


@pytest.mark.parametrize(
    ('status', 'state', 'sent', 'kept'),
    [
        pytest.param(_status(25), {}, 30, False, id='first-warning'),
        pytest.param(_status(20), _state(20, 30), None, True, id='no-repeat-in-window'),
        pytest.param(_status(9), _state(9, 30), 10, False, id='next-threshold'),
        # After missed runs, one mail for where we are now, not one per
        # skipped threshold
        pytest.param(_status(2), _state(2, 30), 3, False, id='missed-runs'),
        # An extension that is still close starts the reminders over
        pytest.param(_status(25), _state(5, 10), 30, False, id='extended-still-close'),
        pytest.param(_status(45), {}, None, False, id='not-close-yet'),
        pytest.param(_status(200), _state(5, 10), None, False, id='extended-far'),
        pytest.param(_status(None), _state(5, 10), None, False, id='extended-forever'),
        # Expired and unusable keys go to the admin report, not to users
        pytest.param(_status(-1, usable=False), _state(1, 3), None, False, id='expired'),
    ],
)
def test_plan_notifications(
    status: Any, state: dict[str, Any], sent: int | None, kept: bool
) -> None:
    """Every threshold is mailed once per expiry date."""
    result = pe.Result('expiring', EXPIRING, status, '')
    notices, newstate = pe.plan_notifications([result], state, T0)
    assert [n.threshold for n in notices] == ([] if sent is None else [sent])
    assert newstate == (state if kept else {})


SETTINGS = pe.Settings(
    users='users',
    keyrepo='pgpkeys.git',
    state='state.json',
    mail_from='keys@example.org',
    mail_domain='example.org',
    docs_url='https://example.org/extend.html',
)


@pytest.mark.parametrize(
    ('archive_url', 'warned'),
    [
        pytest.param('https://example.org/archive/', True, id='public-archive'),
        pytest.param('', False, id='no-archive'),
    ],
)
def test_make_message(archive_url: str, warned: bool) -> None:
    """The reminder reaches the user, asks for the key back, and warns
    that replies are public only when they are."""
    settings = dataclasses.replace(SETTINGS, archive_url=archive_url)
    notice = pe.Notice('expiring', EXPIRING, utc(2026, 10, 28, 17, 44, 33), 30)
    msg = pe.make_message(notice, T0, settings)
    assert msg['From'] == 'keys@example.org'
    assert msg['To'] == 'expiring@example.org'
    assert msg['Subject'] == 'Your OpenPGP key 726C1CE741A7973F expires on 2026-10-28'
    assert msg['Message-ID'].endswith('@example.org>')
    # Vacation auto-replies would go to the public list
    assert msg['Auto-Submitted'] == 'auto-generated'
    # Quoted-printable would break the long gpg command for copy and paste
    assert msg['Content-Transfer-Encoding'] == '7bit'
    body = msg.get_content()
    assert EXPIRING in body
    assert '2026-10-28 17:44 UTC' in body
    assert 'https://example.org/extend.html' in body
    assert ('list archived at:\n\n    https://example.org/archive/\n' in body) is warned
    assert '30, 10 and 3 days' in body
    # So mail clients know where the signature starts
    assert '\n-- \nThe example.org keyring maintainers\n' in body


def test_read_users(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Comments and blank lines are skipped, and so is anything after the
    fingerprint; broken lines are skipped loudly."""
    users = tmp_path / 'users'
    users.write_text(f'# comment\n\nexpiring:{EXPIRING}:extra\nbroken\nsha1:{SHA1}\n')
    assert pe.read_users(users) == [('expiring', EXPIRING), ('sha1', SHA1)]
    assert 'broken' in capsys.readouterr().err


@pytest.mark.parametrize(
    ('text', 'notify', 'error'),
    [
        pytest.param('[main]\nkeyrepo = r\n', False, '[main] users', id='no-users'),
        pytest.param(
            '[main]\nusers = u\nkeyrepo = r\n',
            True,
            '[main] state, [mail] from, [mail] domain, [mail] docs-url',
            id='notify-needs-mail',
        ),
        pytest.param(
            '[main]\nusers = u\nkeyrepo = r\nstate = s\n'
            '[mail]\nfrom = f\ndomain = d\ndocs-url = x\nsmtp-port = smtp\n',
            True,
            'smtp-port',
            id='bad-port',
        ),
    ],
)
def test_load_settings_errors(tmp_path: Path, text: str, notify: bool, error: str) -> None:
    """A config that can't work says what is wrong with it, before
    anything runs."""
    cfg = tmp_path / 'pgpkey-expiry.conf'
    cfg.write_text(text)
    with pytest.raises(pe.ConfigError, match=re.escape(error)):
        pe.load_settings(str(cfg), notify=notify)


def test_load_settings_report_defaults(tmp_path: Path) -> None:
    """--report needs no mail settings, and the optional ones have
    sensible defaults."""
    cfg = tmp_path / 'pgpkey-expiry.conf'
    # A "%" would break configparser's default interpolation
    cfg.write_text('[main]\nusers = /u%1\nkeyrepo = /r\n')
    settings = pe.load_settings(str(cfg), notify=False)
    assert settings == pe.Settings(users='/u%1', keyrepo='/r')
    assert (settings.sq, settings.smtp_host, settings.smtp_port) == ('sq', 'localhost', 25)


@pytest.fixture
def setup(tmp_path: Path) -> dict[str, Path]:
    """A bare pgpkeys.git with the fixtures, a users file for them plus
    two users whose key the repo doesn't have, and a config for it all."""
    work = tmp_path / 'work'
    (work / 'keys').mkdir(parents=True)
    for path in FIXTURES.glob('*.asc'):
        shutil.copy(path, work / 'keys' / path.name)
    git = ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org']
    subprocess.run([*git, 'init', '-q', str(work)], check=True)
    subprocess.run([*git, '-C', str(work), 'add', '.'], check=True)
    subprocess.run([*git, '-C', str(work), 'commit', '-q', '-m', 'keys'], check=True)
    repo = tmp_path / 'pgpkeys.git'
    subprocess.run(['git', 'clone', '-q', '--bare', str(work), str(repo)], check=True)

    users = dict(USERS)
    users['gone'] = 'F' * 40
    # Same file name as the expiring key, but not the same key
    users['mismatch'] = '0' * 24 + EXPIRING[-16:]
    userfile = tmp_path / 'users'
    userfile.write_text(''.join(f'{user}:{fpr}\n' for user, fpr in users.items()))

    state = tmp_path / 'state.json'
    cfg = tmp_path / 'pgpkey-expiry.conf'
    cfg.write_text(
        f'[main]\nusers = {userfile}\nkeyrepo = {repo}\nstate = {state}\nsq = {SQ}\n'
        '[mail]\nfrom = keys@example.org\ndomain = example.org\n'
        'docs-url = https://example.org/extend.html\n'
        'smtp-host = mail.example.org\nsmtp-port = 2525\n'
    )
    return {'cfg': cfg, 'state': state}


def _run(setup: dict[str, Path], now: datetime, *args: str) -> int:
    return int(pe.main([*args, '--config', str(setup['cfg'])], now=now))


class FakeSMTP:
    sent: list[EmailMessage] = []
    servers: list[tuple[str, int]] = []

    def __init__(self, host: str, port: int) -> None:
        self.servers.append((host, port))

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def send_message(self, msg: EmailMessage) -> None:
        self.sent.append(msg)


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.sent = []
    FakeSMTP.servers = []
    monkeypatch.setattr(pe.smtplib, 'SMTP', FakeSMTP)
    return FakeSMTP


@needs_sq
def test_notify(setup: dict[str, Path], smtp: type[FakeSMTP]) -> None:
    """Only the user with a key about to expire gets mail, through the
    configured server, once per threshold, across runs."""
    assert _run(setup, utc(2026, 10, 10), '--notify') == 0
    assert [m['To'] for m in smtp.sent] == ['expiring@example.org']
    assert smtp.servers == [('mail.example.org', 2525)]
    state = json.loads(setup['state'].read_text())
    assert state[EXPIRING]['threshold'] == 30

    # The next day changes nothing
    assert _run(setup, utc(2026, 10, 11), '--notify') == 0
    assert len(smtp.sent) == 1

    assert _run(setup, utc(2026, 10, 20), '--notify') == 0
    assert len(smtp.sent) == 2
    assert json.loads(setup['state'].read_text())[EXPIRING]['threshold'] == 10


@needs_sq
def test_notify_dry_run(
    setup: dict[str, Path], smtp: type[FakeSMTP], capsys: pytest.CaptureFixture[str]
) -> None:
    """A dry run shows the mail and leaves no trace."""
    assert _run(setup, utc(2026, 10, 10), '--notify', '--dry-run') == 0
    assert 'To: expiring@example.org' in capsys.readouterr().out
    assert smtp.servers == []
    assert not setup['state'].exists()


@needs_sq
def test_report(setup: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    """Every key that needs an admin's attention is in the right section."""
    assert _run(setup, T0, '--report') == 0
    sections = {}
    for section in capsys.readouterr().out.strip().split('\n\n'):
        title, *lines = section.splitlines()
        sections[title.split(' (')[0]] = {line.split()[0] for line in lines}
    assert sections == {
        'Rejected by sequoia': {'sha1', 'sha1sub', 'nosign'},
        'Not found in pgpkeys.git': {'gone', 'mismatch'},
        'Expiring within 30 days': {'expiring'},
    }
