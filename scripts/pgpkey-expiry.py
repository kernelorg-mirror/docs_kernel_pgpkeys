#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# kernel.org runs a copy of this from cron. This one, in pgpkeys.git, is
# the one to review and send changes against; keep both identical.
"""Warn users before their OpenPGP key in pgpkeys.git expires.

Users and their key fingerprints come from a users file, and the keys
themselves from pgpkeys.git. A key is usable when sq accepts at least
one of its signing (sub)keys, which is the same check kup-server does.

  --notify  run daily from cron: mail <user>@<domain> 30, 10 and 3 days
            before their key stops being usable
  --report  run by hand: list keys that need an admin's attention, i.e.
            keys sq rejects now and keys that aren't in pgpkeys.git

Keys that are already expired or rejected are only ever in the report:
mailing them from cron would repeat the same news forever.

All settings come from the --config file:

  [main]
  # One "user:fingerprint" per line; anything after a second colon is
  # ignored, and so are blank lines and lines starting with "#"
  users = /path/to/users
  # A clone of pgpkeys.git, bare or not
  keyrepo = /path/to/pgpkeys.git
  # Where --notify remembers which reminders it has sent
  state = /path/to/pgpkey-expiry.json
  # Optional, found in $PATH by default
  sq = /usr/bin/sq

  [mail]
  # Reminders come from here, and replies with the updated key go here
  from = keys@example.org
  # Reminders go to <user>@<domain>
  domain = example.org
  # The steps to extend a key, linked from the reminder
  docs-url = https://example.org/extend-your-key.html
  # Optional: if replies are archived in public, the reminder says where
  archive-url = https://example.org/archive/
  # Optional, these are the defaults
  smtp-host = localhost
  smtp-port = 25
  # Optional: comma-separated addresses that get a blind copy of each
  # reminder
  bcc = admin@example.org

Only [main] users and keyrepo are needed for --report.
"""

from __future__ import annotations

import argparse
import configparser
import fcntl
import json
import os
import re
import smtplib
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Any

# Days before expiry to send a reminder. The first one leaves time for
# the user to extend the key and for an admin to import it by hand.
THRESHOLDS = (30, 10, 3)

BLOCK_RE = re.compile(r'^\s*(Fingerprint|Subkey|UserID): (.*)$')
# sq's reason why a key, subkey or user ID is not usable; a cause that
# doesn't fit goes on "because:" lines under it
INVALID_RE = re.compile(r'^\s*Invalid: (.*)$')
BECAUSE_RE = re.compile(r'^\s*because: (.*)$')
EXPIRES_RE = re.compile(r'^\s*Expiration time: (\S+ \S+) UTC')
FLAGS_RE = re.compile(r'^\s*Key flags: (.*)$')
# sq says this first when it rejects every binding signature; the cause
# follows it, or is in another block (a SHA-1 user ID binding, say)
NO_BINDING_RE = re.compile(r'^No binding signature at time \S+(: )?')

MAIL_BODY = """\
Hello,

This is an automated reminder from {domain}. The OpenPGP key we have
on record for your {domain} account "{user}" stops working for
signing on {expires}:

    {fpr}

After that date, tools like git, b4 and sq will no longer accept
signatures made with this key. You can fix this by extending the
expiration date of your key. The steps are described here:

    {docs}

When you are done, reply to this message with your updated public key
attached. You can export it with:

    gpg --armor --export {fpr} > {keyid}.asc

{archive}\
We send this reminder {thresholds} days before your key expires. It
stops once the {domain} keyring has your new expiration date.

"""
MAIL_ARCHIVE = """\
Please note that your reply goes to {mail_from}, a public mailing
list archived at:

    {archive_url}

Only send your public key and nothing that you want to keep private.

"""
# Kept out of MAIL_BODY: editors strip the space that makes "-- " a
# signature separator for mail clients
MAIL_SIGNATURE = '-- \nThe {domain} keyring maintainers\n'


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    users: str
    keyrepo: str
    sq: str = 'sq'
    # Only needed for --notify
    state: str = ''
    mail_from: str = ''
    mail_domain: str = ''
    docs_url: str = ''
    archive_url: str = ''
    smtp_host: str = 'localhost'
    smtp_port: int = 25
    bcc: tuple[str, ...] = ()


@dataclass
class Block:
    """One key, subkey or user ID in sq inspect output"""

    kind: str
    ident: str
    signing: bool = False
    expires: datetime | None = None
    invalid: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KeyStatus:
    fpr: str
    usable: bool
    # When the key stops being usable; None if it never does
    expires: datetime | None
    # Why sq rejects the key, if it does
    reason: str


@dataclass(frozen=True)
class Result:
    user: str
    fpr: str
    # None when there is no key to check; problem then says why
    status: KeyStatus | None
    problem: str


@dataclass(frozen=True)
class Notice:
    user: str
    fpr: str
    expires: datetime
    threshold: int


def load_settings(path: str, notify: bool) -> Settings:
    # No interpolation: URLs may contain "%"
    cfg = configparser.ConfigParser(interpolation=None)
    if not cfg.read(path):
        raise ConfigError(f'cannot read {path}')
    required = [('main', 'users'), ('main', 'keyrepo')]
    if notify:
        required += [('main', 'state'), ('mail', 'from'), ('mail', 'domain'), ('mail', 'docs-url')]
    missing = [f'[{s}] {k}' for s, k in required if not cfg.get(s, k, fallback='')]
    if missing:
        raise ConfigError(f'{path} does not set {", ".join(missing)}')
    try:
        smtp_port = cfg.getint('mail', 'smtp-port', fallback=25)
    except ValueError as ex:
        raise ConfigError(f'{path}: [mail] smtp-port: {ex}') from ex
    return Settings(
        users=cfg.get('main', 'users'),
        keyrepo=cfg.get('main', 'keyrepo'),
        sq=cfg.get('main', 'sq', fallback='sq'),
        state=cfg.get('main', 'state', fallback=''),
        mail_from=cfg.get('mail', 'from', fallback=''),
        mail_domain=cfg.get('mail', 'domain', fallback=''),
        docs_url=cfg.get('mail', 'docs-url', fallback=''),
        archive_url=cfg.get('mail', 'archive-url', fallback=''),
        smtp_host=cfg.get('mail', 'smtp-host', fallback='localhost'),
        smtp_port=smtp_port,
        bcc=tuple(a.strip() for a in cfg.get('mail', 'bcc', fallback='').split(',') if a.strip()),
    )


def parse_inspect(text: str) -> list[Block]:
    blocks: list[Block] = []
    for line in text.splitlines():
        if m := BLOCK_RE.match(line):
            blocks.append(Block(m.group(1), m.group(2).strip()))
        elif not blocks:
            continue
        elif m := INVALID_RE.match(line):
            blocks[-1].invalid.append(m.group(1).strip())
        elif (m := BECAUSE_RE.match(line)) and blocks[-1].invalid:
            blocks[-1].invalid[-1] += f', because {m.group(1).strip()}'
        elif m := EXPIRES_RE.match(line):
            expires = datetime.fromisoformat(m.group(1).replace(' ', 'T'))
            blocks[-1].expires = expires.replace(tzinfo=timezone.utc)
        elif m := FLAGS_RE.match(line):
            blocks[-1].signing = 'signing' in m.group(1).split(', ')
    return blocks


def _earliest(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def why_unusable(blocks: list[Block]) -> str:
    for block in blocks:
        for reason in block.invalid:
            cause = NO_BINDING_RE.sub('', reason)
            # Subkeys repeat the primary key's reason, which came first
            if cause and not cause.startswith('primary key: '):
                return cause
    # sq is fine with every part of the key, but none of it can sign
    return 'no signing key'


def key_status(blocks: list[Block]) -> KeyStatus:
    keys = [b for b in blocks if b.kind != 'UserID']
    primary = keys[0]
    # sq only shows the flags of a binding it accepts, so a block that
    # says "signing" and has no "Invalid:" is a key that can sign now
    live = [b for b in keys if b.signing and not b.invalid]
    if not live:
        return KeyStatus(primary.ident, False, None, why_unusable(blocks))
    # A subkey can't outlive the primary key that binds it
    ends = [_earliest(b.expires, primary.expires) for b in live]
    expires = None if None in ends else max(e for e in ends if e is not None)
    return KeyStatus(primary.ident, True, expires, '')


def inspect_key(data: bytes, now: datetime, sq: str) -> KeyStatus:
    # --home=none: judge the key only by itself, as kup-server does
    cmd = [sq, '--home=none', '--time', now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'inspect']
    out = subprocess.run(cmd, input=data, capture_output=True, check=True).stdout
    # User IDs aren't always UTF-8
    return key_status(parse_inspect(out.decode(errors='replace')))


def read_users(path: str | os.PathLike[str]) -> list[tuple[str, str]]:
    users: list[tuple[str, str]] = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            user, _, rest = line.partition(':')
            fpr = rest.partition(':')[0]
            if not user or not fpr:
                print(f'Corrupted line in {path}: {line}', file=sys.stderr)
                continue
            users.append((user, fpr.upper()))
    return users


def read_key(keyrepo: str, fpr: str) -> bytes | None:
    # From the committed tree, not a working tree: one consistent
    # snapshot, even while the repo is being updated. Expired keys are
    # moved to keys/expired/, and their holders still need reporting.
    for subdir in ('keys', 'keys/expired'):
        cmd = ['git', '--git-dir', keyrepo, 'show', f'HEAD:{subdir}/{fpr[-16:]}.asc']
        res = subprocess.run(cmd, capture_output=True)
        if res.returncode == 0:
            return res.stdout
    return None


def check_keys(settings: Settings, now: datetime) -> list[Result]:
    results: list[Result] = []
    for user, fpr in read_users(settings.users):
        data = read_key(settings.keyrepo, fpr)
        if data is None:
            results.append(Result(user, fpr, None, 'no key file'))
            continue
        try:
            status = inspect_key(data, now, settings.sq)
        except subprocess.CalledProcessError as ex:
            err = ex.stderr.decode(errors='replace').strip()
            results.append(Result(user, fpr, None, f'sq failed: {err}'))
            continue
        if status.fpr != fpr:
            results.append(Result(user, fpr, None, f'key file has {status.fpr}'))
            continue
        results.append(Result(user, fpr, status, ''))
    return results


def due_threshold(expires: datetime, now: datetime) -> int | None:
    left = expires - now
    for threshold in sorted(THRESHOLDS):
        if left <= timedelta(days=threshold):
            return threshold
    return None


def plan_notifications(
    results: list[Result], state: dict[str, Any], now: datetime
) -> tuple[list[Notice], dict[str, Any]]:
    """Returns the notices to send, and the state of keys that need none.

    The state maps a fingerprint to the expiry date and the threshold it
    was last mailed for. A key that is no longer about to expire drops
    out of it, so a key that comes close again starts over.
    """
    notices: list[Notice] = []
    newstate: dict[str, Any] = {}
    for res in results:
        status = res.status
        if status is None or not status.usable or status.expires is None:
            continue
        threshold = due_threshold(status.expires, now)
        if threshold is None:
            continue
        prev = state.get(res.fpr)
        # A new expiry date means the key was extended: start over
        if (
            prev is not None
            and prev['expires'] == status.expires.isoformat()
            and prev['threshold'] <= threshold
        ):
            newstate[res.fpr] = prev
            continue
        notices.append(Notice(res.user, res.fpr, status.expires, threshold))
    return notices, newstate


def make_message(notice: Notice, now: datetime, settings: Settings) -> EmailMessage:
    msg = EmailMessage()
    keyid = notice.fpr[-16:]
    domain = settings.mail_domain
    msg['From'] = settings.mail_from
    msg['To'] = f'{notice.user}@{domain}'
    msg['Subject'] = f'Your OpenPGP key {keyid} expires on {notice.expires:%Y-%m-%d}'
    msg['Date'] = format_datetime(now)
    msg['Message-ID'] = make_msgid(domain=settings.mail_from.rpartition('@')[2])
    # Replies may go to a public list, and vacation replies would too
    msg['Auto-Submitted'] = 'auto-generated'
    archive = ''
    if settings.archive_url:
        archive = MAIL_ARCHIVE.format(
            mail_from=settings.mail_from, archive_url=settings.archive_url
        )
    *first, last = (str(t) for t in sorted(THRESHOLDS, reverse=True))
    body = MAIL_BODY.format(
        domain=domain,
        user=notice.user,
        expires=f'{notice.expires:%Y-%m-%d %H:%M} UTC',
        fpr=notice.fpr,
        keyid=keyid,
        docs=settings.docs_url,
        archive=archive,
        thresholds=f'{", ".join(first)} and {last}',
    )
    # The text is ASCII, and quoted-printable would break the long gpg
    # command for anyone who copies it from the raw message
    msg.set_content(body + MAIL_SIGNATURE.format(domain=domain), cte='7bit')
    return msg


def format_report(results: list[Result], now: datetime) -> str:
    rejected: list[str] = []
    missing: list[str] = []
    expiring: list[str] = []
    window = timedelta(days=max(THRESHOLDS))
    for res in sorted(results, key=lambda r: r.user):
        status = res.status
        if status is None:
            missing.append(f'  {res.user:<20} {res.fpr}  {res.problem}')
        elif not status.usable:
            rejected.append(f'  {res.user:<20} {res.fpr}  {status.reason}')
        elif status.expires is not None and status.expires - now <= window:
            expiring.append(f'  {res.user:<20} {res.fpr}  {status.expires:%Y-%m-%d}')
    sections = [
        ('Rejected by sequoia', rejected),
        ('Not found in pgpkeys.git', missing),
        (f'Expiring within {max(THRESHOLDS)} days', expiring),
    ]
    return '\n\n'.join('\n'.join([f'{title} ({len(lines)}):', *lines]) for title, lines in sections)


def load_state(path: str) -> dict[str, Any]:
    try:
        with open(path) as fh:
            state: dict[str, Any] = json.load(fh)
            return state
    except FileNotFoundError:
        return {}


def save_state(path: str, state: dict[str, Any]) -> None:
    # Replaced in one go, so a crash leaves the old state, not half of it
    tmp = f'{path}.new'
    with open(tmp, 'w') as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def notify(settings: Settings, now: datetime, dry_run: bool) -> int:
    state = load_state(settings.state)
    notices, newstate = plan_notifications(check_keys(settings, now), state, now)
    if dry_run:
        for notice in notices:
            msg = make_message(notice, now, settings)
            if settings.bcc:
                msg['Bcc'] = ', '.join(settings.bcc)
            print(msg.as_string())
        return 0

    failed = False
    if notices:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
            for notice in notices:
                try:
                    msg = make_message(notice, now, settings)
                    # Bcc only in the envelope, so it never shows in the headers
                    smtp.send_message(msg, to_addrs=[msg['To'], *settings.bcc])
                except smtplib.SMTPException as ex:
                    # Not in the state, so the next run tries again
                    print(f'Mailing {notice.user} failed: {ex}', file=sys.stderr)
                    failed = True
                    continue
                newstate[notice.fpr] = {
                    'expires': notice.expires.isoformat(),
                    'threshold': notice.threshold,
                }
    save_state(settings.state, newstate)
    return 1 if failed else 0


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--notify', action='store_true', help='mail users whose key expires soon')
    mode.add_argument('--report', action='store_true', help='list keys that need an admin')
    parser.add_argument('--config', required=True, help='settings file, see above')
    parser.add_argument('--dry-run', action='store_true', help='print mail instead of sending')
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.config, notify=args.notify)
    except ConfigError as ex:
        parser.error(str(ex))
    # Everything in one run is judged at the same moment
    if now is None:
        now = datetime.now(timezone.utc)

    if args.report:
        print(format_report(check_keys(settings, now), now))
        return 0

    # One run at a time, or two runs could mail the same reminder
    with open(f'{settings.state}.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('pgpkey-expiry is already running, not starting another', file=sys.stderr)
            return 0
        return notify(settings, now, args.dry_run)


if __name__ == '__main__':
    sys.exit(main())
