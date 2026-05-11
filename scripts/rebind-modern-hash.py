#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Help OpenPGP keyholders rebind UIDs and subkeys with a modern hash
# algorithm.
#
# A key generated in the GnuPG era (typically pre-2018) usually has its
# UID self-signatures and subkey binding signatures made with SHA-1.
# Modern Sequoia-based OpenPGP tools reject those bindings under
# StandardPolicy, so trust paths through the cert break silently and
# encryption to it can quietly fail ("no suitable encryption subkey",
# addresses appear missing from the cert).
#
# This is the keyholder-side companion to scripts/resign-modern-hash.py
# (which re-signs YOUR third-party certifications on OTHER maintainers'
# keys). The audit tool tells you which side you need to act on:
#
#     ./scripts/weak-hash-audit.py --uids       # are *you* in this list?
#     ./scripts/weak-hash-audit.py --cross-sigs # have *you* issued weak certs?
#
# This script reads a public key, reports which UIDs and subkeys are
# weakly bound, and prints the exact gpg(1) command sequence the
# keyholder should run to rebind them with SHA-512. The script never
# modifies your real keyring during INSPECTION (file/stdin/--from-repo
# input goes through a temp GNUPGHOME); the printed rebind commands
# are what actually modify your keyring -- and only when you choose
# to run them.
#
# Workflow:
#
#   1. Inspect your key (one of):
#        ./scripts/rebind-modern-hash.py                       # auto-detect
#        ./scripts/rebind-modern-hash.py --fpr <FPR>           # from your keyring
#        ./scripts/rebind-modern-hash.py --from-repo <KEYID>   # canonical pgpkeys.git copy
#        ./scripts/rebind-modern-hash.py /path/to/key.asc      # arbitrary file
#        gpg --export <FPR> | ./scripts/rebind-modern-hash.py  # stdin
#
#   2. Copy-paste the printed gpg command sequence into your shell.
#
#   3. Re-run with --verify to confirm:
#        ./scripts/rebind-modern-hash.py --verify --fpr <FPR>
#
#   4. Submit the rebound key for inclusion in the canonical kernel
#      keyring:
#        gpg --export --armor <FPR> | mail -s your@email.addr keys@linux.kernel.org
#
#   5. Once your update has been merged and you have pulled, confirm
#      the canonical view:
#        ./scripts/rebind-modern-hash.py --verify --from-repo <KEYID>
#
# Auto-detection: with no arguments, the tool finds your secret keys in
# your default GNUPGHOME, picks one whose pubkey is in pgpkeys.git/keys/,
# and inspects it. If multiple match (or none do), pass --fpr explicitly.
#
# Requires only gpg(1) -- no python OpenPGP library needed.

from __future__ import annotations

import argparse
import datetime
import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import NoReturn, Protocol, TypedDict, cast

HERE = os.path.dirname(os.path.abspath(__file__))

# OpenPGP fingerprints are 40 hex chars (V4) or 64 hex chars (V5).
# We accept either, with optional 0x prefix and embedded whitespace
# stripped (gpg's keylist output spaces fingerprints in groups of 4).
_FPR_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_KEYID_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{16}$")

# RFC 4880 §9.4 hash algorithm IDs that Sequoia's StandardPolicy
# rejects on binding signatures. Anything not in this set is treated
# as "modern enough".
WEAK_HASH_IDS = {1, 2, 3}  # MD5, SHA-1, RIPEMD-160
HASH_NAMES = {
    1: "MD5",
    2: "SHA1",
    3: "RIPEMD160",
    8: "SHA256",
    9: "SHA384",
    10: "SHA512",
    11: "SHA224",
    12: "SHA3-256",
    14: "SHA3-512",
}

# RFC 4880 §5.2.1 signature class codes that bind a UID or a subkey
# to the primary key. gpg formats these as "<hex>x" in --with-colons
# output (the trailing 'x' marks the sig as exportable).
UID_BINDING_CLASSES = {"10x", "11x", "12x", "13x", "10", "11", "12", "13"}
SUBKEY_BINDING_CLASSES = {"18x", "18"}

TARGET_HASH = "SHA512"

TAG_OK = "[ OK ]"
TAG_WEAK = "[WEAK]"
TAG_NONE = "[????]"
TAG_SKIP = "[SKIP]"

# Per `gnupg/doc/DETAILS`, field 2 of pub/sub/uid/uat colon records
# is a validity letter. Any item flagged revoked / expired / invalid
# is dead from gpg's point of view -- rebinding a revoked subkey
# would silently fail, and rebinding an expired one with our
# `--quick-set-expire <existing-expiration>` line would either
# resurrect it (if we passed '0') or be a no-op. Skip both.
SKIP_VALIDITIES = {"r": "revoked", "e": "expired", "i": "invalid"}

SUBMIT_ADDRESS = "keys@linux.kernel.org"


class _Sig(TypedDict):
    issuer_keyid: str
    created: int
    sig_class: str
    hash_id: int


class _Item(TypedDict):
    """A UID, user-attribute or subkey parsed out of `gpg --list-sigs`.

    `fingerprint` is meaningful only when kind == "subkey" (otherwise "");
    `expire_unix` likewise (otherwise 0). Keeping both fields on every
    item lets the rest of the script use a single TypedDict and gives
    mypy a consistent shape to reason about.
    """

    kind: str  # 'uid' | 'user-attr' | 'subkey'
    validity: str
    label: str
    fingerprint: str
    gpg_index: int
    expire_unix: int
    sigs: list[_Sig]


class _RmhModule(Protocol):
    """Subset of resign-modern-hash.py's surface that this script uses."""

    def _repo_keys_dir(self) -> str: ...
    def _list_secret_fprs(self, gpg: str) -> list[str]: ...
    def _repo_keyids(self, keys_dir: str) -> set[str]: ...


def _die(msg: str) -> NoReturn:
    print("error: %s" % msg, file=sys.stderr)
    sys.exit(2)


def _gpg_bin() -> str:
    gpg = shutil.which("gpg")
    if gpg is None:
        _die("gpg not found in PATH; install gpg first")
    return gpg


def _load_helpers() -> _RmhModule:
    """Import named helpers from sibling resign-modern-hash.py.

    Same pattern as scripts/weak-hash-audit.py. The sibling has a dash
    in its filename so a plain `import` won't work; we load it via
    importlib instead. Module-level code in the sibling is just imports
    + definitions (main() is gated behind `if __name__ == "__main__"`),
    so this is side-effect free.
    """
    spec = importlib.util.spec_from_file_location(
        "resign_modern_hash",
        os.path.join(HERE, "resign-modern-hash.py"),
    )
    if spec is None or spec.loader is None:
        _die("failed to locate resign-modern-hash.py beside this script")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return cast("_RmhModule", mod)


def _run_gpg(
    gpg: str,
    args: list[str],
    gnupghome: str | None = None,
    stdin_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run gpg with optional GNUPGHOME override.

    Returns the CompletedProcess. Errors are surfaced with the gpg
    stderr prefixed by 'gpg: ' so the operator can see what gpg
    actually complained about.
    """
    env = os.environ.copy()
    if gnupghome:
        env["GNUPGHOME"] = gnupghome
    try:
        return subprocess.run(  # noqa: S603
            [gpg, *args],
            env=env,
            input=stdin_bytes,
            capture_output=True,
            check=check,
        )
    except subprocess.CalledProcessError as ex:
        msg = ex.stderr.decode(errors="replace").strip() or "(no stderr)"
        _die("gpg %s failed (rc=%d): %s" % (" ".join(args), ex.returncode, msg))


def _import_to_temp(gpg: str, key_bytes: bytes) -> tuple[str, str]:
    """Import key bytes into a fresh GNUPGHOME and return (path, fpr).

    The tempdir lives until the script exits; the caller is expected
    to leave it for the OS to clean up. Strict 0o700 mode keeps the
    imported key from leaking to other users on shared workstations.
    """
    if not key_bytes:
        _die("no key data provided")
    tmpd = tempfile.mkdtemp(prefix="rebind-modern-hash-")
    os.chmod(tmpd, 0o700)
    _run_gpg(gpg, ["--import"], gnupghome=tmpd, stdin_bytes=key_bytes)
    res = _run_gpg(gpg, ["--with-colons", "--list-keys"], gnupghome=tmpd)
    for line in res.stdout.decode().splitlines():
        fields = line.split(":")
        if fields and fields[0] == "fpr":
            return tmpd, fields[9]
    _die("could not find a fingerprint after importing the key")


def _from_repo_path(rmh: _RmhModule, raw: str) -> str:
    """Resolve --from-repo input (keyid or fpr) to keys/<KEYID>.asc."""
    s = raw.replace(" ", "").replace(":", "").upper()
    if s.startswith("0X"):
        s = s[2:]
    # _FPR_RE/_KEYID_RE both allow an optional 0x prefix, but s has it
    # stripped already; matching the bare hex form below is unambiguous.
    if _FPR_RE.match(s):
        # Full fingerprint -- the file is named for the last 16 chars.
        s = s[-16:]
    elif not _KEYID_RE.match(s):
        _die("invalid --from-repo value %r (expected keyid or fingerprint)" % raw)
    keys_dir = rmh._repo_keys_dir()
    path = os.path.join(keys_dir, "%s.asc" % s)
    if not os.path.isfile(path):
        _die("no key %s.asc in %s" % (s, keys_dir))
    return path


def _auto_detect_fpr(gpg: str, rmh: _RmhModule) -> str:
    """Pick the user's secret key whose pubkey is in pgpkeys.git/keys/.

    Returns the fingerprint of the secret key to inspect. Mirrors the
    selection logic in resign-modern-hash.py's _find_signer so a
    maintainer's muscle memory carries between the two scripts.
    """
    fprs = rmh._list_secret_fprs(gpg)
    if not fprs:
        _die(
            "no secret keys in your default GNUPGHOME; "
            "pass --fpr, --from-repo, or a path"
        )
    keys_dir = rmh._repo_keys_dir()
    repo_ids = rmh._repo_keyids(keys_dir)
    in_repo = [f for f in fprs if f[-16:].upper() in repo_ids]

    if len(in_repo) == 1:
        return in_repo[0]
    if len(in_repo) > 1:
        cand = "\n".join("  %s" % f for f in in_repo)
        _die(
            "multiple of your secret keys are present in pgpkeys.git;\n"
            "pass --fpr FPR to choose one:\n%s" % cand
        )
    if len(fprs) == 1:
        print(
            "warning: %s is not present in keys/; rebound result will not\n"
            "         propagate via the kernel WoT until you submit your\n"
            "         pubkey to %s." % (fprs[0], SUBMIT_ADDRESS),
            file=sys.stderr,
        )
        return fprs[0]
    cand = "\n".join("  %s" % f for f in fprs)
    _die(
        "multiple secret keys, none matching a key in pgpkeys.git;\n"
        "pass --fpr FPR to choose one:\n%s" % cand
    )


def _resolve_input(
    args: argparse.Namespace,
) -> tuple[str, str | None, str]:
    """Return (gpg_bin, gnupghome_or_None, fpr) for the key to inspect.

    --fpr uses the user's real keyring (no GNUPGHOME override). A path
    or stdin gets imported to a temp keyring so the user's real keyring
    is never touched. --from-repo is sugar for the path form, pointing
    at pgpkeys.git/keys/<KEYID>.asc. With no input at all, we
    auto-detect from the user's secret keys (preferring those in keys/).
    """
    gpg = _gpg_bin()

    explicit = sum(
        1 for v in (args.fpr, args.from_repo, args.source) if v
    )
    stdin_pipe = (
        args.source == "-" or (args.source is None and not sys.stdin.isatty())
    )
    if explicit > 1:
        _die("pass at most one of --fpr, --from-repo, or a path/-")

    if args.from_repo:
        rmh = _load_helpers()
        path = _from_repo_path(rmh, args.from_repo)
        with open(path, "rb") as fh:
            data = fh.read()
        tmpd, fpr = _import_to_temp(gpg, data)
        return gpg, tmpd, fpr

    if args.fpr:
        fpr_input = str(args.fpr).replace(" ", "").replace(":", "")
        if not _FPR_RE.match(fpr_input):
            _die(
                "invalid fingerprint %r (expected 40 or 64 hex chars)"
                % args.fpr
            )
        return gpg, None, fpr_input

    if stdin_pipe:
        data = sys.stdin.buffer.read()
        if not data:
            _die("no key data on stdin")
        tmpd, fpr = _import_to_temp(gpg, data)
        return gpg, tmpd, fpr

    if args.source is None:
        rmh = _load_helpers()
        fpr_auto = _auto_detect_fpr(gpg, rmh)
        return gpg, None, fpr_auto

    try:
        with open(args.source, "rb") as fh:
            data = fh.read()
    except OSError as ex:
        _die("could not load %s: %s" % (args.source, ex))
    tmpd, fpr = _import_to_temp(gpg, data)
    return gpg, tmpd, fpr


def _parse_list_sigs(
    output: str,
) -> tuple[str, str | None, list[_Item]]:
    """Parse `gpg --with-colons --list-sigs` into a structured view.

    Returns (primary_fpr, primary_keyid, items). items is a list of
    dicts in cert order, one per UID / user-attribute / subkey. gpg
    numbers UIDs and subkeys starting from 1 in the order they appear,
    so we increment a counter alongside the parse to produce indices
    the keyholder can paste into --edit-key without recounting.

    Field layout per `gnupg/doc/DETAILS`:
      pub: primary key
      sub: subkey (preceded by `pub`, followed by its `fpr` and sigs)
      uid: user id (field 10 = userid string)
      uat: user attribute
      fpr: full fingerprint of the most recent pub/sub (field 10)
      sig: signature (field 5 = issuer key id, field 6 = creation
           timestamp, field 11 = sig class like '13x' or '18x',
           field 16 = hash algo id)
    """
    primary_fpr: str | None = None
    primary_keyid: str | None = None
    items: list[_Item] = []
    current: _Item | None = None
    awaiting_subkey_fpr = False
    uid_idx = 0
    subkey_idx = 0

    def _flush() -> None:
        nonlocal current
        if current is not None:
            items.append(current)
        current = None

    for line in output.splitlines():
        fields = line.split(":")
        if not fields:
            continue
        rec = fields[0]
        if rec == "pub":
            _flush()
            awaiting_subkey_fpr = False
        elif rec == "fpr":
            fp = fields[9] if len(fields) > 9 else ""
            if primary_fpr is None:
                primary_fpr = fp
                primary_keyid = fp[-16:]
            elif (
                awaiting_subkey_fpr
                and current is not None
                and current["kind"] == "subkey"
            ):
                current["fingerprint"] = fp
                awaiting_subkey_fpr = False
        elif rec == "uid":
            _flush()
            uid_idx += 1
            current = {
                "kind": "uid",
                "validity": fields[1] if len(fields) > 1 else "",
                "label": fields[9] if len(fields) > 9 else "?",
                "fingerprint": "",
                "gpg_index": uid_idx,
                "expire_unix": 0,
                "sigs": [],
            }
        elif rec == "uat":
            _flush()
            uid_idx += 1
            current = {
                "kind": "user-attr",
                "validity": fields[1] if len(fields) > 1 else "",
                "label": "<image attribute>",
                "fingerprint": "",
                "gpg_index": uid_idx,
                "expire_unix": 0,
                "sigs": [],
            }
        elif rec == "sub":
            _flush()
            subkey_idx += 1
            expire_raw = fields[6] if len(fields) > 6 else ""
            current = {
                "kind": "subkey",
                "validity": fields[1] if len(fields) > 1 else "",
                "label": "?",
                "fingerprint": "",
                "gpg_index": subkey_idx,
                "expire_unix": int(expire_raw) if expire_raw.isdigit() else 0,
                "sigs": [],
            }
            awaiting_subkey_fpr = True
        elif rec == "sig" and current is not None:
            issuer_keyid = fields[4] if len(fields) > 4 else ""
            created_raw = fields[5] if len(fields) > 5 else ""
            sig_class = fields[10] if len(fields) > 10 else ""
            hash_raw = fields[15] if len(fields) > 15 else ""
            current["sigs"].append(
                {
                    "issuer_keyid": issuer_keyid,
                    "created": int(created_raw) if created_raw.isdigit() else 0,
                    "sig_class": sig_class,
                    "hash_id": int(hash_raw) if hash_raw.isdigit() else 0,
                }
            )
    _flush()

    if primary_fpr is None:
        _die("gpg --list-sigs returned no public key (was the import empty?)")

    return primary_fpr, primary_keyid, items


def _classify(
    item: _Item, primary_keyid: str | None
) -> tuple[str, _Sig | None]:
    """Return ('strong'|'weak'|'none', latest_self_sig_or_None)."""
    if item["kind"] in ("uid", "user-attr"):
        classes = UID_BINDING_CLASSES
    elif item["kind"] == "subkey":
        classes = SUBKEY_BINDING_CLASSES
    else:
        return ("strong", None)

    candidates = [
        s
        for s in item["sigs"]
        if s["sig_class"] in classes
        and s["issuer_keyid"].upper() == (primary_keyid or "").upper()
    ]
    if not candidates:
        return ("none", None)
    latest = max(candidates, key=lambda s: s["created"])
    return ("weak" if latest["hash_id"] in WEAK_HASH_IDS else "strong", latest)


def _hash_label(sig: _Sig | None) -> str:
    if sig is None:
        return "(none)"
    return HASH_NAMES.get(sig["hash_id"], "id=%d" % sig["hash_id"])


def _skip_reason(item: _Item) -> str | None:
    """Return 'revoked'/'expired'/'invalid' or None for an item."""
    return SKIP_VALIDITIES.get(item.get("validity", ""))


def _expire_arg(item: _Item) -> str:
    """Format the existing subkey expiration for `gpg --quick-set-expire`.

    gpg accepts YYYY-MM-DD or 0 (never). expire_unix == 0 means the
    subkey has no expiration; preserve that semantics by passing '0'.
    """
    exp = item.get("expire_unix") or 0
    if not exp:
        return "0"
    return datetime.datetime.fromtimestamp(
        exp, datetime.timezone.utc
    ).strftime("%Y-%m-%d")


def _print_status(
    items: list[_Item], primary_keyid: str | None
) -> tuple[list[_Item], list[_Item]]:
    """Print a per-target status line; return only actionable weak items.

    Items whose validity says revoked/expired/invalid are tagged
    [SKIP] and never make it into the weak-lists -- the recipe
    shouldn't try to rebind dead bindings.
    """
    weak_uids: list[_Item] = []
    weak_subkeys: list[_Item] = []
    label_for = {"uid": "UID", "user-attr": "Img", "subkey": "Sub"}
    for it in items:
        if it["kind"] not in label_for:
            continue
        status, latest = _classify(it, primary_keyid)
        line_label = it["label"]
        if it["kind"] == "subkey":
            line_label = "0x%s" % (it["fingerprint"][-16:] or it["label"])
        skip = _skip_reason(it)
        if skip:
            tag = TAG_SKIP
            line_label = "%s (%s)" % (line_label, skip)
        else:
            tag = {"strong": TAG_OK, "weak": TAG_WEAK, "none": TAG_NONE}[status]
        print(
            "  %s %s #%-2d %-9s  %s"
            % (
                tag,
                label_for[it["kind"]],
                it["gpg_index"],
                _hash_label(latest),
                line_label,
            )
        )
        if status == "weak" and not skip:
            if it["kind"] == "subkey":
                weak_subkeys.append(it)
            else:
                weak_uids.append(it)
    return weak_uids, weak_subkeys


def _primary_uid_label(items: list[_Item]) -> str | None:
    """Return the label of the primary real UID, or None if none found.

    gpg --list-sigs and --list-keys emit the primary UID first in their
    output for any given key. The colons format doesn't expose a
    dedicated "this is primary" flag on uid records, but the ordering
    is documented and stable across gpg versions, so the first item
    whose kind is "uid" is the original primary. User-attribute (uat)
    packets are skipped -- a photo can technically be flagged primary
    but it's vanishingly rare and we wouldn't want to restore one
    anyway.
    """
    for it in items:
        if it["kind"] == "uid":
            return it["label"]
    return None


def _print_recipe(
    primary_fp: str,
    weak_uids: list[_Item],
    weak_subkeys: list[_Item],
    primary_uid_label: str | None,
) -> None:
    """Print the gpg command sequence to rebind the weak items."""
    print()
    print("To rebind with %s, run the commands below in your shell. The" % TARGET_HASH)
    print("primary key must be available (or your subkeys' secret material;")
    print("smartcards are fine).")
    print()

    fpr = primary_fp.upper()

    weak_real_uids = [u for u in weak_uids if u["kind"] == "uid"]
    weak_attrs = [u for u in weak_uids if u["kind"] != "uid"]

    if weak_real_uids:
        # --quick-set-primary-uid issues a fresh self-signature on the
        # named UID using --cert-digest-algo. Walking each weak UID in
        # turn rebinds every one with SHA-512 with no interactive
        # ceremony (no /dev/tty prompts, no setpref dance). Each call
        # also flips the primary-uid flag onto the named UID, so we
        # emit a final restore-primary line below to put the original
        # primary back where it belongs.
        print("# Rebind UIDs (%d weak)." % len(weak_real_uids))
        for u in weak_real_uids:
            print(
                "gpg --cert-digest-algo %s --quick-set-primary-uid %s %s"
                % (TARGET_HASH, fpr, shlex.quote(u["label"]))
            )
        print()

    if weak_attrs:
        # Image / user-attribute packets have no userid string, so
        # --quick-set-primary-uid can't address them. Fall back to
        # --edit-key; this is rare in practice (very few legacy keys
        # carry photo IDs), so we don't optimise the UX further.
        print(
            "# %d weak image/user-attribute binding(s) need an interactive rebind:"
            % len(weak_attrs)
        )
        print("gpg --cert-digest-algo %s --edit-key %s" % (TARGET_HASH, fpr))
        for u in weak_attrs:
            print(
                "#   then at the gpg> prompt: uid %d ; primary ; save" % u["gpg_index"]
            )
        print()

    if weak_subkeys:
        # --quick-set-expire is non-interactive and re-signs the subkey
        # binding signature. Pass the existing expiration so we don't
        # silently change it; '0' means "never expires".
        print("# Rebind subkeys (%d weak):" % len(weak_subkeys))
        for sk in weak_subkeys:
            exp = _expire_arg(sk)
            label = "expires %s" % exp if exp != "0" else "never expires"
            print(
                "gpg --cert-digest-algo %s --quick-set-expire %s %s %s  # %s"
                % (TARGET_HASH, fpr, exp, sk["fingerprint"], label)
            )
        print()

    if (weak_real_uids or weak_attrs) and primary_uid_label is not None:
        # Each --quick-set-primary-uid / interactive `primary` call
        # above flipped the primary flag onto whichever UID it touched
        # last, demoting the keyholder's original primary. Issue one
        # more --quick-set-primary-uid on the original to put it back.
        # Idempotent in the unusual edge case where the original
        # primary was already last in the rebind list.
        print("# Restore the original primary UID flag.")
        print(
            "gpg --cert-digest-algo %s --quick-set-primary-uid %s %s"
            % (TARGET_HASH, fpr, shlex.quote(primary_uid_label))
        )
        print()

    print("Then verify the result:")
    print("  %s --verify --fpr %s" % (sys.argv[0], fpr))
    print()
    print(
        "Once everything reads [ OK ], submit the rebound key for inclusion"
    )
    print("in the canonical kernel keyring:")
    print(
        "  gpg --export --armor %s | mail -s your@email.addr %s"
        % (fpr, SUBMIT_ADDRESS)
    )


def main() -> NoReturn:
    parser = argparse.ArgumentParser(
        description=(
            "Detect weakly-bound UIDs/subkeys and print a gpg rebind recipe. "
            "With no arguments, auto-detects which of your secret keys is in "
            "pgpkeys.git/keys/ and inspects that one."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modern Sequoia-based OpenPGP tools reject UID and subkey\n"
            "binding signatures made with SHA-1 (typical for keys from the\n"
            "pre-2018 GnuPG era). This tool reports which bindings on a\n"
            "key still use a weak hash, and prints the gpg(1) command\n"
            "sequence the keyholder should run to rebind them with SHA-512.\n"
            "\n"
            "This is the keyholder-side companion to scripts/resign-modern-hash.py.\n"
            "To check whether your key is in the keyholder-rebind list, run\n"
            "scripts/weak-hash-audit.py --uids and look for your keyid.\n"
            "\n"
            "The script never modifies your real keyring during inspection;\n"
            "the printed rebind commands are what change your keyring -- and\n"
            "only when you choose to run them. After running them, re-run\n"
            "with --verify to confirm.\n"
        ),
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Path to a public key file, or '-' to read from stdin.",
    )
    parser.add_argument(
        "--fpr",
        help="Inspect a key already in your gpg keyring, by fingerprint.",
    )
    parser.add_argument(
        "--from-repo",
        metavar="KEYID",
        help=(
            "Inspect a key from pgpkeys.git/keys/<KEYID>.asc. Accepts a "
            "16-char keyid or a full fingerprint (only the last 16 chars "
            "are used to find the file). Lets you check the canonical "
            "view without exporting your key from your own keyring first."
        ),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Suppress the rebind recipe; just report status. Useful as a "
        "post-rebind check or in CI.",
    )
    args = parser.parse_args()

    gpg, gnupghome, fpr = _resolve_input(args)

    res = _run_gpg(gpg, ["--with-colons", "--list-sigs", fpr], gnupghome=gnupghome)
    primary_fp, primary_keyid, items = _parse_list_sigs(
        res.stdout.decode("utf-8", errors="replace")
    )

    print("Cert: %s" % primary_fp.upper())
    print()
    weak_uids, weak_subkeys = _print_status(items, primary_keyid)
    print()

    if not weak_uids and not weak_subkeys:
        print("All UID and subkey bindings use modern hash algorithms.")
        sys.exit(0)

    print(
        "Found %d weakly-bound UID(s) and %d weakly-bound subkey(s)."
        % (len(weak_uids), len(weak_subkeys))
    )

    if not args.verify:
        _print_recipe(
            primary_fp, weak_uids, weak_subkeys, _primary_uid_label(items)
        )

    sys.exit(1)


if __name__ == "__main__":
    main()
