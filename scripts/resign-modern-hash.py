#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Find Linux kernel developer PGP keys (in keys/*.asc) that you have
# certified using a weak hash algorithm (SHA-1, MD5, RIPEMD-160), and
# emit a batch script that re-signs them with SHA-512 and exports the
# result for submission to keys@linux.kernel.org.
#
# Background: OpenPGP cross-signatures (certifications) made before
# ~2018 typically used SHA-1. Modern Sequoia-based tools (e.g. sq)
# reject these under StandardPolicy, so trust paths through affected
# keys break silently. This tool fixes YOUR exportable certifications
# on OTHER maintainers' keys; for your own key's UID/subkey self-sigs
# see the keyholder-side rebind-modern-hash.py tool elsewhere.
#
# Two sources are consulted: the keys/ directory of pgpkeys.git, and
# your default gpg keyring. Some old SHA-1 sigs that you once issued
# may have been stripped from the repo by periodic refreshes or by
# wotmate's --import-clean re-export, but they often still live in
# your local keyring. Such "lost" sigs are flagged with +local and
# re-signing them locally + re-exporting will restore them in the
# repo. Pass --skip-local-keyring to disable this second pass.
#
# Workflow (assumes the recommended setup where the maintainer's [C]
# secret key lives on a separate offline/air-gapped workstation, away
# from their everyday gpg keyring):
#
#   1. On your PUBLIC workstation (with pgpkeys.git checked out and your
#      everyday gpg keyring), generate the batch script:
#        ./scripts/resign-modern-hash.py
#        ./scripts/resign-modern-hash.py --signer <FPR>   # multiple keys
#
#   2. Review the [WEAK] entries in the printed status. Two files are
#      written alongside:
#        - resign-weak-keys.sh: a reviewable driver script.
#        - weak-keys.asc:       a public-key bundle of the affected
#                               target keys, with a header listing them.
#
#   3. Copy BOTH files to your OFFLINE workstation (the one with your
#      [C] secret key or smartcard). Edit the .sh if you want to skip
#      any keys, then run it there. The script re-issues your certs
#      with SHA-512 and writes resigned-keys.asc next to itself. The
#      .asc bundle is imported only if any target keys are missing from
#      your offline keyring (usually a no-op).
#
#   4. Copy resigned-keys.asc back to your public workstation and mail
#      it to keys@linux.kernel.org for inclusion into the canonical
#      keyring.
#
#   5. Verify the result later (after your re-signed certs land in the
#      repo and you've git pulled):
#        ./scripts/resign-modern-hash.py --verify
#
# IMPORTANT: the recipe uses --force-sign-key. Without that flag,
# gpg --quick-sign-key silently does nothing when any sig from the
# issuer already exists on a UID -- which is precisely our case.
#
# Old SHA-1 sig packets stay in the target cert after re-signing; the
# new SHA-512 sig supersedes by creation timestamp. The keyring
# maintainer cleans stale packets when re-exporting.
#
# Requires only gpg(1) -- no python OpenPGP library needed.

from __future__ import annotations

import argparse
import datetime
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from typing import Literal, NoReturn, TypedDict


class Sig(TypedDict):
    issuer_keyid: str
    created: int
    sig_class: str
    hash_id: int


class Uid(TypedDict):
    label: str
    validity: str
    is_attr: bool
    sigs: list[Sig]


class Entry(TypedDict):
    primary_fpr: str
    primary_keyid: str
    primary_uid: str
    primary_validity: str
    primary_bits: int
    primary_algo: int
    uids: list[Uid]


class UidSummary(TypedDict):
    label: str
    is_attr: bool
    status: str
    sig: Sig | None
    level: int | None


class Analysis(TypedDict):
    has_weak_exportable: bool
    has_weak_local: bool
    any_signed: bool
    max_level: int
    weak_exportable_uids: list[str]
    weak_local_uids: list[str]
    uid_summaries: list[UidSummary]


ActionKind = Literal["resign", "export"]
ActionTuple = tuple[Entry, Analysis, ActionKind]

# OpenPGP fingerprints are 40 hex chars (V4) or 64 hex chars (V5).
_FPR_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")

# RFC 4880 §9.4 hash algorithm IDs that Sequoia's StandardPolicy
# rejects on binding signatures. Anything not in this set is modern.
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

# RFC 4880 §5.2.1 sig class codes for third-party certifications.
# gpg formats exportable sigs with trailing 'x'; local sigs have no 'x'.
EXPORTABLE_CERT_CLASSES = {"10x", "11x", "12x", "13x"}
LOCAL_CERT_CLASSES = {"10", "11", "12", "13"}
CERT_REVOC_CLASSES = {"30x", "30"}
ALL_CERT_CLASSES = EXPORTABLE_CERT_CLASSES | LOCAL_CERT_CLASSES | CERT_REVOC_CLASSES

# Hex class prefix → gpg --default-cert-level value (0..3).
CLASS_TO_LEVEL = {"10": 0, "11": 1, "12": 2, "13": 3}

TARGET_HASH = "SHA512"

TAG_OK = "[ OK ]"
TAG_WEAK = "[WEAK]"
TAG_SKIP = "[SKIP]"
TAG_SEND = "[SEND]"

# Per gnupg/doc/DETAILS, field 2 validity flags for dead UIDs.
SKIP_VALIDITIES = {"r": "revoked", "e": "expired", "i": "invalid"}

# RFC 4880 §9.1 public-key algorithm IDs.
# DSA (17) and Elgamal (16) are legacy algorithms; re-signing onto them
# would only extend the life of certs that modern implementations already
# distrust. RSA variants 1/2/3 are acceptable only at >= 2048 bits.
_DSA_ELGAMAL_ALGOS = {16, 17}
_RSA_ALGOS = {1, 2, 3}
MIN_RSA_BITS = 2048

BATCH_SH = "resign-weak-keys.sh"
BATCH_KEYS = "weak-keys.asc"
BATCH_ASC = "resigned-keys.asc"
SUBMIT_ADDRESS = "keys@linux.kernel.org"


def _die(msg: str) -> NoReturn:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def _gpg_bin() -> str:
    gpg = shutil.which("gpg")
    if gpg is None:
        _die("gpg not found in PATH; install gpg first")
    return gpg


def _run_gpg(
    gpg: str, args: list[str], check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    """Run gpg and return the CompletedProcess.

    With check=True (default) a non-zero exit calls _die(). Pass
    check=False to inspect the return code yourself (used for the
    bulk repo import where individual key issues are not fatal).
    """
    proc = subprocess.run(  # noqa: S603
        [gpg, *args],
        capture_output=True,
        check=False,
    )
    if check and proc.returncode != 0:
        msg = proc.stderr.decode(errors="replace").strip() or "(no stderr)"
        argstr = " ".join(args[:2])
        _die(f"gpg {argstr} failed (rc={proc.returncode}): {msg}")
    return proc


def _repo_keys_dir() -> str:
    """Return absolute path to the keys/ directory in pgpkeys.git.

    Resolved relative to this script's location so the tool works whether
    invoked as ./scripts/resign-modern-hash.py from the repo root or via
    an absolute path from elsewhere.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.normpath(os.path.join(here, "..", "keys"))
    if not os.path.isdir(candidate):
        _die(f"expected keys/ directory at {candidate}")
    return candidate


def _repo_keyids(keys_dir: str) -> set[str]:
    """Return set of 16-char key IDs (uppercase) named in keys_dir."""
    out = set()
    for name in os.listdir(keys_dir):
        if not name.endswith(".asc"):
            continue
        stem = name[:-4]
        if re.match(r"^[0-9A-Fa-f]{16}$", stem):
            out.add(stem.upper())
    return out


def _list_secret_fprs(gpg: str) -> list[str]:
    """Return list of primary-key fingerprints from the user's default GNUPGHOME."""
    res = _run_gpg(gpg, ["--with-colons", "--list-secret-keys"])
    fprs = []
    pending_primary = False
    for line in res.stdout.decode().splitlines():
        fields = line.split(":")
        if not fields:
            continue
        if fields[0] == "sec":
            pending_primary = True
        elif fields[0] in ("ssb", "pub", "sub"):
            pending_primary = False
        elif fields[0] == "fpr" and pending_primary:
            fp = fields[9] if len(fields) > 9 else ""
            if fp:
                fprs.append(fp)
            pending_primary = False
    return fprs


def _find_signer(gpg: str, explicit_fpr: str | None, keys_dir: str) -> str:
    """Return the certifier's primary key fingerprint.

    If --signer was given, validate and return it. Otherwise auto-detect
    from the user's default GNUPGHOME secret keys, preferring keys whose
    pubkey already appears in pgpkeys.git/keys/. Exits if the choice is
    ambiguous.
    """
    if explicit_fpr:
        fpr = explicit_fpr.replace(" ", "").replace(":", "").upper()
        if not _FPR_RE.match(fpr):
            _die(f"invalid fingerprint {explicit_fpr!r} (expected 40 or 64 hex chars)")
        # Strip optional 0x prefix so downstream string comparisons against
        # parsed-from-colons fingerprints (which are never 0x-prefixed) work.
        if fpr.startswith("0X"):
            fpr = fpr[2:]
        return fpr

    fprs = _list_secret_fprs(gpg)
    if not fprs:
        _die("no secret keys found in your keyring; pass --signer FPR")

    repo_ids = _repo_keyids(keys_dir)
    in_repo = [f for f in fprs if f[-16:].upper() in repo_ids]

    if len(in_repo) == 1:
        return in_repo[0]
    if len(in_repo) > 1:
        cand = "\n".join(f"  {f}" for f in in_repo)
        _die(
            "multiple of your secret keys are present in pgpkeys.git;\n"
            f"pass --signer FPR to choose one:\n{cand}"
        )

    # No secret key matched a key in the repo.
    if len(fprs) == 1:
        print(
            f"warning: {fprs[0]} is not present in keys/; re-signed certs will not\n"
            "         propagate via the kernel WoT until your pubkey is added\n"
            "         to pgpkeys.git.",
            file=sys.stderr,
        )
        return fprs[0]
    cand = "\n".join(f"  {f}" for f in fprs)
    _die(
        "multiple secret keys, none matching a key in pgpkeys.git;\n"
        f"pass --signer FPR to choose one:\n{cand}"
    )


def _build_repo_keyring(gpg: str, keys_dir: str) -> str:
    """Create a temp GNUPGHOME with all keys/*.asc imported.

    Returns the homedir path. Caller is responsible for shutil.rmtree.

    The import is intentionally done *without* --import-clean: gpg's
    cleaning pass strips third-party signatures whose issuer key is not
    yet present in the keyring at the moment that target is imported.
    Because we import keys in alphabetical order in a single invocation,
    enabling --import-clean would silently drop any sig from a
    later-alphabet issuer onto an earlier-alphabet target -- exactly
    the data we need to analyse.
    """
    home = tempfile.mkdtemp(prefix="resign-modern-hash-")
    os.chmod(home, 0o700)
    asc_files = sorted(
        os.path.join(keys_dir, n)
        for n in os.listdir(keys_dir)
        if n.endswith(".asc")
    )
    if not asc_files:
        _die(f"no *.asc files in {keys_dir}")
    # gpg may return non-zero if individual keys have non-fatal issues
    # (e.g. unsupported packets); we tolerate that for the bulk import.
    _run_gpg(
        gpg,
        ["--homedir", home, "--import", *asc_files],
        check=False,
    )
    return home


def _local_keyring_entries(gpg: str, repo_fprs: set[str]) -> list[Entry]:
    """Parse the user's default gpg keyring, return entries for keys in repo_fprs.

    Uses the user's $GNUPGHOME (no --homedir override) so we see the actual
    historical state of their keyring -- including SHA-1 sigs they once
    issued that may since have been stripped from the repo by periodic
    refreshes or by wotmate's --import-clean re-export.

    repo_fprs is a set of full uppercase fingerprints (40 or 64 hex chars).
    Entries whose primary FPR is not in that set are filtered out so we
    only consider keys that actually live in pgpkeys.git/keys/.
    """
    res = _run_gpg(gpg, ["--with-colons", "--list-sigs"], check=False)
    if res.returncode != 0:
        # An empty/missing default keyring is a normal "no local data"
        # condition, not an error -- fall back to repo-only analysis.
        return []
    entries = _parse_keyring_sigs(res.stdout.decode("utf-8", errors="replace"))
    return [
        e for e in entries
        if e["primary_fpr"] and e["primary_fpr"].upper() in repo_fprs
    ]


def _merge_entries(
    repo_entry: Entry | None, local_entry: Entry | None
) -> Entry:
    """Combine sig sets from a repo entry and a local-keyring entry.

    Returns an entry dict with the same shape as _parse_keyring_sigs, where
    each UID's sigs list is the union of both sources. Sigs are deduped on
    (issuer_keyid, created, sig_class, hash_id) so identical sigs that
    appear in both sources don't get double-counted by the analyser.

    UIDs are matched by (label, is_attr); a UID present in only one source
    is included as-is. The repo entry's primary metadata (validity, bits,
    algo) wins -- the repo is the canonical view of the key for kernel WoT
    purposes; the local keyring is consulted only for sig recovery.

    At least one of repo_entry/local_entry must be non-None.
    """
    if repo_entry is None and local_entry is None:
        raise ValueError("at least one of repo_entry/local_entry must be non-None")
    if local_entry is None:
        assert repo_entry is not None
        return repo_entry
    if repo_entry is None:
        return local_entry

    out: Entry = {
        "primary_fpr": repo_entry["primary_fpr"],
        "primary_keyid": repo_entry["primary_keyid"],
        "primary_uid": repo_entry["primary_uid"],
        "primary_validity": repo_entry["primary_validity"],
        "primary_bits": repo_entry["primary_bits"],
        "primary_algo": repo_entry["primary_algo"],
        "uids": [],
    }

    local_index = {(u["label"], u["is_attr"]): u for u in local_entry["uids"]}
    used_local = set()

    for ruid in repo_entry["uids"]:
        sigs = list(ruid["sigs"])
        seen = {
            (s["issuer_keyid"], s["created"], s["sig_class"], s["hash_id"])
            for s in sigs
        }
        key = (ruid["label"], ruid["is_attr"])
        luid = local_index.get(key)
        if luid is not None:
            for lsig in luid["sigs"]:
                lkey = (
                    lsig["issuer_keyid"],
                    lsig["created"],
                    lsig["sig_class"],
                    lsig["hash_id"],
                )
                if lkey not in seen:
                    sigs.append(lsig)
                    seen.add(lkey)
            used_local.add(key)
        out["uids"].append(
            {
                "label": ruid["label"],
                "validity": ruid["validity"],
                "is_attr": ruid["is_attr"],
                "sigs": sigs,
            }
        )

    for luid in local_entry["uids"]:
        key = (luid["label"], luid["is_attr"])
        if key in used_local:
            continue
        out["uids"].append(
            {
                "label": luid["label"],
                "validity": luid["validity"],
                "is_attr": luid["is_attr"],
                "sigs": list(luid["sigs"]),
            }
        )

    return out


def _local_only_strong_uids(
    repo_entry: Entry | None,
    local_entry: Entry | None,
    merged_analysis: Analysis,
    signer_keyid: str,
) -> list[str]:
    """List UID labels where the local keyring has an exportable strong cert
    by signer that's missing from the repo's copy of the key.

    Only UIDs whose merged binding is 'strong' are considered: a strong cert
    on a UID with a weak self-binding wouldn't be accepted by Sequoia
    anyway, so there's no point forwarding it until the keyholder fixes
    their own self-sigs.

    Returns [] if local_entry is None or has nothing the repo lacks.
    Used to detect the propagation-gap case: the certifier already
    re-signed locally with a modern hash, but the new sig hasn't made
    it back to pgpkeys.git yet.
    """
    if local_entry is None:
        return []

    strong_uid_labels = {
        us["label"]
        for us in merged_analysis["uid_summaries"]
        if us["status"] == "strong" and not us["is_attr"]
    }
    if not strong_uid_labels:
        return []

    repo_sigs = set()
    if repo_entry is not None:
        for uid in repo_entry["uids"]:
            for s in uid["sigs"]:
                if s["issuer_keyid"].upper() != signer_keyid.upper():
                    continue
                if s["sig_class"] not in EXPORTABLE_CERT_CLASSES:
                    continue
                repo_sigs.add(
                    (
                        uid["label"],
                        uid["is_attr"],
                        s["created"],
                        s["hash_id"],
                        s["sig_class"],
                    )
                )

    extras = []
    seen = set()
    for uid in local_entry["uids"]:
        if uid["is_attr"]:
            continue
        if uid["label"] not in strong_uid_labels:
            continue
        for s in uid["sigs"]:
            if s["issuer_keyid"].upper() != signer_keyid.upper():
                continue
            if s["sig_class"] not in EXPORTABLE_CERT_CLASSES:
                continue
            if s["hash_id"] in WEAK_HASH_IDS:
                continue
            sig_key = (
                uid["label"],
                uid["is_attr"],
                s["created"],
                s["hash_id"],
                s["sig_class"],
            )
            if sig_key in repo_sigs:
                continue
            if uid["label"] not in seen:
                extras.append(uid["label"])
                seen.add(uid["label"])
                break
    return extras


def _local_only_sample_sig(
    local_entry: Entry, signer_keyid: str, uid_labels: list[str]
) -> Sig | None:
    """Return the most recent exportable strong cert sig from signer in
    local_entry on any UID in uid_labels. Used for status-line hash display.
    """
    best: Sig | None = None
    label_set = set(uid_labels)
    for uid in local_entry["uids"]:
        if uid["label"] not in label_set:
            continue
        for s in uid["sigs"]:
            if s["issuer_keyid"].upper() != signer_keyid.upper():
                continue
            if s["sig_class"] not in EXPORTABLE_CERT_CLASSES:
                continue
            if s["hash_id"] in WEAK_HASH_IDS:
                continue
            if best is None or s["created"] > best["created"]:
                best = s
    return best


def _unescape_uid(s: str) -> str:
    """Decode gpg --with-colons field 10 escape sequences."""
    return s.replace("\\x3a", ":").replace("\\\\", "\\").replace("\\n", "\n")


def _parse_keyring_sigs(output: str) -> list[Entry]:
    """Parse `gpg --with-colons --list-sigs` for the whole keyring.

    Returns a list of key-entry dicts, one per primary key:
      primary_fpr     -- full fingerprint string
      primary_keyid   -- last 16 chars of primary_fpr
      primary_uid     -- label of the first UID (for display)
      uids            -- list of UID dicts (see below)

    Each UID dict:
      label           -- uid string (or '<image attribute>' for uat)
      validity        -- gpg validity letter ('r', 'e', 'i', ...)
      is_attr         -- True for user-attribute (photo) packets
      sigs            -- list of sig dicts

    Each sig dict:
      issuer_keyid    -- field 5 from gpg colons (16 hex chars)
      created         -- creation timestamp (int)
      sig_class       -- e.g. '13x', '13', '30x'
      hash_id         -- RFC 4880 hash algorithm id (int)
    """
    entries: list[Entry] = []
    current: Entry | None = None
    current_uid: Uid | None = None
    awaiting_primary_fpr = False

    def _flush_uid() -> None:
        nonlocal current_uid
        if current is not None and current_uid is not None:
            current["uids"].append(current_uid)
        current_uid = None

    for line in output.splitlines():
        fields = line.split(":")
        if not fields:
            continue
        rec = fields[0]

        if rec == "pub":
            _flush_uid()
            if current is not None:
                entries.append(current)
            current = {
                "primary_fpr": "",
                "primary_keyid": "",
                "primary_uid": "",
                "primary_validity": fields[1] if len(fields) > 1 else "",
                "primary_bits": (
                    int(fields[2])
                    if len(fields) > 2 and fields[2].isdigit() else 0
                ),
                "primary_algo": (
                    int(fields[3])
                    if len(fields) > 3 and fields[3].isdigit() else 0
                ),
                "uids": [],
            }
            current_uid = None
            awaiting_primary_fpr = True

        elif rec == "fpr":
            fp = fields[9] if len(fields) > 9 else ""
            if awaiting_primary_fpr and fp and current is not None:
                current["primary_fpr"] = fp
                current["primary_keyid"] = fp[-16:]
                awaiting_primary_fpr = False

        elif rec == "uid":
            if current is None:
                continue
            _flush_uid()
            label = _unescape_uid(fields[9] if len(fields) > 9 else "?")
            current_uid = {
                "label": label,
                "validity": fields[1] if len(fields) > 1 else "",
                "is_attr": False,
                "sigs": [],
            }
            if not current["primary_uid"]:
                current["primary_uid"] = label

        elif rec == "uat":
            if current is None:
                continue
            _flush_uid()
            current_uid = {
                "label": "<image attribute>",
                "validity": fields[1] if len(fields) > 1 else "",
                "is_attr": True,
                "sigs": [],
            }

        elif rec == "sub":
            # Subkeys follow UIDs; we don't inspect subkey binding sigs.
            _flush_uid()

        elif rec == "sig" and current_uid is not None:
            issuer_keyid = fields[4] if len(fields) > 4 else ""
            created_raw = fields[5] if len(fields) > 5 else ""
            sig_class = fields[10] if len(fields) > 10 else ""
            hash_raw = fields[15] if len(fields) > 15 else ""
            current_uid["sigs"].append(
                {
                    "issuer_keyid": issuer_keyid,
                    "created": int(created_raw) if created_raw.isdigit() else 0,
                    "sig_class": sig_class,
                    "hash_id": int(hash_raw) if hash_raw.isdigit() else 0,
                }
            )

    _flush_uid()
    if current is not None:
        entries.append(current)

    # Defensive: only keep entries whose primary fingerprint is a valid
    # 40 or 64 hex string. gpg should never emit anything else, but this
    # closes the door on malformed input ever flowing into shell-arg or
    # filesystem-path construction downstream (e.g. _recipe_args feeding
    # gpg, or _write_batch_file building keys/<keyid>.asc paths).
    return [e for e in entries if _FPR_RE.match(e["primary_fpr"])]


def _classify_uid_cert(
    uid: Uid, signer_keyid: str, primary_keyid: str
) -> tuple[str, Sig | None, int | None]:
    """Return (status, latest_sig_or_None, cert_level_or_None).

    Examines the certifier's most recent sig on this UID and returns:
      'strong'                -- latest sig uses a modern hash
      'weak_exportable'       -- latest sig is exportable and uses a weak hash
      'weak_local'            -- latest sig is local-only and uses a weak hash
      'revoked_by_issuer'     -- certifier has revoked their certification
      'unsigned'              -- certifier has not signed this UID
      'skipped_<reason>'      -- UID is revoked / expired / invalid
      'skipped_weak_binding'  -- UID's own self-sig uses a weak hash; resigning
                                 it would be pointless (Sequoia still rejects it)

    cert_level is the gpg --default-cert-level integer (0..3), only
    meaningful for weak_* and strong statuses.
    """
    skip = SKIP_VALIDITIES.get(uid.get("validity", ""))
    if skip:
        return (f"skipped_{skip}", None, None)

    self_sigs = [
        s for s in uid["sigs"]
        if s["issuer_keyid"].upper() == primary_keyid.upper()
        and s["sig_class"] in (EXPORTABLE_CERT_CLASSES | LOCAL_CERT_CLASSES)
    ]
    if self_sigs:
        latest_self = max(self_sigs, key=lambda s: s["created"])
        if latest_self["hash_id"] in WEAK_HASH_IDS:
            return ("skipped_weak_binding", None, None)

    candidates = [
        s
        for s in uid["sigs"]
        if s["issuer_keyid"].upper() == signer_keyid.upper()
        and s["sig_class"] in ALL_CERT_CLASSES
    ]
    if not candidates:
        return ("unsigned", None, None)

    latest = max(candidates, key=lambda s: s["created"])

    if latest["sig_class"] in CERT_REVOC_CLASSES:
        return ("revoked_by_issuer", latest, None)

    class_prefix = latest["sig_class"].rstrip("x")
    level = CLASS_TO_LEVEL.get(class_prefix, 0)

    if latest["hash_id"] in WEAK_HASH_IDS:
        is_local = latest["sig_class"] not in EXPORTABLE_CERT_CLASSES
        return ("weak_local" if is_local else "weak_exportable", latest, level)
    return ("strong", latest, level)


def _analyze_key_certs(entry: Entry, signer_keyid: str) -> Analysis:
    """Summarize the certifier's certification status on one key.

    Returns a dict describing which UIDs need re-signing and at what
    level, along with metadata for status display and recipe generation.
    Local (non-exportable) certs are tracked but not actioned -- the
    pgpkeys.git keyring only carries exportable WoT sigs.
    """
    weak_exportable: list[str] = []
    weak_local: list[str] = []
    max_level = 0
    any_signed = False
    uid_summaries: list[UidSummary] = []

    for uid in entry["uids"]:
        status, sig, level = _classify_uid_cert(
            uid, signer_keyid, entry["primary_keyid"]
        )

        if status not in ("unsigned",) and not status.startswith("skipped"):
            any_signed = True

        uid_summaries.append(
            {
                "label": uid["label"],
                "is_attr": uid["is_attr"],
                "status": status,
                "sig": sig,
                "level": level,
            }
        )

        if uid["is_attr"]:
            continue

        if status == "weak_exportable":
            weak_exportable.append(uid["label"])
            max_level = max(max_level, level or 0)
        elif status == "weak_local":
            weak_local.append(uid["label"])

    return {
        "has_weak_exportable": bool(weak_exportable),
        "has_weak_local": bool(weak_local),
        "any_signed": any_signed,
        "max_level": max_level,
        "weak_exportable_uids": weak_exportable,
        "weak_local_uids": weak_local,
        "uid_summaries": uid_summaries,
    }


def _hash_label(sig: Sig | None) -> str:
    if sig is None:
        return "(none)"
    return HASH_NAMES.get(sig["hash_id"], f"id={sig['hash_id']}")


def _orig_sig_date(analysis: Analysis) -> str | None:
    """Return ISO-8601 date of the earliest weak certification sig, or None."""
    dates = [
        us["sig"]["created"]
        for us in analysis["uid_summaries"]
        if us["status"] == "weak_exportable" and us["sig"] is not None
    ]
    if not dates:
        return None
    return datetime.datetime.fromtimestamp(
        min(dates), tz=datetime.timezone.utc
    ).date().isoformat()


def _key_strength_skip(entry: Entry) -> str | None:
    """Return a human-readable skip reason if the primary key is too weak, else None."""
    algo = entry.get("primary_algo", 0)
    bits = entry.get("primary_bits", 0)
    if algo in _DSA_ELGAMAL_ALGOS:
        return "legacy algo (DSA/Elgamal)"
    if algo in _RSA_ALGOS and bits < MIN_RSA_BITS:
        return f"RSA-{bits} < {MIN_RSA_BITS} bits"
    return None


def _recipe_args(entry: Entry, analysis: Analysis) -> Iterator[list[str]]:
    """Yield gpg args list(s) for re-signing this key's exportable weak certs.

    UIDs are always listed explicitly and prefixed with '=' so gpg matches
    them exactly. Two safety properties hinge on this:

      1. Whole-key form (no UID args) would tell gpg to sign every UID on
         the imported key, including any UID the user's real keyring
         picked up from a keyserver but that the certifier never actually
         touched. Listing UIDs caps the signing to ones we vetted.

      2. gpg's default UID match is substring; without '=' a malicious
         UID containing a vetted UID as substring would also get signed.
    """
    if not analysis["has_weak_exportable"]:
        return
    fpr = entry["primary_fpr"].upper()
    cmd = [
        "--cert-digest-algo", TARGET_HASH,
        "--default-cert-level", str(analysis["max_level"]),
        "--force-sign-key",
        "--quick-sign-key",
        fpr,
    ]
    cmd.extend(f"={uid}" for uid in analysis["weak_exportable_uids"])
    yield cmd


def _args_to_cmd(gpg_args: list[str]) -> str:
    """Format a gpg args list as a printable shell command string."""
    return "gpg " + " ".join(shlex.quote(a) for a in gpg_args)


def _shell_safe(s: str) -> str:
    """Escape a string for safe interpolation inside a double-quoted shell echo."""
    return (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("$", "\\$")
         .replace("`", "\\`")
    )


def _write_batch_file(
    action_keys: list[ActionTuple],
    signer_fpr: str,
    keys_dir: str,
) -> None:
    """Write the offline-workstation re-sign script and key bundle.

    Two files are written to the current directory:

      * BATCH_SH: a reviewable driver script. Optionally imports
        BATCH_KEYS, re-signs with --quick-sign-key (skipped for the
        'export' kind), then exports the result to BATCH_ASC.
      * BATCH_KEYS: a public-key bundle of every affected target key,
        with a human-readable header listing them. Imported by BATCH_SH
        if any of those keys are missing from the offline keyring;
        usually a no-op since most maintainers already have them.

    action_keys: list of (entry, analysis, kind) where kind is 'resign'
    or 'export'. Both kinds participate in the bundle and the export;
    only 'resign' triggers a --quick-sign-key invocation.
    """
    resign_keys = [(e, a) for e, a, k in action_keys if k == "resign"]
    export_only = [(e, a) for e, a, k in action_keys if k == "export"]
    n_total = len(action_keys)
    n_resign = len(resign_keys)
    n_export_only = len(export_only)
    s_total = "" if n_total == 1 else "s"
    s_resign = "" if n_resign == 1 else "s"
    s_export = "" if n_export_only == 1 else "s"
    today = datetime.date.today().isoformat()

    # --- Bundle: BATCH_KEYS ---
    # gpg --import ignores text outside -----BEGIN/END----- blocks, so
    # the human-readable header below is harmless. surrogateescape lets
    # us round-trip stray latin-1 bytes some old keys have in their
    # textual preamble (e.g. "Heiko Stübner" with 0xfc).
    bundle_lines: list[str] = [
        f"{BATCH_KEYS} - public keys with weak certifications",
        f"Generated by resign-modern-hash.py on {today}",
        f"Certifier: {signer_fpr.upper()}",
        "",
        f"This bundle contains {n_total} public key{s_total} that you have",
        "certified using a weak hash algorithm (SHA-1/MD5/RIPEMD-160).",
        f"The companion {BATCH_SH} re-issues those certifications using",
        f"{TARGET_HASH}.",
        "",
        "Keys included:",
    ]
    for entry, _, _ in action_keys:
        keyid = entry["primary_fpr"][-16:].upper()
        uid = entry["primary_uid"] or "?"
        bundle_lines.append(f"  {keyid}  {uid}")
    bundle_lines += [
        "",
        f"Copy this file alongside {BATCH_SH} to your offline workstation.",
        "If any of these keys are not already in your keyring there, the",
        "script will import them automatically. (Anything outside the PGP",
        "armor blocks below is ignored by gpg --import.)",
        "",
    ]
    for entry, _, _ in action_keys:
        keyid = entry["primary_fpr"][-16:].upper()
        asc_path = os.path.join(keys_dir, f"{keyid}.asc")
        with open(asc_path, encoding="utf-8", errors="surrogateescape") as fh:
            asc_content = fh.read().rstrip("\n")
        bundle_lines.append(asc_content)
        bundle_lines.append("")
    with open(BATCH_KEYS, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write("\n".join(bundle_lines))

    # --- Driver: BATCH_SH ---
    quoted_keys = shlex.quote(BATCH_KEYS)
    lines = [
        "#!/bin/sh",
        f"# Generated by resign-modern-hash.py on {today}",
        f"# Certifier: {signer_fpr.upper()}",
        "#",
        "# Run this on the offline workstation that holds your Certify ([C])",
        f"# secret key. It re-issues your weak certifications on {n_total}",
        f"# key{s_total} using {TARGET_HASH} and writes the result to {BATCH_ASC}",
        f"# for submission to {SUBMIT_ADDRESS}.",
        "#",
        f"# Copy this script and {BATCH_KEYS} to your offline workstation",
        "# (e.g. via USB), review them, and run from the same directory.",
        f"# Copy {BATCH_ASC} back to your public workstation to mail it.",
        "",
        "set -e",
        "",
        "# --- Ensure target keys are present in this keyring ---",
        f"# (no-op if you already have them; {BATCH_KEYS} is a fallback)",
        f"if [ -f {quoted_keys} ]; then",
        f'    echo "==> Importing keys from {BATCH_KEYS}'
        ' (no-op if already present) ..."',
        f"    gpg --quiet --import --import-options import-clean {quoted_keys}",
        "fi",
        "",
    ]

    if n_resign:
        lines.append(f"# --- Re-sign {n_resign} key{s_resign} with {TARGET_HASH} ---")
        lines.append("")
        lines.append(
            f'echo "==> Re-signing {n_resign} key{s_resign} with {TARGET_HASH} ..."'
        )
        for entry, analysis in resign_keys:
            date = _orig_sig_date(analysis) or "unknown"
            raw_label = entry["primary_uid"] or "?"
            keyid = entry["primary_fpr"][-16:].upper()
            label = _shell_safe(raw_label)
            lines.append(f"# {raw_label}, originally signed on {date}")
            lines.append(f'echo "    {keyid}  {label} (orig {date})"')
            for gpg_args in _recipe_args(entry, analysis):
                lines.append(_args_to_cmd(gpg_args))
            lines.append("")

    if n_export_only:
        # No commands needed for these -- the import above already merged
        # the canonical pubkey with the user's existing local sigs, so the
        # export below picks up the strong cert that's missing from the
        # repo. Recorded here only for the maintainer's review.
        lines.append(
            f"# --- {n_export_only} key{s_export} already strong-signed "
            "in your local keyring ---"
        )
        lines.append("# (no re-sign needed; export below forwards the existing sig)")
        lines.append("")
        lines.append(
            f'echo "==> {n_export_only} key{s_export} already strong-signed '
            'locally; will be re-exported as-is:"'
        )
        for entry, _ in export_only:
            keyid = entry["primary_fpr"][-16:].upper()
            label = _shell_safe(entry["primary_uid"] or "?")
            lines.append(f'echo "    {keyid}  {label}"')
        lines.append("")

    lines.append(f"# --- Export {n_total} key{s_total} ---")
    lines.append(f'echo "==> Exporting {n_total} key{s_total} to {BATCH_ASC} ..."')
    lines.append("gpg --armor --export \\")
    for entry, _, _ in action_keys:
        lines.append(f"    {entry['primary_fpr'].upper()} \\")
    short_signer = signer_fpr.upper()[-16:]
    lines += [
        f"    > {shlex.quote(BATCH_ASC)}",
        "",
        "echo",
        f'echo "Updated keys written to {BATCH_ASC}."',
        f'echo "Send it to {SUBMIT_ADDRESS}, e.g.:"',
        (
            f'echo "    mail -s \\"resigned keys from {short_signer}\\" '
            f'{SUBMIT_ADDRESS} < {BATCH_ASC}"'
        ),
        "",
    ]

    with open(BATCH_SH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    os.chmod(BATCH_SH, 0o755)


def _print_status(
    repo_entries: list[Entry],
    local_entries: list[Entry],
    signer_fpr: str,
    signer_keyid: str,
) -> list[ActionTuple]:
    """Walk repo and local keyrings together, print status, return action list.

    Sig sets from both sources are merged per primary FPR (deduped). The
    canonical analysis runs on the merged entry, so a stronger sig in
    either source supersedes a weaker one by creation timestamp -- which
    means a maintainer who already re-signed locally won't be told to do
    it again.

    Weak sigs found only in the local keyring (i.e. lost from the repo
    at some point) are tagged "+local" so they stand out. Strong sigs
    that exist locally but haven't propagated back to the repo are
    tagged [SEND] -- no re-sign needed, just an export.

    Returns a list of (entry, analysis, kind) tuples where kind is one of:
      'resign' -- weak cert needs to be reissued with SHA-512
      'export' -- already-strong cert just needs to reach the repo
    """
    repo_by_fpr = {
        e["primary_fpr"].upper(): e for e in repo_entries if e["primary_fpr"]
    }
    local_by_fpr = {
        e["primary_fpr"].upper(): e for e in local_entries if e["primary_fpr"]
    }
    all_fprs = sorted(set(repo_by_fpr) | set(local_by_fpr))

    action_keys: list[ActionTuple] = []
    for efpr in all_fprs:
        if efpr == signer_fpr.upper():
            continue  # skip own key

        repo_entry = repo_by_fpr.get(efpr)
        local_entry = local_by_fpr.get(efpr)
        merged = _merge_entries(repo_entry, local_entry)

        analysis = _analyze_key_certs(merged, signer_keyid)
        if not analysis["any_signed"] and not analysis["has_weak_exportable"]:
            continue  # certifier never touched this key in either source

        shortfpr = efpr[-16:]
        label = merged["primary_uid"] or "?"

        dead = SKIP_VALIDITIES.get(merged.get("primary_validity", ""))
        if dead:
            print(f"  {TAG_SKIP} {shortfpr}  key {dead}  {label}")
            continue

        too_weak = _key_strength_skip(merged)
        if too_weak:
            print(f"  {TAG_SKIP} {shortfpr}  key {too_weak}  {label}")
            continue

        if analysis["has_weak_exportable"]:
            first_weak = next(
                (
                    us
                    for us in analysis["uid_summaries"]
                    if us["status"] == "weak_exportable" and us["sig"] is not None
                ),
                None,
            )
            hash_label = _hash_label(first_weak["sig"] if first_weak else None)
            n_uids = len(analysis["weak_exportable_uids"])
            uid_note = f" ({n_uids} UIDs)" if n_uids > 1 else ""

            # Origin: was the weak finding present in the repo's view, or
            # only in the local keyring? Re-analyse each source alone.
            repo_a = (
                _analyze_key_certs(repo_entry, signer_keyid)
                if repo_entry is not None else None
            )
            local_a = (
                _analyze_key_certs(local_entry, signer_keyid)
                if local_entry is not None else None
            )
            repo_weak = bool(repo_a and repo_a.get("has_weak_exportable"))
            local_weak = bool(local_a and local_a.get("has_weak_exportable"))
            origin_note = " +local" if local_weak and not repo_weak else ""
            level = analysis["max_level"]
            print(
                f"  {TAG_WEAK} {shortfpr}  {hash_label:<9s}  "
                f"level={level}{origin_note}{uid_note}  {label}"
            )
            action_keys.append((merged, analysis, "resign"))
            continue

        if analysis["has_weak_local"]:
            # Local (non-exportable) sigs aren't carried in pgpkeys.git;
            # nothing to publish, so just note and move on.
            print(
                f"  {TAG_SKIP} {shortfpr}  local sigs only  {label}"
            )
            continue

        # No weak certs to fix. Check whether the local keyring has a
        # strong cert by signer that hasn't propagated back to the repo.
        extras = _local_only_strong_uids(
            repo_entry, local_entry, analysis, signer_keyid
        )
        if extras:
            # _local_only_strong_uids returns [] when local_entry is None.
            assert local_entry is not None
            sample = _local_only_sample_sig(local_entry, signer_keyid, extras)
            hash_label = _hash_label(sample)
            n_uids = len(extras)
            uid_note = f" ({n_uids} UIDs)" if n_uids > 1 else ""
            print(
                f"  {TAG_SEND} {shortfpr}  {hash_label:<9s}  "
                f"needs propagation{uid_note}  {label}"
            )
            action_keys.append((merged, analysis, "export"))
            continue

        first_strong = next(
            (
                us
                for us in analysis["uid_summaries"]
                if us["status"] == "strong" and us["sig"] is not None
            ),
            None,
        )
        hash_label = _hash_label(first_strong["sig"] if first_strong else None)
        print(f"  {TAG_OK} {shortfpr}  {hash_label:<9s}  {label}")
    return action_keys


def main() -> NoReturn:
    parser = argparse.ArgumentParser(
        description=(
            "Find your weak-hash certifications on keys in pgpkeys.git "
            f"and emit a batch script that re-signs them with {TARGET_HASH}."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The generated batch script imports the affected keys into your\n"
            "default gpg keyring, re-issues your certifications using\n"
            f"--cert-digest-algo {TARGET_HASH} and --force-sign-key, then exports the\n"
            + f"result into a single .asc file for mailing to {SUBMIT_ADDRESS}.\n"
            + "\n"
            "Old SHA-1 sig packets stay in the target cert after re-signing\n"
            "(the new SHA-512 sig supersedes by timestamp); the keyring\n"
            "maintainer prunes stale packets when re-exporting."
        ),
    )
    parser.add_argument(
        "--signer",
        metavar="FPR",
        help=(
            "Fingerprint of your signing key. Auto-detected if you have "
            "exactly one secret key whose pubkey is present in pgpkeys.git."
        ),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "Report weak certifications without writing a batch file. "
            "Exits 1 if any remain, 0 if all are modern. Useful as a "
            "post-resign sanity check after the keyring maintainer has "
            "merged your update."
        ),
    )
    parser.add_argument(
        "--skip-local-keyring",
        action="store_true",
        help=(
            "Don't consult your default gpg keyring -- only inspect sigs "
            "currently present in pgpkeys.git/keys/. Use this if you don't "
            "want the script to scan your personal keyring at all (e.g. on "
            "a fresh machine). By default both sources are merged so SHA-1 "
            "sigs lost from the repo over time can still be recovered."
        ),
    )
    args = parser.parse_args()

    gpg = _gpg_bin()
    keys_dir = _repo_keys_dir()
    signer_fpr = _find_signer(gpg, args.signer, keys_dir)
    signer_keyid = signer_fpr[-16:]

    print(f"Certifier: {signer_fpr.upper()}")
    print(f"Keys dir:  {keys_dir}")
    print()

    print("Building analysis keyring...", end="", flush=True)
    home = _build_repo_keyring(gpg, keys_dir)
    try:
        res = _run_gpg(gpg, ["--homedir", home, "--with-colons", "--list-sigs"])
        repo_entries = _parse_keyring_sigs(
            res.stdout.decode("utf-8", errors="replace")
        )
    finally:
        shutil.rmtree(home, ignore_errors=True)
    n = len(repo_entries)
    print(f" {n} key{'' if n == 1 else 's'}.")

    local_entries: list[Entry] = []
    if not args.skip_local_keyring:
        print("Cross-checking local keyring...", end="", flush=True)
        repo_fprs = {
            e["primary_fpr"].upper() for e in repo_entries if e["primary_fpr"]
        }
        local_entries = _local_keyring_entries(gpg, repo_fprs)
        n = len(local_entries)
        print(f" {n} matching key{'' if n == 1 else 's'}.")
    print()

    action_keys = _print_status(
        repo_entries, local_entries, signer_fpr, signer_keyid
    )
    print()

    if not action_keys:
        scope = (
            "in pgpkeys.git" if args.skip_local_keyring
            else "in pgpkeys.git and your local keyring"
        )
        print(f"All your certifications {scope} use modern hash algorithms.")
        sys.exit(0)

    n_resign = sum(1 for _, _, k in action_keys if k == "resign")
    n_export = sum(1 for _, _, k in action_keys if k == "export")
    parts = []
    if n_resign:
        parts.append(f"{n_resign} to re-sign")
    if n_export:
        parts.append(f"{n_export} to forward")
    n = len(action_keys)
    breakdown = ", ".join(parts)
    signer = signer_keyid.upper()
    print(f"Found {n} key{'' if n == 1 else 's'} for {signer} ({breakdown}).")

    if args.verify:
        sys.exit(1)

    _write_batch_file(action_keys, signer_fpr, keys_dir)
    print()
    print(f"Wrote: {BATCH_SH}, {BATCH_KEYS}")
    print("Copy both files to the workstation that holds your [C] secret")
    print("key, review, then run:")
    print(f"  sh {BATCH_SH}")
    print(f"and mail the resulting {BATCH_ASC} to {SUBMIT_ADDRESS}.")
    sys.exit(1)


if __name__ == "__main__":
    main()
