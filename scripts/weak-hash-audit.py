#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Konstantin Ryabitsev <konstantin@linuxfoundation.org>
#
# Audit weak-hash usage in pgpkeys.git/keys/. Two independent reports,
# selectable via --uids and --cross-sigs (both run by default):
#
#   --uids        Keys whose UID self-bindings still use a weak hash.
#                 These UIDs are rejected by modern OpenPGP tooling
#                 regardless of any third-party certs on them, so any
#                 cross-cert pointing at them is moot until the
#                 keyholder rebinds from their own [C] secret key.
#                 Output: keyid, weak/total live-UID counts, primary uid.
#
#   --cross-sigs  Per-certifier count of keys where the certifier's
#                 latest exportable cert on a live UID is still a weak
#                 hash. Sorted by count descending. UIDs with weak
#                 self-bindings ARE counted here -- those sigs are real
#                 packets in the repo, and re-signing them pays off as
#                 soon as the keyholder rebinds.
#                 Output: keyid, count, developer name.
#
# "Weak" means SHA-1, MD5, or RIPEMD-160 -- the same set
# resign-modern-hash.py rejects. In practice MD5 and RIPEMD-160 are
# vanishingly rare in this keyring, so the numbers are SHA-1-driven.
#
# Counting semantics for --cross-sigs: only the LATEST exportable sig
# per (issuer, target UID) is examined, so any certifier who has
# already re-signed that UID with a modern hash drops out automatically.
# Revoked / expired / invalid UIDs are skipped (the keyholder has told
# the world to ignore them).

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from typing import Protocol, TypedDict, cast

HERE = os.path.dirname(os.path.abspath(__file__))


# Mirrors of the TypedDicts defined in resign-modern-hash.py. Kept here
# (rather than imported) because the source module's filename contains
# a dash, which blocks `import` -- including mypy's static import.
class _Sig(TypedDict):
    issuer_keyid: str
    created: int
    sig_class: str
    hash_id: int


class _Uid(TypedDict):
    label: str
    validity: str
    is_attr: bool
    sigs: list[_Sig]


class _Entry(TypedDict):
    primary_fpr: str
    primary_keyid: str
    primary_uid: str
    primary_validity: str
    primary_bits: int
    primary_algo: int
    uids: list[_Uid]


class _RmhModule(Protocol):
    """Subset of resign-modern-hash.py's surface that this script uses."""

    WEAK_HASH_IDS: set[int]
    SKIP_VALIDITIES: dict[str, str]
    EXPORTABLE_CERT_CLASSES: set[str]
    LOCAL_CERT_CLASSES: set[str]
    ALL_CERT_CLASSES: set[str]
    CERT_REVOC_CLASSES: set[str]

    def _gpg_bin(self) -> str: ...
    def _repo_keys_dir(self) -> str: ...
    def _build_repo_keyring(self, gpg: str, keys_dir: str) -> str: ...
    def _run_gpg(
        self,
        gpg: str,
        args: list[str],
        check: bool = ...,
    ) -> subprocess.CompletedProcess[bytes]: ...
    def _parse_keyring_sigs(self, output: str) -> list[_Entry]: ...


def _load_helpers() -> _RmhModule:
    """Import named helpers from sibling resign-modern-hash.py.

    Same pattern as scripts/rebind-modern-hash.py. The sibling has a
    dash in its filename so a plain `import` won't work; we load it
    via importlib instead. Module-level code in the sibling is just
    imports + definitions (main() is gated behind
    `if __name__ == "__main__"`), so this is side-effect free.
    """
    spec = importlib.util.spec_from_file_location(
        "resign_modern_hash",
        os.path.join(HERE, "resign-modern-hash.py"),
    )
    if spec is None or spec.loader is None:
        sys.exit("error: failed to locate resign-modern-hash.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return cast("_RmhModule", mod)


def _build_repo_view(rmh: _RmhModule) -> list[_Entry]:
    gpg = rmh._gpg_bin()
    keys_dir = rmh._repo_keys_dir()
    print("Building analysis keyring...", end="", flush=True)
    home = rmh._build_repo_keyring(gpg, keys_dir)
    try:
        res = rmh._run_gpg(
            gpg, ["--homedir", home, "--with-colons", "--list-sigs"]
        )
        entries = rmh._parse_keyring_sigs(
            res.stdout.decode("utf-8", errors="replace")
        )
    finally:
        shutil.rmtree(home, ignore_errors=True)
    print(f" {len(entries)} keys.")
    return entries


def _report_uids(entries: list[_Entry], rmh: _RmhModule) -> None:
    """List keys where at least one live UID has a weak self-binding."""
    rows: list[tuple[_Entry, int, int]] = []
    for e in entries:
        pkid = e["primary_keyid"].upper()
        weak = 0
        total = 0
        for u in e["uids"]:
            if u["is_attr"]:
                continue
            if u["validity"] in rmh.SKIP_VALIDITIES:
                continue
            self_sigs = [
                s for s in u["sigs"]
                if s["issuer_keyid"].upper() == pkid
                and s["sig_class"] in (
                    rmh.EXPORTABLE_CERT_CLASSES | rmh.LOCAL_CERT_CLASSES
                )
            ]
            if not self_sigs:
                continue  # malformed UID; skip from both numerator and denom
            total += 1
            latest = max(self_sigs, key=lambda s: s["created"])
            if latest["hash_id"] in rmh.WEAK_HASH_IDS:
                weak += 1
        if weak:
            rows.append((e, weak, total))

    print()
    print("=== Keys with weak-hash UID self-bindings ===")
    print()
    if not rows:
        print("(none)")
        return

    # Sort by weak count desc, then keyid for stability.
    rows.sort(key=lambda r: (-r[1], r[0]["primary_keyid"]))
    print(f"{'keyid':<16}  {'weak':>4}  {'total':>5}  primary uid")
    print(f"{'-' * 16}  {'-' * 4}  {'-' * 5}  {'-' * 11}")
    for e, weak, total in rows:
        kid = e["primary_keyid"].upper()
        print(f"{kid:<16}  {weak:>4}  {total:>5}  {e['primary_uid']}")
    s = "" if len(rows) == 1 else "s"
    print()
    print(f"{len(rows)} key{s} with at least one weak-bound live UID.")


def _report_cross_sigs(entries: list[_Entry], rmh: _RmhModule) -> None:
    """Per-certifier count of keys with a live weak-hash cross-cert."""
    name_by_keyid: dict[str, str] = {
        e["primary_keyid"].upper(): (e["primary_uid"] or "?")
        for e in entries if e["primary_keyid"]
    }

    weak_targets: dict[str, set[str]] = {}
    for entry in entries:
        primary_keyid = entry["primary_keyid"].upper()
        primary_fpr = entry["primary_fpr"].upper()
        for uid in entry["uids"]:
            if uid["is_attr"]:
                continue
            if uid["validity"] in rmh.SKIP_VALIDITIES:
                continue
            by_issuer: dict[str, list[_Sig]] = {}
            for sig in uid["sigs"]:
                iid = sig["issuer_keyid"].upper()
                if iid == primary_keyid:
                    continue
                if sig["sig_class"] not in rmh.ALL_CERT_CLASSES:
                    continue
                by_issuer.setdefault(iid, []).append(sig)
            for iid, sigs in by_issuer.items():
                latest = max(sigs, key=lambda s: s["created"])
                if latest["sig_class"] in rmh.CERT_REVOC_CLASSES:
                    continue  # issuer revoked their cert
                if latest["sig_class"] not in rmh.EXPORTABLE_CERT_CLASSES:
                    continue  # local sig, not in repo bundle
                if latest["hash_id"] not in rmh.WEAK_HASH_IDS:
                    continue
                weak_targets.setdefault(iid, set()).add(primary_fpr)

    print()
    print("=== Certifiers with live weak-hash cross-signatures ===")
    print()
    if not weak_targets:
        print("(none)")
        return

    rows = sorted(
        weak_targets.items(),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    print(f"{'keyid':<16}  {'count':>5}  developer")
    print(f"{'-' * 16}  {'-' * 5}  {'-' * 9}")
    for iid, fprs in rows:
        name = name_by_keyid.get(iid, "(unknown)")
        print(f"{iid:<16}  {len(fprs):>5}  {name}")
    s = "" if len(rows) == 1 else "s"
    print()
    print(f"{len(rows)} certifier{s} with weak-hash cross-certs.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Audit weak-hash usage in pgpkeys.git/keys/. With no flags "
            "both reports run; pass --uids or --cross-sigs to scope to "
            "just that section."
        ),
    )
    parser.add_argument(
        "--uids",
        action="store_true",
        help=(
            "Report keys whose UID self-bindings still use a weak hash "
            "(SHA-1/MD5/RIPEMD-160). Modern OpenPGP tooling rejects "
            "such UIDs regardless of any third-party certs on them; the "
            "keyholder must rebind from their own [C] secret key to fix."
        ),
    )
    parser.add_argument(
        "--cross-sigs",
        action="store_true",
        help=(
            "Report per-certifier count of keys where the certifier's "
            "latest exportable cert on a live UID is still a weak hash. "
            "Sorted by count descending."
        ),
    )
    args = parser.parse_args()

    show_uids: bool = args.uids
    show_cross: bool = args.cross_sigs
    if not (show_uids or show_cross):
        show_uids = show_cross = True

    rmh = _load_helpers()
    entries = _build_repo_view(rmh)

    if show_uids:
        _report_uids(entries, rmh)
    if show_cross:
        _report_cross_sigs(entries, rmh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
