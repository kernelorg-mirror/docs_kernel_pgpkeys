Linux developer PGP keys
------------------------

The purpose of this repository is to help distribute Linux kernel
developer PGP keys that have valid trust paths to Linus Torvalds.

There are currently the following directories in this repository:

 - keys/:    ascii-armoured keys
 - graphs/:  svg graphs showing trust paths to Linus Torvalds' key
 - scripts/: auxiliary helper scripts

Importing keys
--------------

Every file in the keys/ directory contains all UIDs, so you can just
grep for the person you need::

    $ grep -il torvalds *.asc
    79BE3E4300411886.asc

You can then `gpg --import 79BE3E4300411886.asc` into your keyring.

Refreshing keys
---------------

First, you should assign full trust to Linus's key::

    $ gpg --edit-key 79BE3E4300411886
    gpg> trust
    gpg> 4
    gpg> q
    $ gpg --check-trustdb

Now, copy the `scripts/korg-refresh-keys` script to your `~/bin` and
edit it according to the instructions.

That script will first verify that the latest commit to the repository
is signed by a valid key (a key directly signed by you or Linus), and
then will run a `merge-only` import -- meaning that it will ignore any
*new* keys added to the git repository and will only refresh keys that
you already have imported into your keyring.

Make sure to run `chmod a+x ~/bin/korg-refresh-keys` after you are done.

The last step is to set up a nightly cronjob by adding this to your
`crontab -e`::

    @daily ~/bin/korg-refresh-keys -q

Alternatively, if you are running a systemd-enabled system, set up a
timer instead::

    $ cat ~/.config/systemd/user/korg-refresh-keys.timer
    [Timer]
    OnCalendar=daily
    Persistent=yes
     
    [Install]
    WantedBy=sockets.target
     
    $ cat ~/.config/systemd/user/korg-refresh-keys.service
    [Service]
    ExecStart=%h/bin/korg-refresh-keys -q
    Type=oneshot
     
    $ systemctl enable --user korg-refresh-keys.timer
    $ systemctl start  --user korg-refresh-keys.timer
    $ systemctl start  --user korg-refresh-keys.service

Submitting keys to the keyring
------------------------------

If you are in MAINTAINERS or regularly submit patches or pull requests
to other maintainers, you should consider submitting your own public key
for inclusion into this repository. Note, that your key should be signed
by at least one other key already present in this repository in order to
qualify.

For now, the easiest way to submit your key is to run the following::

    gpg -a --export your@email.addr | mail -s your@email.addr keys@linux.kernel.org

If your `mail` command does not deliver mail properly, you can export to
a file and copy-paste that into the email body instead.

Note, that anything you send to keys@linux.kernel.org will be archived
on https://lore.kernel.org/keys.

Re-signing legacy SHA-1 certifications
--------------------------------------

A lot of third-party signatures in this keyring were made back when SHA-1
was still the default hash. Modern Sequoia-based tooling (e.g. ``sq``)
rejects SHA-1 binding signatures, which silently breaks trust paths
through affected keys. If you are a maintainer with sigs in this keyring,
you can find and re-issue your own SHA-1 certifications using
``./scripts/resign-modern-hash.py``.

The workflow assumes your Certify ([C]) secret key lives on a separate
offline workstation, away from your everyday gpg keyring -- the
recommended setup for kernel maintainers. It splits cleanly into three
phases:

1. **On your public workstation** (this checkout + your everyday gpg
   keyring), run::

       $ ./scripts/resign-modern-hash.py

   The script scans every key under ``keys/``, cross-checks against your
   default gpg keyring, lists which ones still carry a SHA-1 (or MD5/
   RIPEMD-160) certification from your key, and writes two files:

   - ``resign-weak-keys.sh`` -- the re-sign / export driver script.
   - ``weak-keys.asc`` -- a public-key bundle of the affected target
     keys, with a human-readable header listing them.

2. **On your offline workstation** (the one with your [C] secret key
   or smartcard), copy both files over (e.g. via USB), review them and
   remove anyone you would rather not re-certify, then run
   ``resign-weak-keys.sh``. It re-issues your certifications using
   ``--cert-digest-algo SHA512`` and writes the result to
   ``resigned-keys.asc`` next to itself. The bundle is imported only
   if any of the target keys are missing from your offline keyring --
   usually a no-op since you already have them.

3. **Back on your public workstation**, mail the ``.asc`` file to
   keys@linux.kernel.org. Once your update has been merged and you have
   pulled, confirm the result with::

       $ ./scripts/resign-modern-hash.py --verify

Entries tagged ``+local`` in the status listing indicate weak sigs that
were found only in your local keyring -- meaning the SHA-1 sig was lost
from the repo at some point (e.g. by a periodic refresh from the public
keyservers) but is still recoverable from your gpg homedir. Re-signing
will restore it in the repo with a modern hash.

Entries tagged ``[SEND]`` indicate the reverse case: your local keyring
already has a strong (SHA-256/SHA-512) certification on a key, but that
sig hasn't propagated back to the repo. No re-sign is needed; the
generated batch script will simply re-export the key so the existing
strong sig reaches the keyring maintainer.

See ``rebind-modern-hash.py`` (below) if your own key's UID
self-signatures or subkey bindings use a weak hash, and
``weak-hash-audit.py`` (below) for a per-keyring overview.

Rebinding your own UIDs with a modern hash
------------------------------------------

If your key was generated before roughly 2018, its UID self-signatures
and subkey binding signatures are most likely SHA-1, which Sequoia's
``StandardPolicy`` rejects. This shows up as your UIDs and email
addresses appearing "missing" from the key when seen through modern
tooling, and as encryption to your subkeys failing with "no suitable
encryption subkey". The keyholder-side fix is to rebind your UIDs and
subkeys with a modern hash; ``./scripts/rebind-modern-hash.py`` prints
the exact ``gpg(1)`` command sequence to do that.

By default the script auto-detects which key to inspect by looking
for one of your secret keys that has a public copy in this
repository's ``keys/`` directory. You can also point it at a specific
key explicitly::

    $ ./scripts/rebind-modern-hash.py                       # auto-detect
    $ ./scripts/rebind-modern-hash.py --fpr <FPR>           # your keyring
    $ ./scripts/rebind-modern-hash.py --from-repo <KEYID>   # canonical pgpkeys.git copy
    $ ./scripts/rebind-modern-hash.py /path/to/key.asc      # arbitrary file
    $ gpg --export <FPR> | ./scripts/rebind-modern-hash.py  # stdin

The script never modifies your real keyring during inspection (file,
stdin and ``--from-repo`` input go through a temporary ``GNUPGHOME``);
the printed rebind commands are what actually modify your keyring,
and only when you choose to run them. Copy-paste them into your
shell and they'll do the right thing:

- ``--quick-set-primary-uid`` re-signs each weak UID self-signature
  with SHA-512.
- ``--quick-set-expire`` (preserving the existing expiration date)
  re-signs each weak subkey binding signature with SHA-512.
- A final ``--quick-set-primary-uid`` line restores your original
  primary UID, since the per-UID rebind calls above shuffle the
  primary flag around as a side effect.

Image / user-attribute (uat) packets can't be addressed by
``--quick-set-primary-uid`` and need an interactive ``--edit-key``
session; the recipe walks you through that case too.

Once the commands have run, re-run with ``--verify`` to confirm
everything reads ``[ OK ]``::

    $ ./scripts/rebind-modern-hash.py --verify --fpr <FPR>

Then mail the rebound public key to keys@linux.kernel.org so the
canonical keyring picks it up::

    $ gpg --export --armor <FPR> | mail -s your@email.addr keys@linux.kernel.org

This is the keyholder-side companion to ``resign-modern-hash.py``
(above): the rebind script fixes your own UID and subkey
self-signatures; the resign script fixes the third-party
certifications you've issued on *other* maintainers' keys. Whether
you need one or both is visible at a glance via the audit script
below.

Auditing weak-hash usage in the keyring
---------------------------------------

For a bird's-eye view of where weak hashes still appear in this
repository, ``./scripts/weak-hash-audit.py`` produces two
complementary reports:

- ``--uids`` lists every key in ``keys/`` that has at least one live
  UID whose self-binding is still SHA-1 / MD5 / RIPEMD-160. These
  UIDs are rejected by Sequoia regardless of any third-party
  certifications on them; the keyholder must rebind from their own
  ``[C]`` secret key (using ``rebind-modern-hash.py`` above).

- ``--cross-sigs`` lists, per certifier, the count of keys on which
  the certifier's latest exportable certification of a live UID is
  still a weak hash. Sorted by count descending, so the largest
  sources of legacy weak certifications float to the top.

With no arguments both reports run; pass ``--uids`` or
``--cross-sigs`` to scope to a single section.

The script is read-only and operates on a fresh, temporary
``GNUPGHOME`` built from the ``keys/`` directory -- it does not touch
your real keyring.
