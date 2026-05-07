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
