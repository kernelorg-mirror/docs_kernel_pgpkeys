Linux developer PGP keys
------------------------

The purpose of this repository is to help distribute Linux kernel
developer PGP keys that have valid trust paths to Linus Torvalds.

There are currently two directories in this repository:

 - keys/:   contains ascii-armoured keys
 - graphs/: contains svg graphs showing trust paths to Linus's key

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

For now, the easiest is to run the following::

    gpg -a --export your@email.addr | mail -s your@email.addr keys@kernel.org

If your `mail` command does not deliver mail properly, you can export to
a file and copy-paste that into the email body instead.
