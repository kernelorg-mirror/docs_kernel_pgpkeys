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

Now, add the following script to your `~/bin`::

    #!/bin/bash
    # FIX ME: POINT AT ACTUAL LOCATION of pgpkeys.git clone
    PGPKEYS="$HOME/git/korg-pgpkeys"

    # If you remove --import-options merge-only, it will import keys
    # not already present on your keyring, which is not what you want!
    IMPORTFLAGS="--import-options import-clean --import-options merge-only"

    # Make sure this points to your gpg v2 binary. You can also add other
    # flags here, such as --homedir
    GPGBIN="/usr/bin/gpg2 -q --batch"

    cd $PGPKEYS
    if ! git fetch -q > /dev/null; then
        # Couldn't run git fetch, maybe not online?
        exit 0
    fi
    if [[ $(git rev-parse HEAD) == $(git rev-parse @{u}) ]]; then
        # No updates since last run
        exit 0
    fi

    COUNT=$(git verify-commit --raw @{u} | grep -c -E '^\[GNUPG:\] (GOODSIG|VALIDSIG)')
    if [[ ${COUNT} -lt 2 ]]; then
        echo "PGPKEYS REFRESH: FAILED TO VERIFY COMMIT SIGNATURE!"
        exit 1
    fi

    git pull -q
    $GPGBIN --import $IMPORTFLAGS keys/*.asc > /dev/null

This script will first verify that the latest commit to the repository
is signed by a valid key (a key directly signed by you or Linus), and
then will run a `merge-only` import -- meaning that it will ignore any
*new* keys added to the git repository and will only refresh keys that
you already have imported into your keyring.

The last step is to set up a nightly cronjob by adding this to your
`crontab -e`::

    @daily ~/bin/refresh-korg-keyring

Make sure to `chmod a+x ~/bin/refresh-korg-keyring` first.

Submitting keys to the keyring
------------------------------

The easiest is to run the following::

    gpg -a --export your@email.addr | mail -s your@email.addr keys@kernel.org

If your `mail` command does not deliver mail properly, you can export to
a file and copy-paste that into the email body instead.
