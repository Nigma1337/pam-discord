pam-discord
========

A PAM discord oauth module built using pam-rs

# Prerequisites

You need some libraries before you build like libpam and libssl.

If you're going to build on Ubuntu, just run this:

```
sudo apt-get install -y build-essential libpam0g-dev libpam0g libssl-dev
```

# Building

Just use `cargo build`.

# Installing

Just use `just install`.

# Usage

You need to move the build product to a folder where PAM is looking for modules.

If you're using Ubuntu you can move `libpam_discord.so` to `/lib/security`.
Then you can place a configuration file in `/etc/pam.d/`. It can look something like this:

```
auth sufficient pam_discord.so client_id=<client_id> client_secret=<client_secret>  guild=<guild id> role=<role id>
account sufficient pam_discord.so client_id=<client_id> client_secret=<client_secret> guild=<guild id> role=<role id>
session    include      system-local-login
```

To use with sshd, you'll need a patched version of openssh, located [here](https://github.com/Nigma1337/openssh-portable)
and built with these commands:
```
autoreconf
./configure --with-pam
make install
```