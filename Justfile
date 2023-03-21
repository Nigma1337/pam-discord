
all:
    cargo build

install:
    @cargo build --release
    sudo cp target/release/libpam_discord.so /lib/security/pam_discord.so
