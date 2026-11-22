# obsidian-collaboration-server

Server for the [Collaboration](https://github.com/9ostudio/obsidian-collaboration-client) plugin for Obsidian. It stores and relays end-to-end encrypted changes, so it never sees your notes, file names or member names.

## Install

On a Linux machine with systemd:

```sh
curl -fsSL https://raw.githubusercontent.com/9ostudio/obsidian-collaboration-server/main/install.sh | bash
```

With Tailscale installed, the server is published through Tailscale Funnel. Otherwise point an HTTPS address at `127.0.0.1:8790` and pass it in:

```sh
curl -fsSL https://raw.githubusercontent.com/9ostudio/obsidian-collaboration-server/main/install.sh | PUBLIC_URL=https://share.example.com bash
```

The installer prints a one-time setup link. Open it on the computer with your vault to connect it as the owner. For another one, run:

```sh
~/obsidian-collaboration-server/owner-link.sh
```

Run the install command again to update.

## Data

Everything is stored in `~/.local/share/obsidian-collaboration`: encrypted change logs, encrypted attachments, and an index of accounts, folders and permissions. The full history of every shared folder is kept until its owner stops sharing it.

## License

MIT
