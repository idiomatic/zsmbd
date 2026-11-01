# zsmbd

A small SMB 3.1.1 file server for Linux and macOS hosts, written in Zig. One
binary holds the SMB server, an admin web console, and a command-line tool.
It has four settings, all with working defaults.

> **Status:** early. macOS 15 mounts and reads a share; Windows and Linux
> clients are untested, and the web console is minimal. See
> [ARCHITECTURE.md](ARCHITECTURE.md) section 13.

## Features

- SMB 3.1.1 only, with signing required by default and optional encryption
  (AES-128-GCM or AES-128-CCM).
- NTLMv2 authentication with local users; no domain or Kerberos.
- Shares confined to their directory: `..` is rejected, and symlinks are
  followed only inside the share.
- State in one SQLite database, or in plain-text files you can edit, diff,
  and keep in version control.
- Admin web console and JSON API on localhost.

Not supported: SMB 1, 2, and 3.0; oplocks and leases; multichannel; DFS;
named streams; durable handles; and Windows ACLs.

## Build

Requires [Zig](https://ziglang.org/) 0.17.0 or later and the system SQLite (3.24 or later)
library (`sqlite-devel` on Fedora, `sqlite-dev` on Alpine, built in on
macOS).

```bash
zig build
```

The binary is `zig-out/bin/zsmbd`. Run the unit tests with:

```bash
zig build test
```

## Quick start

Add a share and an SMB user, then start the server. `--db` names the SQLite
database (created on first use) and is required with every command that uses
it. Only root can listen on SMB's port 445 on Linux and macOS, so the SMB
port defaults to 445 for root and to 4450 for everyone else. Give `--smb`
to choose (a bare port keeps the default address), as in
`zsmbd --db zsmbd.db serve --smb 4455`.

```bash
zsmbd --db zsmbd.db share add data /srv/data
```

```bash
zsmbd --db zsmbd.db user add hal
```

```bash
zsmbd --db zsmbd.db user passwd hal
```

```bash
sudo zsmbd --db zsmbd.db serve --web 8445
```

`user add` creates a user with no password; `user passwd` sets the SMB
password, from stdin. The web console is opt-in: `--web 8445` starts it
at <http://127.0.0.1:8445/>, and on first start zsmbd creates the web console
user `admin` and prints its random password once.

Connect from a client. On port 4450, name the port, as in
`smb://HOST:4450/data` on macOS; other clients have their own port options.

| Client | Command |
|---|---|
| macOS | `mount_smbfs //hal@HOST/data ~/mnt` or Finder: Go ▸ Connect to Server ▸ `smb://HOST/data` |
| Linux | `sudo mount -t cifs //HOST/data /mnt -o username=hal,vers=3.1.1` |
| Windows | `net use Z: \\HOST\data /user:hal` |

## Command line

```
zsmbd [--db PATH|none] [--config FILE] [--users FILE|-] CMD

  serve [--smb [ADDR:]PORT]
          default: 0.0.0.0:445 (0.0.0.0:4450 as user)
        [--web [ADDR:]PORT]
          the web console, off unless given
        [--share NAME:PATH[:OPTIONS[:TEXT]]]
        [--user LOGIN:NT_HASH:WEB_HASH]
        [--smb-user LOGIN:PASSWORD]
        [--web-user LOGIN:PASSWORD]
          the last four are ephemeral, in memory
  user list
  user add LOGIN
      no password: can't sign in until one is set
  user passwd [--web] LOGIN
      prompts for the SMB (or web console) password
  user passwd --both LOGIN
      prompts for one password for both
  user nopasswd [--web] LOGIN
      clears the SMB (or web console) password
  user nopasswd --both LOGIN
      clears both; can't sign in anywhere
  user del LOGIN
  share list
  share add SHARE PATH
  share comment SHARE TEXT
  share readonly SHARE
  share readwrite SHARE
  share guest SHARE        allow guests (no sign-in)
  share noguest SHARE
  share del SHARE
  get [KEY]                show settings
  set KEY VALUE
  hash [--web] [LOGIN]
      hash an SMB (or web) password; with LOGIN,
      print a users-file line
  hash --both LOGIN
      a users-file line, one password for both
  help
```

Passwords are read from stdin, one per line, and aren't echoed at a terminal.
Weak passwords get a warning; only empty ones are refused. A mistyped command
prints just its own synopsis and exits with status 2; other failures exit
with 1. `share comment SHARE ""` clears a comment.

### Users and passwords

A user has an SMB password, a web console password, both, or neither, and
each password opens one service. `user passwd` sets them and `user nopasswd`
clears them. `user list` names the four cases:

| Shown as | Passwords | Signs in to |
|---|---|---|
| `smb` | SMB | SMB |
| `web` | web | web console |
| `both` | both, kept separate | both |
| `none` | neither | nothing |

Users with both passwords get a warning, and a stronger one when the two
match.
The last user with a web password can't be deleted or lose it.

### Settings

| Key | Default | Meaning |
|---|---|---|
| `server_name` | host name up to its first dot, upper-cased (15 characters at most) | NetBIOS-style server name |
| `workgroup` | `WORKGROUP` | workgroup name |
| `signing_required` | `yes` | require signed SMB messages |
| `encrypt` | `no` | require encryption for every session |

```bash
zsmbd set encrypt yes
```

The web console runs only when `serve` is given `--web [ADDR:]PORT`; a
bare port listens on `127.0.0.1`. Without it no HTTP listener starts, no
first-run `admin` is made, and `--web-user` is refused. Manage users and
shares with the CLI and files instead.

The console's Shares panel has Read-only and Allow guests switches for each
share. Making a share read-only, or removing guests, disconnects the
connections using it (a confirmation says how many) so they reconnect under
the new rules; relaxing changes apply to new connections.

### Control socket

When `serve` has a persistent store it also listens on a Unix socket beside
it (`zsmbd.db.sock` for `--db zsmbd.db`; mode 0600, same user or root only).
CLI commands that change shares, users, or settings tell the running server
through it, so tightening a share, or removing a user's SMB password, drops
the affected connections at once:

```
$ zsmbd --db zsmbd.db share readonly docs
zsmbd: docs: 1 connection dropped; each
reconnects under the new rules
```

With no server running the CLI says nothing. `--socket PATH` moves the
socket, `--socket none` turns it off, and a store path over 100 bytes needs
`--socket` (the OS limits socket paths). An in-memory store has no socket.

Settings saved in the web console take effect at once; changes made with `zsmbd set` or in a file take effect when `serve` restarts.

## Storage

Everything lives in one SQLite database, `--db PATH`, created on first use;
there is no default. Either part can live in a plain-text file instead:

| Flags | Settings and shares | Users |
|---|---|---|
| `--db PATH` | database | database |
| `--config FILE` | FILE | database |
| `--users FILE` | database | FILE |
| `--config FILE --users FILE` | FILE | FILE |

### Ephemeral shares and logins

For demos, tests, CI, and containers, `serve` takes shares and logins that
live in memory only and vanish on restart. The flags repeat:

```
zsmbd serve --share docs:/srv/docs:ro,guest:Team files \
  --smb-user hal:'a long passphrase' \
  --web-user hal:'another one'
```

* `--share NAME:PATH[:OPTIONS[:TEXT]]`: OPTIONS are `ro`, `rw`, `guest`, and
  `noguest`, comma-separated; TEXT is the comment. The path may be relative to the directory
  `serve` starts in (it is made absolute), and can't contain a colon.
* `--user LOGIN:NT_HASH:WEB_HASH` is a [users-file](examples/users) line (make
  one with `zsmbd hash`); `--smb-user` and `--web-user` take `LOGIN:PASSWORD`
  and hash it at startup. A login takes each service once.
* `--users -` reads users-file text from stdin instead, with `serve` only:
  those are the only users, and they are read-only.

`--db none` (with `serve` only) keeps the store in memory: nothing is written,
and the settings take their defaults. `serve` does the same when it is given
ephemeral entries and no `--db`.

Ephemeral entries hide stored ones of the same name. The web console edits
and deletes them like stored ones (and, with `--users -`, creates users
too), with a warning in the response; the only difference is that a
restart forgets the change, and deleting one reveals the stored entry it
hid. The CLI can't reach them, being another process (`user list` and
`share list` mark them `ephemeral`). With no `--db` or with `--users -`, and no web login given, `serve`
makes an ephemeral `admin` with a random web password (no SMB
password), printed once and gone when `zsmbd` exits.

**Passwords and hashes on the command line are visible** to other users of the
host (in `ps`) until `serve` starts, and stay in your shell history and audit
logs; an NT hash is as good as the password to anyone who sees it. `serve`
masks them with `X` in its argument list right after parsing (the login
stays visible, and the length of the secret does) and warns, but prefer
`--users FILE` or `--users -`. With bash, a leading space keeps a command out
of the history when `HISTCONTROL=ignorespace`.

Every command, including `serve`, takes the same flags. Hand edits take
effect without a restart (settings excepted), and a file that doesn't parse is
reported with its line number. Examples:
[examples/zsmbd.conf](examples/zsmbd.conf) and [examples/users](examples/users).

**Configuration file:** settings as `key = value` lines, then one `[name]`
section per share with `path`, `comment`, `read_only`, and `guest_ok`.
Comments are whole lines starting with `#` or `;`, and zsmbd's own edits keep
them.

```ini
workgroup = HOME
encrypt = yes

[data]
path = /srv/data
comment = Team files
```

**Users file:** one user per line, `name:nt_hash:web_hash`. A blank hash
disables sign-in to that service. Set passwords with `zsmbd --users FILE user passwd LOGIN`, or hash
them on another machine and add the line it prints:

```bash
zsmbd hash hal >> users
```

`hash LOGIN` reads one password and fills in the SMB hash, the web hash
(`--web`), or both from the same password (`--both`, with a warning).
Without LOGIN, `zsmbd hash` or `zsmbd hash --web` prints just the hash, to
paste into an existing line.
`hash` opens no database or files.

## Security

- NT hashes are password-equivalent. zsmbd writes the users file with mode
  0600 and warns when others can read it; protect the database the same way.
- The web console listens on localhost only and has no TLS. To reach it
  remotely, use an SSH tunnel (`ssh -L 8445:127.0.0.1:8445 HOST`) or a TLS
  proxy.
- The console hashes SMB passwords in the browser with WebAssembly, and falls
  back to hashing them on the server only when the browser can't.

[SECURITY.md](SECURITY.md) maps untrusted input and secrets.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): design, modules, and status.
- [AGENTS.md](AGENTS.md): requirements and decisions.
- [SECURITY.md](SECURITY.md): attack surface and secrets.
- [REFERENCES.md](REFERENCES.md): protocol specifications.
- [CHANGELOG.md](CHANGELOG.md): changes by version.
