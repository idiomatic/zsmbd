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

Add a share and an SMB user, then start the server. Port 445 needs root on
Linux and macOS. To test without root, give just a port, as in
`zsmbd serve --smb 4450`; a missing address keeps the default.

```bash
zsmbd share add data /srv/data
```

```bash
zsmbd user add hal
```

```bash
zsmbd user passwd hal
```

```bash
sudo zsmbd serve
```

`user add` creates a user with no password; `user passwd` sets the SMB
password, from stdin. On first start, zsmbd creates the
web console user `admin` and prints its random password once. The console is
at <http://127.0.0.1:8445/>.

Connect from a client:

| Client | Command |
|---|---|
| macOS | `mount_smbfs //hal@HOST/data ~/mnt` or Finder: Go ▸ Connect to Server ▸ `smb://HOST/data` |
| Linux | `sudo mount -t cifs //HOST/data /mnt -o username=hal,vers=3.1.1` |
| Windows | `net use Z: \\HOST\data /user:hal` |

## Command line

```
zsmbd [--db PATH] [--config FILE] [--users FILE] <command>

  serve [--smb [ADDR:]PORT] [--web [ADDR:]PORT]
                                   defaults: 0.0.0.0:445, 127.0.0.1:8445
  user list
  user add LOGIN                   no password: can't sign in until one is set
  user passwd [--web] LOGIN        prompts for the SMB (or web console) password
  user passwd --both LOGIN         prompts for one password for both
  user nopasswd [--web] LOGIN      clears the SMB (or web console) password
  user nopasswd --both LOGIN       clears both
  user del LOGIN
  share list
  share add SHARE PATH
  share comment SHARE TEXT
  share readonly SHARE
  share readwrite SHARE
  share guest SHARE                allow guests (no sign-in)
  share noguest SHARE
  share del SHARE
  get [KEY]                        show settings
  set KEY VALUE
  hash [--web] [LOGIN]             hash an SMB (or web) password; with LOGIN,
                                   print a users-file line
  hash --both LOGIN                a users-file line with one password for both
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

Settings take effect when `serve` restarts.

## Storage

By default everything lives in one SQLite database, `./zsmbd.db` (or `--db
PATH`), created on first use. Either part
can live in a plain-text file instead:

| Flags | Settings and shares | Users |
|---|---|---|
| (none) | database | database |
| `--config FILE` | FILE | database |
| `--users FILE` | database | FILE |
| `--config FILE --users FILE` | FILE | FILE |

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
