# zsmbd

## Requirements
* A network file server daemon implementing SMB 3.1.1 or later, with few configuration options and sensible defaults.
* Hosts: recent Linux and macOS. Clients: recent Linux, Windows, and macOS.
* Embedded admin web server: settings, shares (names and directory paths), user credentials, and live activity.
* libsmbd: the SMB server is also an embeddable Zig module (`smbd`, root `src/smbd.zig`; guide [src/smb/README.md](src/smb/README.md)), and zsmbd is its host.
* All code in Zig 0.17.0 or later; this is non-negotiable.
* SQLite may store data (hashed passwords, configuration).
* Markdown code blocks are at most 60 columns wide (due to a Claude desktop app bug).
* Keep this file, [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [CHANGELOG.md](CHANGELOG.md) current with each change.

## Build
* `zig build` makes `zsmbd`; `zig build lib` makes libsmbd for C (`libsmbd.a`, the shared library, `smbd.h`); `zig build test` runs the unit tests (zsmbd's, and libsmbd's in a binary without SQLite) and the C test, `test/c/smoke.c`.
* `zig build torture` makes `zsmbt`, the protocol test client ([test/torture/](test/torture/README.md)); it imports only `smb/proto.zig` and `shared/crypto.zig`, its self-tests run in `zig build test`, and `zsmbt --server zig-out/bin/zsmbd` runs it against a `zsmbd` of its own. `--target` requires `--profile` (zsmbd, samba, windows), so results say what they were judged against.
* Local databases, logs, and test shares go in `var/` (git-ignored), e.g. `--db var/zsmbd.db`.
* Version: semantic, in `build.zig.zon` only (code reads `build_options.version`); releases get a CHANGELOG.md section and a `vX.Y.Z` tag.
* `zig build check -Dtarget=x86_64-linux-gnu` (and `aarch64-linux-gnu`) type-checks main and both test binaries for Linux.
* Components (`src/` folders) depend one way: main → cli → web, control, policy, smbd; web → policy → store → shared; smbd (`smb/`) → shared only; `web/`, `control/`, and `policy/` never import `smb/`.
* Untrusted input and secrets are mapped in [SECURITY.md](SECURITY.md); every new parser of untrusted input gets a fuzz target (`src/shared/fuzz.zig`) and a row there; each fuzz target is in one test binary only (a `shared/` one goes in a file only `smbd.zig` imports, like `shared/wire_fuzz.zig`).
* CI: `.github/workflows/ci.yml` (Fedora, Alpine, macOS; type checks; fuzzing; Linux interoperability tests, [test/interop/](test/interop/README.md); `zsmbt`; a `vX.Y.Z` tag also builds, on each platform's own runner (`.github/dist.sh`), a `zsmbd` archive (the server) and a `zsmbd-dev` archive (libsmbd and `smbd.h`) and publishes a GitHub Release with its CHANGELOG.md section).
* Specifications used are copied to `docs/specifications/` and indexed in its [README.md](docs/specifications/README.md); add new ones there.
* Release builds name a CPU with hardware AES (`-Dcpu`, per target in `ci.yml`); `serve` warns when a build has none.
* Only external library: system libsqlite3, through hand-written `extern` declarations.

## Decisions
* libsmbd stores nothing: its host supplies shares, NT hashes, and the log (`Host`) and pushes settings (`setConfig`); nothing in `smb/` calls `std.log`. `start`, `adopt`, `stop`, and `wait` bound its life; connections are `Io.Group` tasks, and `stop` returns once they have ended.
* libsmbd's C interface: `src/smbd_c.zig` and the hand-written `include/smbd.h`; opaque `smbd_server`, callbacks that copy in (`smbd_shares_add`) so no memory crosses the boundary, negative `SMBD_E*` codes, `malloc`ed memory, and one `std.Io.Threaded` per process (refcounted). Unstable before 1.0.
* SMB 3.1.1 or later (no older dialect); signing required by default.
* Authentication: SPNEGO with NTLMv2 only; no Kerberos.
* Anonymous sessions can't sign, so a guest share works only with `signing_required = no`; with signing required, `serve` and share changes warn about each guest share.
* Not supported: SMB before 3.1.1, oplocks and leases, multichannel, DFS, named streams, durable handles, and Windows ACLs.
* Shares are confined to their real path: `..` and stream names are rejected, symlinks are followed only inside the share, and lookups fall back to case-insensitive matching.
* Settings (the complete list, with defaults): server_name (host name up to its first dot, upper-cased, at most 15 characters), workgroup (`WORKGROUP`), signing_required (yes), encrypt (no). Web-console changes apply at once; `set` and file edits apply when `serve` restarts. Settings with shares, and users, each live in SQLite or in a plain-text file (`--config FILE`, `--users FILE`), in any combination; CLI flags cover locations (`--db`, `--config`, `--users`, `--socket`), listen addresses, and the ephemeral entries of `serve`; each new flag needs a reason.
* Users have an SMB password (NT hash), a web password (argon2id), both (optional), or neither; each opens one service. No role is stored; smb, web, both, and none are display names only.
* Users with both passwords should keep them separate and get a hygiene warning on every change, and a stronger one when the two passwords match.
* Password strength is reported, never enforced; only empty passwords are refused.
* NT hashes are password-equivalent: the users file is written with mode 0600, and zsmbd warns when others can read it.
* Plain-text files: the config file is `key = value` settings, then a `[name]` share section per share with `path`, `comment`, `read_only`, and `guest_ok`; the users file is one `name:nt_hash:web_hash` line per user, a blank hash disabling that service. `#` and `;` start whole-line comments, which zsmbd's edits keep. Hand edits apply without a restart (settings excepted); a file that doesn't parse is reported with its line number.
* SMB passwords cross the network only from the CLI (stdin) or the web console, which hashes them in the browser with WebAssembly and falls back to server hashing.
* CLI commands: `serve`, `user` (`list`, `add`, `passwd`, `nopasswd`, `del`), `share` (`list`, `add`, `comment`, `readonly`, `readwrite [--kick]`, `guest [--kick]`, `noguest`, `del`), `web start|stop`, `get`, `set`, `hash`, `help`; `--web` or `--both` selects the password a `user` or `hash` command acts on (flags before or after LOGIN; `user add` sets none). Each command's synopsis is in [README.md](README.md).
* CLI storage flags: `--db PATH`, `--config FILE`, `--users FILE`. `--db` is required for any part not in a file and has no default; `--db none` (serve only), or `serve` given ephemeral entries and no `--db`, keeps the store in memory. Other flags cover listen addresses, `--socket`, and the ephemeral entries of `serve`; each new flag needs a reason.
* CLI I/O: each password comes from one line of stdin, unechoed at a terminal. Usage errors print that command's synopsis and exit 2; unknown commands open no store. `web start` defaults to the console's last address, else a port is required. `hash` opens no store. `share comment SHARE ""` clears a comment; other failures exit 1. Without a running `serve` the CLI reports nothing about it. `user list` and `share list` mark ephemeral entries.
* `serve` defaults: SMB `0.0.0.0:445` for root, else `:4450`; web `127.0.0.1`, no default port.
* SIGTERM and SIGINT stop `serve` (libsmbd `stop`, web console, control socket) and exit 0; a second signal kills at once.
* Ephemeral entries: `serve --share NAME:PATH[:OPTIONS[:TEXT]]` (PATH may be relative to the starting directory and has no colon; OPTIONS from ro, rw, guest, noguest), `--user LOGIN:NT_HASH:WEB_HASH`, `--smb-user` and `--web-user LOGIN:PASSWORD`, and `--users -` (users-file text from stdin; replaces stored users). They live in memory, hide stored entries of the same name, and behave like stored ones in the web console (edit and delete; with `--users -` also create), with a warning. A restart forgets them and reveals what they hid. The CLI can't reach them. A login takes each service once. `serve` masks secret-bearing arguments with `X` in argv right after parsing and warns.
* With no web login, stored or ephemeral, `serve` gives user `admin` a random web password (no SMB password), printed once: stored (created if missing), or ephemeral when nothing can be stored (no `--db`, or `--users -`) and the name is free.
* Share and user changes (web console or control socket): tightening (read-only on, guests off, moved or deleted share; a user without SMB password) disconnects the affected connections; relaxing changes apply to new connections. `share readwrite --kick` and `share guest --kick` (and the console's confirmation) also drop, once and unstored, the connections still acting on the old rules: trees opened read-only, or those with an anonymous session.
* Control socket: `serve` listens on a Unix socket (mode 0600; same user or root only) beside the first persistent store (`PATH.sock` for `--db`, else `--config`, else `--users`; none for an in-memory store), so CLI commands that change shares, users, or settings can tell it (`share NAME`, `share-kick writable|guests NAME`, `user NAME`, `settings`, `web start [[ADDR:]PORT]`, `web stop`; reply `ok N` or a message). It re-reads the store and drops the connections whose access tightened; relaxing changes drop none unless `share-kick` asks. `--socket PATH|none` overrides; a path over 100 bytes disables it with a warning.
* Web console: off unless `serve --web [ADDR:]PORT` (no default port; a bare port is `127.0.0.1`, and there is no TLS); while off, there is no HTTP listener or first-run `admin`, and `--web-user` is refused; users with a web password only; session cookie; every POST, PUT, and DELETE must send `X-Zsmbd: 1`; no CORS.
* Any web login may be deleted or lose its password, the last included; the console then stops (after replying) and ends the user's sessions, whether the change came from the console or the control socket. `web start` brings it back, making `admin` first if no web login exists (its password is in the reply).

## Status
* See [ARCHITECTURE.md](ARCHITECTURE.md) section 13. Next: interoperability tests with Windows and macOS clients, then the browser UI.
