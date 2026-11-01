# zsmbd

## Requirements
* A network file server daemon implementing SMB 3.1.1 or later, with the fewest configuration options.
* Hosts: recent Linux and macOS. Clients: recent Linux, Windows, and macOS.
* Embedded admin web server: settings, shares (names and directory paths), user credentials, and live activity.
* All code in Zig 0.17.0 or later; this is non-negotiable.
* SQLite may store data (hashed passwords, configuration).
* Markdown code blocks are at most 60 columns wide (due to a Claude desktop app bug).
* Keep this file, [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [CHANGELOG.md](CHANGELOG.md) current with each change.

## Build
* `zig build` makes `zsmbd`; `zig build test` runs the unit tests.
* Local databases, logs, and test shares go in `var/` (git-ignored), e.g. `--db var/zsmbd.db`.
* Version: semantic, in `build.zig.zon` only (code reads `build_options.version`); releases get a CHANGELOG.md section and a `vX.Y.Z` tag.
* `zig build check -Dtarget=x86_64-linux-gnu` (and `aarch64-linux-gnu`) type-checks main and the tests for Linux.
* Components (`src/` folders) depend one way: main → cli → web, smb → policy → store → shared; `web/` and `policy/` never import `smb/`.
* Untrusted input and secrets are mapped in [SECURITY.md](SECURITY.md); every new parser of untrusted input gets a fuzz target (`src/shared/fuzz.zig`) and a row there.
* CI: `.github/workflows/ci.yml` (Fedora, Alpine, macOS; type checks; fuzzing).
* Specifications used are copied to `docs/references/` and indexed in [REFERENCES.md](REFERENCES.md); add new ones there.
* Only external library: system libsqlite3, through hand-written `extern` declarations.

## Decisions
* SMB 3.1.1 or later (no older dialect); signing required by default.
* Authentication: SPNEGO with NTLMv2 only; no Kerberos.
* Not supported: oplocks and leases, multichannel, DFS, and named streams.
* Shares are confined to their real path: `..` and stream names are rejected, symlinks are followed only inside the share, and lookups fall back to case-insensitive matching.
* Settings (the complete list): server_name, workgroup, signing_required, encrypt. Settings with shares, and users, each live in SQLite or in a plain-text file (`--config FILE`, `--users FILE`), in any combination; CLI flags exist only for these locations, listen addresses, and the ephemeral entries of `serve`.
* Users have an SMB password (NT hash), a web password (argon2id), both (optional), or neither; each opens one service. No role is stored; smb, web, both, and none are display names only.
* Users with both passwords should keep them separate and get a hygiene warning on every change, and a stronger one when the two passwords match.
* Password strength is reported, never enforced; only empty passwords are refused.
* SMB passwords cross the network only from the CLI (stdin) or the web console, which hashes them in the browser with WebAssembly and falls back to server hashing.
* CLI: `serve [--smb [ADDR:]PORT] [--web [ADDR:]PORT] [--share SPEC]... [--user SPEC]... [--smb-user LOGIN:PASSWORD]... [--web-user LOGIN:PASSWORD]...` (ADDR defaults: 0.0.0.0 and 127.0.0.1; the SMB port defaults to 445 for root, else 4450), `user list|add LOGIN|passwd [--web|--both] LOGIN|nopasswd [--web|--both] LOGIN|del LOGIN` (flags before or after LOGIN; `add` sets no password), `share list|add SHARE PATH|comment SHARE TEXT|readonly|readwrite|guest|noguest|del SHARE`, `get [KEY]`, `set KEY VALUE`, `hash [--web] [LOGIN]` and `hash --both LOGIN` (one password; a users-file line with LOGIN, else the hash; opens no store), `help`, and `--db PATH`, `--config FILE`, and `--users FILE` for the rest (`--db` is required for any part not in a file, with no default; `serve` given only ephemeral entries and no `--db` keeps the store in memory); each password comes from one line of stdin, unechoed at a terminal. Usage errors print that command's synopsis and exit 2; unknown commands open no store.
* Ephemeral entries: `serve --share NAME:PATH[:OPTIONS[:TEXT]]` (PATH may be relative to the starting directory; OPTIONS from ro, rw, guest, noguest), `--user LOGIN:NT_HASH:WEB_HASH`, `--smb-user` and `--web-user LOGIN:PASSWORD`, and `--users -` (users-file text from stdin; `serve` only; replaces stored users). They live in memory, hide stored entries of the same name, and behave like stored ones in the web console (edit, delete, and with `--users -` create, all in memory, with a warning, never past the last web login), so the only difference is that a restart forgets them (and reveals any stored entry they hid); the CLI is another process and can't reach them; a login takes each service once. The last-web-user guard counts stored users only. Secret-bearing arguments are masked with `X` after the login in the process's argv right after parsing, and `serve` warns about them.
* With no web login, stored or ephemeral, `serve` gives user `admin` a random web password (no SMB password), printed once: stored (created if missing), or ephemeral when nothing can be stored (no `--db`, or `--users -`) and the name is free.
* Share changes in the web console: tightening (read-only on, guests off, moved, or deleted) disconnects the connections using the share; relaxing changes and CLI edits apply to new connections.
* Web console: off unless `serve --web [ADDR:]PORT` (no default port; a bare port is `127.0.0.1`); users with a web password only; session cookie; every POST, PUT, and DELETE must send `X-Zsmbd: 1`; no CORS.
* The last user with a web password can't be deleted nor lose it.

## Status
* See [ARCHITECTURE.md](ARCHITECTURE.md) section 13. Next: interoperability tests with real clients, then the browser UI.
