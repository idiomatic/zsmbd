# zsmbd

## Requirements
* A network file server daemon implementing SMB 3.1.1 or later, with the fewest configuration options.
* Hosts: recent Linux and macOS. Clients: recent Linux, Windows, and macOS.
* Embedded admin web server: settings, shares (names and directory paths), user credentials, and live activity.
* All code in Zig 0.17.0 or later; this is non-negotiable.
* SQLite may store data (hashed passwords, configuration).
* Keep this file, [ARCHITECTURE.md](ARCHITECTURE.md), and [CHANGELOG.md](CHANGELOG.md) current with each change.

## Build
* `zig build` makes `zsmbd`; `zig build test` runs the unit tests.
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
* Settings (the complete list): server_name, workgroup, signing_required, encrypt. Settings with shares, and users, each live in SQLite or in a plain-text file (`--config FILE`, `--users FILE`), in any combination; CLI flags exist only for these locations and listen addresses.
* User roles: client (SMB only, the default), admin (web console only), and hybrid (both; optional). Each role stores only its own passwords (NT hash for SMB, argon2id for web).
* Hybrid users have separate passwords and get a hygiene warning on every change, and a stronger one when the two passwords match.
* Password strength is reported, never enforced; only empty passwords are refused.
* SMB passwords cross the network only from the CLI (stdin) or the web console, which hashes them in the browser with WebAssembly and falls back to server hashing.
* CLI: `serve [--web ADDR:PORT]`, `user list|add [--role R]|passwd [--web]|role NAME R|del`, `share list|add|del`, `get`, `set KEY VALUE`, and `--db PATH`, `--config FILE`, and `--users FILE` for all; passwords come from stdin, one per line, SMB first.
* First run creates admin-role user `admin` with a random web password, printed once.
* Web console: admin and hybrid users only; session cookie; every POST, PUT, and DELETE must send `X-Zsmbd: 1`; no CORS.
* The last web console admin user can't be deleted nor demoted to client.

## Status
* See [ARCHITECTURE.md](ARCHITECTURE.md) section 13. Next: decryption (`src/smb/conn.zig`).
