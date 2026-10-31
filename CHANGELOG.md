# Changelog

All notable changes to zsmbd. Versions follow [Semantic Versioning](https://semver.org/);
the version lives in `build.zig.zon`, and each release is tagged `vX.Y.Z`.

## Unreleased

### Added
- SMB request loop (`conn.serve`): frame reading with the 4 MiB + 64 KiB limit, compound chains (related requests inherit the session, tree, and file ID, and fail after a failed predecessor), the credit window with per-payload charges, ECHO, LOGOFF, TREE_DISCONNECT, CANCEL of pending CHANGE_NOTIFY requests, and dispatch to the file commands. NEGOTIATE, SESSION_SETUP, TREE_CONNECT, signature verification, and decryption are not written yet and fail closed.

### Changed
- SMB 3.1.1 is the minimum dialect: 2.0.2, 2.1, 3.0, and 3.0.2 are no longer negotiated, preauthentication integrity is required, and HMAC-SHA256 signing, the 3.0 key labels, and the VALIDATE_NEGOTIATE_INFO check are gone. Windows 8.1 and Server 2012 R2 and older, old Samba clients, and embedded clients limited to 2.x or 3.0 can no longer connect.

## 0.1.0 (2026-10-31)

First version.

### Security
- Fixed: an RPC request whose auth length exceeded its fragment crashed the server (integer overflow), and fragments without the last flag could grow memory without limit (now capped at 64 KiB).
- Fixed: READ, WRITE, and set-size offsets of 2^63 or more panicked the whole process; they now return `STATUS_INVALID_PARAMETER`.
- Fixed: the wildcard matcher took exponential time on patterns like `*a*a*a*b` (client-controlled in QUERY_DIRECTORY); it is now linear in pattern × name.
- Fixed: editing `zsmbd.conf` had no effect when a key appeared twice in a section or a setting also appeared in a `[global]` section.

### Changed
- Source tree regrouped into components: `store/` (the `Db` facade, record types, SQLite, and the text files; `db.zig` split three ways), `policy/` (`auth.zig`, `strength.zig`), `shared/` (`crypto.zig`, `wire.zig`), `smb/server.zig` (was `state.zig`), `smb/auth/` (NTLM and SPNEGO), and `cli.zig` (the commands, out of `main.zig`). `policy/` and `web/` no longer import anything from `smb/`.
- The plain-text store is split into `textfile.zig` (shared file handling), `textconf.zig`, and `textusers.zig`.
- Share paths and comments may not contain control characters.
- [AGENTS.md](AGENTS.md) rewritten as a short list of requirements, build commands, and decisions; details live in [ARCHITECTURE.md](ARCHITECTURE.md).
- Password strength is now reported instead of enforced: the 8-character minimum is gone (only empty passwords are refused). The CLI prints each password's estimated strength, the web page shows a live strength meter, and the API warns about weak passwords.
- `PUT /api/users` returns a `warnings` list instead of a single `warning`.
- Users now have a role: `client` (SMB only, the default), `admin` (web console only), or `hybrid` (both, optional). Each role stores only the passwords it uses, so the web login never carries an SMB password.
- Hybrid users get password hygiene warnings, including a stronger warning when their SMB and web passwords are identical.
- CLI: `user add --role`, `user role NAME ROLE` (replaces `user admin NAME on|off`), and `user passwd --web` for hybrids; `user list` shows roles. Passwords are read one per line from a single stdin reader.
- `PUT /api/users` takes `role`, `password` (SMB), and `web_password` (replacing `admin`) and returns any `warning`; `GET /api/users` reports roles.
- Existing databases are migrated on open: admins become hybrids, other users clients.
- The first-run `admin` user has the admin role (web password only).
- Changing a user's web password, or moving them to the client role, ends their web sessions.

### Fixed
- CLI output redirected to a file no longer overwrites itself (stdout is written as a stream).

### Added
- [REFERENCES.md](REFERENCES.md) indexes the specifications behind zsmbd (Microsoft Open Specifications, RFCs, and NIST papers), with copies in `docs/references/`.
- `zsmbd --version`; the server logs its version at startup.
- [SECURITY.md](SECURITY.md): trust boundaries, their guards and tests, secrets, a review checklist, and known gaps.
- Fuzz targets for SMB file commands, NTLM, SPNEGO, DCE/RPC, UTF-16, path normalization, wildcards, the text configuration and users files, and the web cookie and query parsers, on a shared harness that also runs under `zig build test --fuzz`.
- CI workflow: Fedora and Alpine (x86_64, aarch64) and macOS builds and tests, Linux type checks, and fuzzing.
- Plain-text storage, independently for each part: `--config FILE` keeps settings and shares in an INI-style file, and `--users FILE` keeps users in a `name:role:nt_hash:web_hash:created` file (mode 0600). Either, both, or neither may replace the SQLite database. The files may be edited by hand, and changes are picked up without a restart.
- SMB file commands (`src/smb/files.zig`): CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL (validate negotiate, pipe transceive, server-side copy, set sparse), QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, and SET_INFO, with share modes, delete-on-close, byte-range locks, and rename, plus unit tests.
- Connection core in `src/smb/conn.zig`: reference counting, the open-handle table, the CHANGE_NOTIFY queue, and signed or encrypted message writes. `state.zig` now compiles.
- `zig build check` also type-checks the tests.
- Web console page with sign-in and an SMB password form that hashes the password in the browser using the server's NT hash code compiled to WebAssembly (`/nthash.wasm`), falling back to server-side hashing when WebAssembly is unavailable.
- `PUT /api/users` accepts `nt_hash` (32 hex digits) in place of `password`.
- [ARCHITECTURE.md](ARCHITECTURE.md): long-form description of the process and thread model, modules, data model, SMB protocol stack, admin web server, concurrency rules, and roadmap. It absorbs the former connection handler spec (`docs/conn-handler-spec.md`).
- SQLite-backed store for users, shares, and settings; CLI for managing them.
- Admin web server JSON API with argon2id login, session cookies, and a CSRF header guard.
- SMB building blocks: protocol constants, wire codec, MD4/RC4/AES-CCM/KDF, SPNEGO, NTLMv2 verification, share-confined file system layer, and srvsvc share enumeration.
