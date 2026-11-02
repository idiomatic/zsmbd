# Changelog

All notable changes to zsmbd. Versions follow [Semantic Versioning](https://semver.org/);
the version lives in `build.zig.zon`, and each release is tagged `vX.Y.Z`.

## 0.1.1 (2026-11-02)

### Fixed
- Directory entries and other UTF-16 length fields for names that are not valid UTF-8 (`wire.utf16Len` now counts what `appendUtf16` writes).
- The reply to a request the client signed is signed, even on a session that does not require signing, and so are the reply to LOGOFF on a signing session and an error reply on one.
- A session's signing mode follows what NEGOTIATE advertised, not the setting as it is at SESSION_SETUP or TREE_CONNECT.
- NEGOTIATE answers STATUS_SMB_NO_SIGNING_ALGORITHM_OVERLAP when the client's signing context omits AES-CMAC.
- Web logins for users without a web password take as long as other failures.
- Setting attributes on a handle without a file descriptor refuses a symlink, on every host alike, and works on musl hosts without /proc.
- A rejected DCE/RPC PDU is dropped instead of blocking every later write on the pipe.
- Web error bodies are complete JSON however long the message, and a rejected setting is reported by name.
- `treeConnect` no longer leaks the share name when allocation fails.

### Changed
- CI installs Zig with `mlugg/setup-zig`.
- README attributes the authorship to Claude.

## 0.1.0 (2026-10-31)

First version.

### Added
- SMB 3.1.1 only: 2.0.2, 2.1, 3.0, and 3.0.2 are not negotiated, preauthentication integrity is required, and signing is AES-CMAC.
- NEGOTIATE (`smb/handshake.zig`): the preauthentication hash (SHA-512 required), AES-128-GCM or AES-128-CCM by context, and the SMB1 upgrade through the wildcard dialect.
- SESSION_SETUP (`handshake.sessionSetup`): SPNEGO or raw NTLMSSP with NTLMv2, the per-session preauth hash, 3.1.1 key derivation, mechListMIC checks, a signed final response, anonymous sessions, `signing_required` and `encrypt` policy, and at most 64 sessions per connection; binding and reauthentication are refused.
- TREE_CONNECT: share lookup with `realpath`, synthesized `IPC$`, read-only maximal access, guest rules for anonymous sessions, and at most 256 trees per session.
- Signature verification (`conn.signatureValid`): requests on signing sessions, or flagged signed, need a valid AES-CMAC signature, compared in constant time; anonymous and unfinished sessions never verify.
- Decryption (`conn.handleFrame`): transform frames are checked, decrypted with AES-128-GCM or AES-128-CCM, and answered sealed; any failure closes the connection, and every unrelated request inside must name the transform's session.
- SMB request loop (`conn.serve`): frame reading with the 4 MiB + 64 KiB limit, compound chains (related requests inherit the session, tree, and file ID, and fail after a failed predecessor), the credit window with per-payload charges, ECHO, LOGOFF, TREE_DISCONNECT, CANCEL of pending CHANGE_NOTIFY requests, dispatch to the file commands, and a log line saying why each connection ended.
- Live activity for the admin console (`web.Live`): `GET /api/activity` lists connections with their sessions, trees, and open handles, the recent events, and counters; `POST /api/kick` drops a connection; saving settings in the web console reloads them without a restart.
- `--db none` (serve only) keeps the store in memory, as `serve` does when it is given ephemeral entries and no `--db`.
- NTLM: the AUTHENTICATE MIC is verified when the client sent one (`MsvAvFlags`), and a session key exchange needs sign or seal and a 16-byte key, as MS-NLMP 3.2.5.1.2 says.
- Control socket: `serve` listens on a Unix socket beside the store (`PATH.sock`, mode 0600, same user or root), and the CLI tells it about `share`, `user`, and `set` changes, so tightening a share or removing a user's SMB password drops the affected connections at once. `--socket PATH|none` overrides the location; the protocol is one line each way and can grow.
- `zsmbd web start [[ADDR:]PORT]` and `web stop` start and stop a running server's web console through that socket. The last web login can now be deleted or lose its password: the console stops and ends that user's sessions (CLI changes end them too).
- Web console: a Shares panel with Read-only and Allow guests switches for each share. Making a share read-only, moving or deleting it, or removing its guests disconnects the connections using it (guests only, for guests); the panel asks first. Other changes apply to new connections.
- The web console is opt-in: `serve --web [ADDR:]PORT` starts it (a bare port listens on `127.0.0.1`; there is no default port). Without it there is no HTTP listener and no first-run `admin`, and `--web-user` is refused.
- Ephemeral shares and logins for `serve`, kept in memory: `--share NAME:PATH[:OPTIONS[:TEXT]]` (PATH may be relative), `--user LOGIN:NT_HASH:WEB_HASH`, `--smb-user` and `--web-user LOGIN:PASSWORD`, and `--users -` (users-file text from stdin, replacing stored users). They hide stored entries of the same name, show as `ephemeral` in lists, and behave like stored ones in the web console (edit, delete, and with `--users -` create, in memory until exit, with a warning); the secrets in the arguments are masked with `X` in the process's argv after parsing (the login stays visible), with a warning.
- `--db PATH` has no default: it is required for any part not in a file, and `serve` given only ephemeral entries runs with an in-memory store and creates no database.
- `serve` runs the SMB listener (`--smb [ADDR:]PORT`, default `0.0.0.0:445`, or 4450 unless run as root), one thread per connection, and, with `--web [ADDR:]PORT`, the web console; it fails clearly when a port can't be bound.
- SMB file commands (`src/smb/files.zig`): CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL (validate negotiate, pipe transceive, server-side copy, set sparse), QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, and SET_INFO, with share modes, delete-on-close, byte-range locks, and rename.
- Connection core in `src/smb/conn.zig`: reference counting, the open-handle table, the CHANGE_NOTIFY queue, and signed or encrypted message writes.
- SMB building blocks: protocol constants, wire codec, MD4/RC4/AES-CCM/KDF, SPNEGO, NTLMv2 verification, share-confined file system layer, and srvsvc share enumeration.
- Users have an SMB password, a web password, both, or neither; `smb`, `web`, `both`, and `none` are display names. Users with both get password hygiene warnings, and a stronger one when the passwords match.
- Password strength is reported, not enforced (only empty passwords are refused): the CLI prints it, the web page shows a live meter, and the API warns about weak passwords.
- CLI: `user list|add|passwd [--web|--both]|nopasswd [--web|--both]|del`, `share list|add|comment|readonly|readwrite|guest|noguest|del`, `get`, `set`, `hash`, `help`, and `--version`. Passwords come from one line of stdin and aren't echoed at a terminal; a usage error prints that command's synopsis and exits with status 2, and an unknown command opens no store.
- `zsmbd hash` hashes one password from stdin without opening a store, for a users file on another machine: `hash [--web] [LOGIN]` prints the SMB (or web) hash, or with LOGIN a users-file line, and `hash --both LOGIN` a line with both hashes.
- SQLite-backed store for users, shares, and settings.
- Plain-text storage, independently for each part: `--config FILE` keeps settings and shares in an INI-style file, and `--users FILE` keeps users in a `name:nt_hash:web_hash` file (mode 0600); a blank hash disables sign-in to that service. Either, both, or neither may replace the SQLite database. The files may be edited by hand, and changes are picked up without a restart.
- Admin web server JSON API with argon2id login, session cookies, and a CSRF header guard. `PUT /api/users` takes `smb_password`, `nt_hash`, `web_password`, `no_smb_password`, and `no_web_password`, and returns `warnings`; `GET /api/users` reports `has_smb`, `has_web`, and `access`. Changing a user's web password ends their web sessions.
- Web console page with sign-in and an SMB password form that hashes the password in the browser using the server's NT hash code compiled to WebAssembly (`/nthash.wasm`), falling back to server-side hashing when WebAssembly is unavailable.
- The first-run `admin` user gets a random web password, printed once; with no database (no `--db`, or `--users -`) and no web login given, it is ephemeral and gone when `serve` exits.
- Fuzz targets for SMB file commands, NTLM, SPNEGO, DCE/RPC, UTF-16, path normalization, wildcards, the text configuration and users files, and the web cookie and query parsers, on a shared harness that also runs under `zig build test --fuzz`.
- CI workflow: Fedora and Alpine (x86_64, aarch64) and macOS builds and tests, Linux type checks, and fuzzing.
- Documentation: [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md) (trust boundaries, guards, secrets, review checklist, known gaps), [REFERENCES.md](REFERENCES.md) (specifications, copied to `docs/references/`), and the example files [examples/zsmbd.conf](examples/zsmbd.conf) and [examples/users](examples/users).
