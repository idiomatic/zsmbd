# Security review map

Where zsmbd handles untrusted input or secrets, what guards each place, and
which tests cover it. Design detail is in [ARCHITECTURE.md](ARCHITECTURE.md).
Report vulnerabilities privately to the maintainer rather than in a public
issue.

## Trust boundaries

| # | Boundary | Attacker | Guarded by | Tests |
|---|---|---|---|---|
| 1 | SMB requests from the network | anyone who can reach port 445 | `wire.slice` (bounds-checked reads; `error.Malformed`), `files.dispatch` | `files.zig`: unit tests, `fuzz: file commands` |
| 2 | Client paths → host paths | authenticated SMB users | `vfs.normalize` (rejects `..`, `:`, control and Windows-illegal characters), `vfs.resolve` (symlinks only inside the share root) | `vfs.zig`: `normalize`, `fuzz: normalize`; `files.zig`: `names that leave the share are refused` |
| 3 | Client wildcard patterns | authenticated SMB users | `vfs.wildcardMatch`: linear-time table, input capped at 1024 bytes | `fuzz: wildcardMatch agrees with the reference matcher`, `wildcardMatch is fast on backtracking patterns` |
| 4 | Client offsets and sizes | authenticated SMB users | `vfs.checkRange` (≤ `maxInt(i64)` before any `off_t` cast); READ and WRITE ≤ 4 MiB; copy chunk limits | `client offsets beyond off_t are refused, not trapped`, `fuzz: file commands` |
| 5 | Authentication tokens | anyone on the network | `spnego.parseClientToken`, `ntlm.authenticate` (NTLMv2 only, constant-time proof check); SMB 3.1.1 or later only, so preauthentication integrity binds session keys to the negotiation and defeats downgrades | MS-NLMP 4.2.4 vectors, `fuzz: parseClientToken`, `fuzz: NEGOTIATE and AUTHENTICATE parsing` |
| 6 | DCE/RPC on `IPC$` | anonymous sessions | `rpc.Pipe.write` (fragment length, auth trailer, 64 KiB stub cap) | `bind then NetrShareEnum level 1`, `fuzz: DCE/RPC pipe` |
| 7 | UTF-16 names | all of the above | `wire.utf16ToUtf8` (invalid sequences become U+FFFD) | `fuzz: UTF-16 decoding round-trips` |
| 8 | Admin HTTP API | web pages in the admin's browser; local users | `X-Zsmbd: 1` on every POST, PUT, and DELETE; SameSite=Strict HttpOnly cookie; no CORS; 64 KiB body cap; 750 ms delay after a failed login | `fuzz: cookie and query parsing` (parsers only; the handlers have no automated tests yet) |
| 9 | Text configuration and users files | local users who can write them | `textconf.parseConf`, `textusers.parseUsers`; a broken file keeps the last good contents and blocks writes | `fuzz: configuration parsing and editing`, `fuzz: users file parsing` |
| 10 | Validation of admin input | admins, the CLI | `policy/auth.zig`: `validateUserName`, `validateShareName`, `validateSharePath`, `validateComment`, `normalizeSetting` | `validation` |
| 11 | SMB frames and compound chains | anyone on the network | `conn.readFrame` (4 MiB + 64 KiB cap), `conn.nextInChain` (alignment and bounds), `Credits` (message-ID window), `conn.smb1OffersSmb2`; bad or missing AES-CMAC signatures (`conn.signatureValid`) and plain frames on encrypting sessions fail closed | `conn.zig` unit tests, `fuzz: frames, compound chains, and credits` |
| 12 | NEGOTIATE, SESSION_SETUP, and TREE_CONNECT | anyone on the network (NEGOTIATE, SESSION_SETUP); SMB sessions (TREE_CONNECT) | `handshake.negotiate` (bounds-checked contexts, SHA-512 required, one of each context), `handshake.sessionSetup` (64 sessions per connection, never compounded, failed exchanges removed, mechListMIC checked in constant time, no binding or reauthentication), `handshake.treeConnect` and `shareName` (path syntax, share lookup, `realpath`, anonymous rules, 256 trees per session) | `handshake.zig` unit tests, `fuzz: NEGOTIATE, SESSION_SETUP, and TREE_CONNECT` |

## Secrets

| Secret | Stored as | Notes |
|---|---|---|
| SMB password | NT hash (MD4 of UTF-16LE) | Password-equivalent ("pass the hash"). SQLite or the users file (mode 0600, with a warning when others can read it). The web console hashes it in the browser (`nthash_wasm.zig`). |
| Web password | argon2id (t=2, m=19 MiB) | `policy/auth.zig`: `hashPassword`, `verifyPassword`. |
| Session token | 256 random bits, in memory | Looked up in a hash map; a 12-hour sliding expiry; ended by a web password change or a move to the client role. |
| SMB session keys | in memory | Derived with `crypto.kdf`; copied into each pending `Notify` so another thread can sign or seal. |

Plaintext passwords are wiped (`secureZero`) after use in the CLI, the
WebAssembly module, and the users-file writer.

## Review checklist for changes

- Every read of client data goes through `wire.slice` or checks its length
  first; no `@intCast` of a client value without a range check.
- Every client path goes through `vfs.normalize`, then `vfs.resolve`.
- New parsers of untrusted input get a fuzz target (`shared/fuzz.zig`) and a
  row in the table above.
- No lock is held across socket I/O or a database call (ARCHITECTURE.md
  section 9).
- Secrets never reach logs, URLs, or error messages.

## Fuzzing

`zig build test` runs each fuzz target on its seeds plus 400 deterministic
mutations of each seed, so CI catches regressions reproducibly.
`zig build test --fuzz=1M` adds Zig's coverage-guided fuzzer and saves
crashing inputs in `.zig-cache/f/`. Run `zig build test` once first; the
fuzzer needs `.zig-cache/tmp`.

Fuzzing found, and these were fixed:

- An integer overflow in the RPC parser on an auth length longer than the
  fragment, plus unbounded stub growth from fragments without the last flag.
- A process-wide panic on WRITE, READ, or set-size offsets of 2^63 or more.
- Exponential time in the wildcard matcher (found while writing its target).
- Edits to `zsmbd.conf` that had no effect when a key appeared twice or also
  in a `[global]` section.

## Known gaps

- **No TLS on the admin server.** It listens on 127.0.0.1 by default; NT
  hashes and session cookies cross plain HTTP otherwise.
- **No `Host` header check.** A DNS-rebinding page can reach the admin API as
  same-origin. It has no session cookie for its host name, but it can try
  passwords at the login delay.
- **Decryption is not written** (`smb/conn.zig`): it fails closed. Only
  AES-CMAC has a known-answer test; SESSION_SETUP is checked against an
  in-test client rather than a real one, and the SMB key derivation,
  signing, and encryption paths lack spec vectors.
- **The NTLM AUTHENTICATE MIC** (MS-NLMP 3.2.5.1.2) is not checked; the
  SPNEGO mechListMIC and the preauth-bound keys cover tampering instead.
- **Host-side races.** A local process could swap a directory for a symlink
  between resolution and open; byte-range locks are advisory among SMB
  clients only.
- **Text-file writes** from two processes at the same moment can lose one
  change.
