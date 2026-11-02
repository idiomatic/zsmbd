# zsmbd architecture

> **Style note for maintainers and agents:** this document is exempt from the
> succinct-specification rule. Automatic updates keep it in long form: explain
> each design in full prose, including the rationale, trade-offs, and
> examples, rather than reducing it to terse requirements. The succinct
> summary of decisions lives in [AGENTS.md](AGENTS.md).

zsmbd is a small SMB 3 file server for Linux and macOS hosts, written entirely
in Zig, that serves Windows, macOS, and Linux clients. It ships as one binary
that contains the SMB server, an embedded admin web server, and a command-line
tool for managing the same configuration. All persistent state lives in one
SQLite database file or, if preferred, in two plain-text files.

This document describes how the pieces fit together: the process and thread
model, each module's responsibility, the data that flows between them, and the
security decisions behind them. It covers both what exists today and the parts
still to be written; each section says which. The requirements themselves live
in [AGENTS.md](AGENTS.md). Section references written as "MS-SMB2 x.y" are to
Microsoft's SMB2/3 protocol specification.

---

## 1. Goals and constraints

| Goal | Consequence for the design |
|---|---|
| Fewest configuration options | Every setting has a working default. No configuration file is needed. The command line takes only a store location (a database path, or a directory of plain-text files) and a web listen address. Four settings exist in total, edited from the web UI, the CLI, or the text file. |
| SMB 3.1.1 as the minimum | No older dialect is negotiated, so there is one signing algorithm, one key derivation, and preauthentication integrity on every connection. Windows 10 and later, macOS, and Linux all speak it; Windows 8.1 and older, and embedded clients limited to 2.x or 3.0, cannot connect. SMB1 is never spoken. |
| Modern clients | Signing is required by default because Windows 11 24H2 refuses unsigned sessions with non-domain servers. NTLMv2 is the only accepted authentication. |
| Linux and macOS hosts | File access goes through a thin POSIX layer (`vfs.zig`) with small per-OS branches (`statx` on Linux, `statfs` layout on Darwin). |
| Pure Zig | No C sources and no `translate-c`. The one external library, the system `libsqlite3`, is bound with hand-written `extern` declarations. Cryptography missing from Zig's standard library (MD4, RC4, AES-CCM, the SP 800-108 KDF) is implemented in Zig. |
| Embedded admin web server | A single-page UI plus a JSON API, served from the same process, sharing the database and live server state. |

### Non-goals

These are deliberately left out to keep the server small. Each has a known
client fallback.

- **Oplocks and leases.** Every CREATE grants no oplock. Clients then do not
  cache aggressively, which costs some performance but is always correct.
- **Multichannel, RDMA, and QUIC.** One TCP connection per session.
- **DFS.** Shares are never advertised as DFS; DFS referral FSCTLs fail.
- **Named streams and extended attributes over SMB.** Only the default data
  stream (`::$DATA`) is accepted. macOS clients detect this and fall back to
  AppleDouble (`._name`) files for resource forks and Finder metadata.
- **Kerberos and domain membership.** Users are local to zsmbd.
- **Durable and persistent handles.** A dropped connection loses its opens.
- **Windows ACLs.** Security descriptors are synthesized from share
  permissions, not stored.

---

## 2. Process overview

```
                 ┌──────── zsmbd serve ────────┐
                 │                             │
 SMB clients ───►│ SMB listener (:445)         │
 (TCP 445)       │   │ accept                  │
                 │   ▼                         │
                 │ conn thread ×N              │
                 │   ├► smb/conn.zig           │
                 │   │    ├► smb/files.zig     │
                 │   │    │    └► smb/vfs.zig  │
                 │   │    │         └► host FS │
                 │   │    ├► smb/rpc.zig       │
                 │   │    │    (IPC$ srvsvc)   │
                 │   │    └► ntlm, spnego,     │
                 │   │       crypto            │
                 │   ▼                         │
                 │ server.Server               │
                 │   config snapshot,          │
                 │   connection registry,      │
                 │   open-file nodes,          │
                 │   activity ring, counters   │
                 │   ▲                         │
                 │   │ web.Live hooks          │
                 │   │ (activity, kick,        │
                 │   │  reload)                │
 Browser ───────►│ admin web server            │
 (HTTP)          │   127.0.0.1:8445,           │
                 │   web/server.zig            │
                 │   │ thread per connection   │
                 │   ▼                         │
                 │ policy/auth ──► store       │
                 │     ├► sqlite.zig ► zsmbd.db│
                 │     └► textconf, textusers  │
                 │          ──► files          │
                 └─────────────────────────────┘

 zsmbd user|share|get|set ──► cli
   ──► policy/auth ──► store
   (a separate process)
```

One process hosts up to two listeners: SMB (`--smb`, default `0.0.0.0:445`,
or `0.0.0.0:4450` unless run as root) and the admin web server, which runs
only when `--web` is given (it has no default port). Each flag takes
`ADDR:PORT` or just `PORT` (or `:PORT`), and a missing address keeps that
listener's default, so `--smb 4450` still listens on every interface and
`--web 8099` only on localhost. `serve` binds the SMB port first and fails
if it cannot, then runs `Server.acceptLoop` on its own thread (without
`--web` there is no web listener and no first-run `admin`, and
`acceptLoop` runs on the main thread). Each accepted
connection, SMB or HTTP, gets its own detached OS thread. The threads share three things: the store
(`store.Db`: SQLite or plain-text files), the in-memory server state (`server.Server`), and the
`std.Io` instance from `std.process.Init`, which is thread-safe.

The CLI commands other than `serve` open the same store, make their change,
and exit. Because SQLite runs in WAL mode, and text files are replaced
atomically, they can run while a server is up.
A running server notices CLI changes to shares and users on its next lookup
(they are read from the database each time); settings changed from the CLI
take effect on the next restart or on the next settings save from the web UI,
which triggers a reload.

---

## 3. Source layout

```
build.zig            build, test, type-check steps
examples/            example --config and --users files
src/
  main.zig           global flags, store, run a command
  cli.zig            serve, user, share, get, set, hash
  nthash_wasm.zig    NT hash and strength for WebAssembly
                     (top level, so its module can reach
                     shared/ and policy/)
  shared/
    wire.zig         LE codec, output buffer, UTF-16
    crypto.zig       MD4, NT hash, RC4, AES-CCM, KDF,
                     signatures
  store/
    store.zig        Db: a backend per part, one mutex
    types.zig        User, UserAuth, Share, Change, errors
    sqlite.zig       SQLite bindings, schema, queries
    textfile.zig     text file: change check, atomic write
    textconf.zig     settings and shares (--config FILE)
    textusers.zig    users (--users FILE)
    ephemeral.zig    serve's in-memory shares and users
  policy/
    auth.zig         validation, hashing, settings,
                     first-run bootstrap
    ephemeral.zig    parses serve's ephemeral flags
    strength.zig     password strength (informs only)
  smb/
    server.zig       process-wide state: connections,
                     nodes, events
    conn.zig         one connection: framing, chains,
                     credits, dispatch
    handshake.zig    NEGOTIATE (and SMB1 upgrade),
                     TREE_CONNECT
    files.zig        file commands: CREATE ... SET_INFO
    vfs.zig          POSIX access confined to a share
    rpc.zig          DCE/RPC srvsvc: NetrShareEnum,
                     NetrShareGetInfo
    proto.zig        SMB2/3, MS-FSCC, NTSTATUS constants
    auth/
      spnego.zig     minimal DER SPNEGO
      ntlm.zig       NTLMSSP server, NTLMv2 verification
  control/
    control.zig      control socket: the CLI tells serve
  web/
    server.zig       admin HTTP server and JSON API
    index.html       single-page UI via @embedFile
                     (sign-in and SMB password form so far)
```

### Module dependencies

Each folder is a component, and dependencies point one way:

```
main ──► cli ──┬──► web ────┐
               │            ▼
               ├──► control (std only)
               │
               └──► smb ──► policy ──► store ──► shared
                     │                   ▲
                     └───────────────────┴──────► shared
```

- `shared/` depends on nothing else in the project, and `store/` only on
  libsqlite3.
- `policy/` uses `store/` and `shared/crypto.zig` (to store NT hashes). It
  checks share paths with its own `open` call, so it never reaches into
  `smb/`.
- `web/` uses `policy/` and `store/` and reaches the SMB side only through
  the `web.Live` hooks (section 8).
- `control/` imports only `std` and `shared/fuzz.zig` (for its fuzz
  target) and reaches the SMB side only through its `Hooks` (section 8,
  "Control socket").
- `smb/` is the only component that knows about connections and threads.
  `smb/server.zig` and `smb/conn.zig` refer to each other, but the cycle
  stays inside the component. `files.zig` gets the share list from the store
  through `smb/server.zig`'s `*Db`.
- Within `store/`, the backends import `types.zig`, never the `store.zig`
  facade that imports them.

---

## 4. Persistent data: `store/`

### Schema

```sql
settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)
users(name TEXT PRIMARY KEY COLLATE NOCASE,
      -- SMB password: MD4(UTF-16LE(pw)); empty = none
      nt_hash BLOB NOT NULL,
      -- web password: argon2id PHC; empty = none
      web_hash TEXT NOT NULL,
      created INTEGER NOT NULL)  -- Unix seconds
shares(name TEXT PRIMARY KEY COLLATE NOCASE,
       path TEXT NOT NULL,       -- absolute directory
       comment TEXT NOT NULL DEFAULT '',
       read_only INTEGER NOT NULL DEFAULT 0,
       guest_ok INTEGER NOT NULL DEFAULT 0)
```

The schema is created with `CREATE TABLE IF NOT EXISTS` on every open, so a
new database needs no setup step. Names are case-insensitive to match how
Windows treats user and share names.

### Users and passwords

The web console is for administering the server, so most SMB users never
sign in to it. A user has an SMB password, a web password, both, or neither,
and each password opens one service: SMB or the web console. Nothing else is
stored about what a user may do; there is no role field or type. For
display, `auth.accessName` names the four cases after the `user passwd`
flags:

| Name | Passwords | Signs in to |
|---|---|---|
| `smb` | SMB | SMB only |
| `web` | web | web console only |
| `both` | both, kept separate | both |
| `none` | neither | nothing |

`zsmbd user add LOGIN` creates a user with neither (`auth.addUser`). `user
passwd LOGIN` sets the SMB password and `user passwd --web LOGIN` the web
password (`auth.grantPasswords`); `--both` sets both from one password,
with the identical-passwords warning. `user nopasswd` clears them the same
way (`auth.revokePasswords`). The web API does the same with
`smb_password` (or `nt_hash`), `web_password`, `no_smb_password`, and
`no_web_password`. The users
file stores exactly the same thing: one line, two hashes, either blank.

The store's `putUser` takes a `Change` for each hash (`keep`, `clear`, or
`set`), so callers say exactly what changes, and `User` and `UserAuth` carry
`has_smb` and the web hash (or `has_web`) instead of a role.

- The **SMB password** is stored as its NT hash, because NTLM authentication
  needs it: the server recomputes the client's HMAC-MD5 proof from it. The NT
  hash is therefore password-equivalent for SMB, and the database file must be
  protected like a password file. NTLMv2 itself never sends the password or
  its hash over the network.
- The **web password** is stored as an argon2id hash (t = 2, m = 19 MiB,
  p = 1) and is used only to sign in to the web console.

`db.ntHash` returns nothing for a user without an SMB password, so such a
user trying SMB fails exactly like an unknown user; web sign-in likewise
requires a non-empty web hash.

The web login carries a password over plain HTTP, so it must never be an SMB
password. For users with one password this holds by construction. An SMB password crosses the network only when someone
sets it, either through the CLI, which reads it from stdin on the server
host, or through the web console.

The web console hashes SMB passwords in the browser where it can, so the
plaintext never leaves the browser. It does this with the server's own
`crypto.ntHash`, compiled to WebAssembly (section 8). If the browser can't
run the module, or the module fails a known-answer self-test, the page sends
the password and the server hashes it instead. The page says beforehand which
of the two will happen, and afterward which one did.

In-browser hashing keeps the plaintext private, which matters because people
reuse passwords. It does not make plain HTTP safe for SMB credentials: NTLM
accepts the NT hash itself, so anyone who captures it can use it to connect
over SMB ("pass the hash"). Keeping the web console on localhost or behind
TLS remains the real protection. Two checks can't happen on the server for a
pre-hashed password, because the server never sees the plaintext:
- **Strength rating:** the page rates the password instead, with the same
  estimator (see "Password strength" below).
- **Identical-password detection:** the stored web password can't be
  compared with a hash that arrives alone. The check still works when the web
  password is supplied in the same request, since the server can hash that
  one and compare.

Users with both passwords are the deliberate exception and come with
password hygiene warnings. They exist for small installations where the
administrator also uses the shares. This is never a default: it takes giving
one user both passwords. Whenever a password is set and the user then has both, the
operation succeeds but returns warnings. The CLI prints them to stderr
and the API returns them in a `warnings` list.

- **General warning:** use different SMB and web passwords, and keep the web
  console on localhost or behind TLS.
- **Identical passwords:** a stronger warning when the SMB and web passwords
  are the same. The server can tell even though it stores only hashes. A new
  SMB password is checked against the stored argon2id hash; a new web
  password is hashed with MD4 and compared with the stored NT hash.

### Password strength

Strength is reported, never enforced. The only password refused is an empty
one, because an empty value means "no password". `src/policy/strength.zig` gives a
rough estimate in bits:
- It multiplies the length by the bits per character of the character
  classes used (lowercase, uppercase, digits, ASCII symbols, and anything
  else).
- Repeated and sequential characters (`aa`, `ab`, `21`) count half.
- A short list of very common passwords is rated weak, even with digits or
  symbols appended.

Below 40 bits a password is *weak*, below 64 bits *fair*, and otherwise
*strong*. The estimate can't recognize dictionary words or personal details,
so it informs a decision rather than replacing one. The same Zig code rates
passwords in three places:
- **CLI:** prints the level and bits for each password as it is read.
- **Server:** adds `weak_smb` or `weak_web` to the returned warnings for
  any plaintext password rated weak.
- **Web page:** shows a live meter, using the estimator compiled into the
  WebAssembly module.

### Access pattern

SQLite is opened with `SQLITE_OPEN_FULLMUTEX`, and `Db` additionally serializes
every statement through its own `Io.Mutex`, so prepare/bind/step/read sequences
are atomic with respect to other threads. Statements are prepared per call;
the database is small and these calls are rare (logins, tree connects, admin
edits), so a statement cache is not worth its complexity. Returned strings are
copied into caller-owned memory before the lock is released.

### Ephemeral entries: `store/ephemeral.zig`, `policy/ephemeral.zig`

`serve` can be given shares and logins that exist only in memory. `policy/ephemeral.zig`
parses them (`--share`, `--user`, `--smb-user`, `--web-user`, and users-file
text from stdin for `--users -`) with the validators of `share add` and
`user add` (a relative share path is made absolute against the current directory), merges them per login (each service once; a hash given twice for
one service is `DuplicateLogin`), and hands them to `Db.addEphemeralShare`
and `addEphemeralUser`. `Db` keeps them in an `Ephemeral` layer in front of the
stored part:

- Lookups, `listShares`, and `listUsers` find them first; a stored entry of
  the same name is hidden (and logged once at startup), untouched.
- They change like stored entries, in memory: `putUser`
  (`Ephemeral.changeUser`), `deleteUser` (`removeUser`), `putShare`
  (`changeShare`), and `deleteShare` (`removeShare`) act on the layer when the
  name is ephemeral. Deleting one reveals the stored entry it hid. The web API
  adds the `ephemeral` warning to such responses (`isEphemeralUser`,
  `isEphemeralShare`); the change ends with the process. Only the web console
  can do this, because the CLI is another process with its own store.
  Lists mark them `ephemeral`.
- `bootstrap` creates no `admin` when an ephemeral web login exists.
- `--users -` (global flag, `serve` only; the last `--users` wins) sets
  `Db.users_stdin`: there are no stored users, so the users read from stdin,
  and any the web console creates, are ephemeral (the layer is made when the
  store opens).
- Argument values that may hold secrets (`--user`, `--smb-user`, `--web-user`)
  are copied into the spec and then masked with `X` in place in the process's
  argv (`cli.maskSecret`: everything after the login's colon, so `ps` shows
  `brian:XXXXXXXX`), before any listener starts; `serve` warns that the values were
  readable until then. Passwords are hashed at startup and the copies wiped.

### Plain-text files: `store/textconf.zig`, `store/textusers.zig`

The store has two parts, and each can live in SQLite or in a plain-text
file, for administrators who prefer files they can read, edit, diff, and keep
in version control:

| Flags | Settings and shares | Users |
|---|---|---|
| `--db PATH` | SQLite | SQLite |
| `--config FILE` | FILE | SQLite |
| `--users FILE` | SQLite | FILE |
| `--config FILE --users FILE` | FILE | FILE (no database is opened; `--db` is refused) |

`--db PATH` names the database for the parts that use it, and has no default: without it, `main` refuses every command that needs a store, except `serve` with `--db none` or given ephemeral entries, which keeps the store in memory (SQLite's `:memory:` inside; the flag accepts only `none`). A missing text
file starts empty, and its directory is created. `Db` keeps one interface;
each method goes to the backend of its part, under the same mutex. Keeping
users apart lets password hashes have stricter permissions, ownership, or
backups than the configuration, which might be kept in version control.

- **Configuration file** (`textconf.Conf`): settings as `key = value` lines before the first section,
  then one `[name]` section per share with `path`, `comment`, `read_only`,
  and `guest_ok` (yes or no, default no). Boolean settings are yes or no, or
  true or false; `serve` refuses to start on any other value. `#` and `;`
  start comment lines; an optional `[global]` section also holds settings. zsmbd edits it line by
  line, so comments, order, and layout survive its changes.
- **Users file** (`textusers.Users`): one user per line, `name:nt_hash:web_hash`.
  A blank hash disables sign-in to that service, and its access follows from
  the hashes (shown as smb, web, both, or none). The file keeps no creation time. `zsmbd hash
  LOGIN` reads one password and prints a line with its SMB hash (the
  default), its web hash (`--web`), or both from that same password
  (`--both`, with the identical-passwords warning); without LOGIN, `zsmbd
  hash` or `zsmbd hash --web` prints just the hash. None of these opens a store, without opening any store, so passwords can be
  hashed on another machine and only hashes copied to the server. Both the
  command and the file writer format lines with `textusers.formatLine`. zsmbd
  rewrites it whole, with mode 0600, and warns when it is
  readable by others, since NT hashes are password-equivalent.

Examples: [examples/zsmbd.conf](examples/zsmbd.conf) and
[examples/users](examples/users).

Every lookup checks its file's inode, size, and modification time and
rereads a file that changed, so hand edits take effect without a restart
(settings still follow the reload rule in section 2). Writes go to a
temporary file that is renamed over the old one. A file that doesn't parse
is reported once with its line number; until it is fixed, lookups use its
last good contents and changes to it are refused, so a save can't overwrite
the hand edit. At startup, a broken file is fatal. Two processes saving at
the same moment can lose one change; SQLite has no such window.

Names match case-insensitively (ASCII), as with the SQLite store's
`COLLATE NOCASE`. Share paths and comments may not contain control
characters, so every value fits on one line.

---

## 5. Configuration and validation: `policy/auth.zig`

`auth.zig` is the single place where user input about configuration is
checked, so the CLI and the web API apply identical rules.

- **Settings catalog.** `auth.settings` is the complete list:
  `server_name` (default: host name up to its first dot, at most 15
  characters, upper-cased), `workgroup` (default `WORKGROUP`),
  `signing_required` (default true), and `encrypt` (default false).
  `normalizeSetting` rejects unknown keys and canonicalizes booleans to
  `true`/`false`. Absent rows mean "use the default", so the database holds
  only what an administrator changed.
- **Names.** User names are 1–64 UTF-8 characters without `\ / : @ "` or
  control characters. Share names are 1–80 characters without Windows-illegal
  characters; `IPC$` is reserved.
- **Share paths** must be absolute and name an existing directory at the time
  they are added. They are re-resolved with `realpath` at tree connect, so a
  later rename or removal of the directory fails cleanly
  (`STATUS_BAD_NETWORK_NAME`) instead of serving the wrong place.
- **Passwords** may be any non-empty string; weak ones produce a warning
  (section 4, "Password strength"). Each is set (`auth.grantPasswords`) or
  cleared (`auth.revokePasswords`) on its own.
- **Last login.** Any web login may be deleted or lose its password. When
  none is left (`Admin.stopIfNoLogins`), the console stops after replying,
  ends every session, and closes its listener; `web start` (control socket)
  brings it back and runs `bootstrap`. Changes from the CLI reach the
  console through `Admin.userChanged`, which ends the user's sessions if
  they lost the web password.
- **Bootstrap.** When nobody can sign in to the web console, `serve` gives
  user `admin` (creating it if missing) a random 16-character web password
  from an unambiguous alphabet, and prints the password once to stderr. An
  existing `admin` keeps its SMB password. When nothing can be stored (no
  `--db`, or `--users -`) and no web login is given, the `admin` is an
  ephemeral login with a web password only, printed once and gone at exit
  (none is made if an ephemeral `admin` already exists).
- **Login timing.** An unknown user name still costs one argon2id hash, so
  response time does not reveal which names exist.

---

## 6. Shared server state: `smb/server.zig`

`server.Server` is the one object every SMB thread and the web server can
reach. It compiles against the `Conn` core and is exercised by the
`files.zig` tests.

| Field | Purpose |
|---|---|
| `cfg: Config` | Snapshot of the four settings, refreshed by `loadConfig`. NEGOTIATE reads it under the lock; SESSION_SETUP and TREE_CONNECT use the signing rule the NEGOTIATE response promised (`Negotiated.signing_required`) so a reload never changes rules mid-handshake (`encrypt` is read live). |
| `guid`, `start_ms` | Server GUID and start time, reported in NEGOTIATE responses. |
| `conns` | Registry of live connections, for the monitor, kicking, and change notification. |
| `nodes` | Open-file table keyed by `(st_dev, st_ino)`; see below. |
| `events` | Ring buffer of the last 512 activity events (connect, logon, tree connect, errors), each a fixed-size record so logging never allocates under the lock. |
| `stats` | Atomic counters: connections, bytes in and out, data read and written, requests, logon failures. Updated without the lock. |

### Open-file nodes

SMB semantics that span handles, such as share modes, delete-pending, and
byte-range locks, must be enforced across every open of the same file,
including opens by different clients. POSIX does not provide these semantics,
so zsmbd tracks them itself in a `Node` per file system object that has at
least one open handle.

- **Identity.** Nodes are keyed by device and inode, so two paths that reach
  the same file (case variants, hard links, symlinks inside the share) share
  one node. The node also records its current path, which `renameNodes`
  rewrites, for the node and everything beneath it, after a successful
  rename.
- **Share modes.** At CREATE, the requested access and share access are
  checked against every existing open on the node; a conflict fails with
  `STATUS_SHARING_VIOLATION`.
- **Delete-pending.** Delete-on-close and `FileDispositionInformation` mark
  the node; new opens then fail with `STATUS_DELETE_PENDING`, and the last
  close performs the `unlink` or `rmdir`.
- **Byte-range locks.** Kept in the node as `(offset, length, exclusive,
  owner)`. LOCK checks overlaps against other owners; READ and WRITE check
  against conflicting locks held by other opens. These locks are advisory
  among SMB clients only; local processes on the host do not see them.
- **Lifetime.** A node is created on first open and freed by
  `dropNodeIfUnused` when its last open closes. All node operations happen
  with the server lock held.

### Change notification

When a connection changes a directory's contents (create, delete, rename,
or closing a handle that wrote data or changed the size), it calls
`dirChanged(dir_path, origin)`. That takes
a reference on every registered connection under the lock, releases the
lock, and then calls each connection's `completeNotifies`, which sends the
completion for any CHANGE_NOTIFY pending on that directory. Holding
references rather than the lock while writing to sockets keeps a slow client
from stalling the whole server. Completions report `STATUS_NOTIFY_ENUM_DIR`
("something changed, re-list"), which every client accepts, rather than
per-entry change records. This keeps Finder and Explorer windows current for
changes made through zsmbd; changes made directly on the host are not
detected.

---

## 7. SMB protocol stack

### 7.1 Layers

```
 TCP stream
  └─ framing: 4-byte header (0x00 + 24-bit
  │    big-endian length)             conn.zig
  └─ transform: 0xFD 'SMB' encrypted envelope,
  │    if encryption is on     conn.zig, crypto.zig
  └─ compound: SMB2 messages linked by
  │    NextCommand                    conn.zig
  └─ message: 64-byte SMB2 header + command
     │    body                  conn.zig, files.zig
     ├─ security blobs: SPNEGO ⊃ NTLMSSP
     │                      spnego.zig, ntlm.zig
     └─ IPC$ pipe data: DCE/RPC ⊃ NDR srvsvc
                                        rpc.zig
```

Codec work is shared through `wire.zig`: bounds-checked reads
(`wire.slice` returns `error.Malformed` rather than trapping), a growable
little-endian output buffer with reserve-then-patch offsets, and UTF-8 ⇄
UTF-16LE conversion that replaces invalid sequences with U+FFFD instead of
failing. Everything above the socket works on UTF-8.

### 7.2 Connection handler (`conn.zig`)

The handler owns one TCP connection from accept to close. Its data model is
defined:

- `Session`: authentication state, user identity, the NTLM exchange in
  progress, the signing and encryption keys, the 3.1.1 preauthentication hash,
  and its trees.
- `Tree`: a connected share with its resolved root path, read-only flag, and
  whether it is `IPC$`.
- `Open`: one handle, with its file descriptor, node, share-relative path,
  granted access, share access, create options, directory-enumeration cursor,
  optional RPC pipe, and per-open byte counters for the monitor.
- `Notify`: a pending CHANGE_NOTIFY with everything needed to complete it
  from another thread.

`Conn` itself must provide these members, because `smb/server.zig` already uses
them:

| Member | Used for |
|---|---|
| `id: u64` | Shown in the monitor; the key for kicking a connection. |
| `stream: std.Io.net.Stream` | `Server.kick` calls `stream.shutdown(io, .both)` from the web thread to drop a client. |
| `ref()` / `unref()` | Reference count. `Server.dirChanged` takes a reference on every connection before touching it from another thread; the connection is freed only when the count reaches zero (section 9). |
| `completeNotifies(dir_path, origin)` | Called from any thread when a directory changed (section 6). |

These exist now, in a `Conn` core that also holds the negotiated parameters
(`files.Negotiated`), the open-handle table (`files.Opens`), the
pending-notify queue (`queueNotify`, `cleanupNotifies`), and the write path
(`writeMessage`: sign, seal in a transform header, frame, and write under the
write mutex). Each `Notify` copies its session's signing and encryption keys,
so another thread can complete it without touching the session. The request
loop (`serve`, `handleFrame`, `processChain`) handles framing, compound
chains, credits, ECHO, LOGOFF, TREE_DISCONNECT, CANCEL, and dispatch to
`files.zig`; NEGOTIATE, SESSION_SETUP, and TREE_CONNECT are in `handshake.zig`. Anything
before NEGOTIATE, a second NEGOTIATE, or a NEGOTIATE inside a compound
closes the connection. Requests on signing sessions, and requests flagged
signed, must carry a valid AES-CMAC signature (`signatureValid`, constant-time
compare; sessions without a key never verify), or they get
`STATUS_ACCESS_DENIED`. Replies are signed on signing sessions, whenever the
request was signed, and for the final SESSION_SETUP and LOGOFF (whose key
is copied before the session is freed). A transform frame
(`transformSession`, `unseal`)
must name a session with keys, give `OriginalMessageSize` equal to its
payload, flag AES encryption, and arrive after a cipher was negotiated; it
is decrypted with the session's decryption key, and every unrelated request
inside must name the same session. Any failure closes the connection. A
decrypted chain skips signature checks and is answered sealed with a copy of
the session's encryption key (`Reply.seal`), even if the chain logged off.
Plain requests on encrypting sessions get `STATUS_ACCESS_DENIED`; CANCEL is
ignored. Threading rules for the handler are in section 9.

Request processing per frame:

1. Read the 4-byte length, reject frames over `max_io_size + 64 KiB`
   (4 MiB + 64 KiB), and read the frame.
2. If it starts with the transform header, decrypt it with the session's
   decryption key; failure drops the connection. Reject an unencrypted
   message on a session or tree that requires encryption.
3. If it starts with `0xFF 'SMB'` and is an SMB1 NEGOTIATE that offers
   `SMB 2.???`, answer with an SMB2 NEGOTIATE response for the wildcard
   dialect `0x02FF`, so that clients which open with SMB1 upgrade. Any other
   SMB1 traffic closes the connection.
4. Walk the compound chain. For each message: verify the signature when the
   session signs (or the message is flagged signed); for related operations,
   inherit the session, tree, and file ID from the previous message; dispatch
   on the command; build the response with the same message ID, the granted
   credits, and the status.
5. Sign each response, concatenate the chain, encrypt it as one transform
   when needed, and write it under the connection's write mutex.

Credits (`Credits`): each response grants what the request asked for (at
least one), keeping at most 8192 message IDs outstanding. A request spends
`max(CreditCharge, 1)` consecutive IDs; an ID outside the window or already
spent closes the connection, and a charge below one per 64 KiB of payload
gets `STATUS_INVALID_PARAMETER`. CANCEL spends no ID.

Compound chains: each message must be 8-byte aligned and inside the frame.
A related request inherits the previous one's session, tree, and file ID; it
is invalid first in a chain, and it fails with its predecessor's status.
Responses are padded to 8 bytes, linked, and then each is signed.

Asynchronous operations: only CHANGE_NOTIFY goes asynchronous. It gets an
interim `STATUS_PENDING` response with an async ID; CANCEL, CLOSE of the
directory handle, tree disconnect, logoff, or connection teardown completes it
with `STATUS_CANCELLED` or `STATUS_NOTIFY_CLEANUP`. Byte-range locks that
would block are refused immediately (`STATUS_LOCK_NOT_GRANTED`) rather than
queued; clients retry.

### 7.3 NEGOTIATE

The server picks the highest dialect, 3.1.1 or later, that both sides
support (today only 3.1.1 exists); a NEGOTIATE that offers none gets
`STATUS_NOT_SUPPORTED` and the connection closes. It advertises only
`large_mtu` (encryption is negotiated by context in 3.1.1); it never
advertises leasing, multichannel, persistent handles, or DFS. Read, write,
and transact sizes are 4 MiB. The security
buffer carries the SPNEGO `NegTokenInit` offering only NTLMSSP, with the
conventional `not_defined_in_RFC4178@please_ignore` hint that Windows
expects.

The negotiate contexts are processed as follows:

- **Preauthentication integrity:** exactly one context is required (else
  `STATUS_INVALID_PARAMETER`), and it must offer SHA-512 (else
  `STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP`). The response carries a
  32-byte random salt. The connection's running
  hash covers the NEGOTIATE request and response; each session continues it
  through its SESSION_SETUP exchange. The final value is the KDF context for
  that session's keys, which binds the keys to the exact negotiation and
  defeats downgrade attacks.
- **Encryption:** the server chooses AES-128-GCM if offered, otherwise
  AES-128-CCM. The 256-bit ciphers are not offered. With no cipher in
  common, the response names cipher 0, the session is unencrypted, and it
  is refused when `encrypt` is on.
- **Signing:** AES-CMAC; a signing context that omits it gets
  `STATUS_SMB_NO_SIGNING_ALGORITHM_OVERLAP`.
- **Compression, RDMA, transport, and netname** contexts are ignored. A
  repeated encryption, signing, compression, or RDMA context gets
  `STATUS_INVALID_PARAMETER`.

An SMB1 NEGOTIATE offering `SMB 2.???`, as the first frame only, gets an
SMB2 NEGOTIATE response for the wildcard dialect with one credit; the
client's SMB2 NEGOTIATE then uses message ID 1.

`FSCTL_VALIDATE_NEGOTIATE_INFO` drops the connection, as MS-SMB2
3.3.5.15.12 requires for 3.1.1.

### 7.4 Authentication: SESSION_SETUP

```
client                              server
  │ SESSION_SETUP (SPNEGO init,        │
  │   NTLM NEGOTIATE)                  │
  │───────────────────────────────────►│
  │ MORE_PROCESSING_REQUIRED           │
  │   (NTLM CHALLENGE)                 │
  │◄───────────────────────────────────│
  │ SESSION_SETUP (NTLM AUTHENTICATE   │
  │   + MIC)                           │
  │───────────────────────────────────►│
  │ SUCCESS (accept-completed +        │
  │   mechListMIC)                     │
  │◄───────────────────────────────────│
```

The server side of the exchange: `ntlm.Server.challengeFor` makes a
random 8-byte challenge and the target info AV pairs;
`ntlm.authenticate` takes the NT hash from the store, checks the NTLMv2
response, and derives the session key and the SMB keys.

- `spnego.zig` accepts either SPNEGO-wrapped tokens or raw NTLMSSP, records
  the client's DER `mechTypes` list (for the mechListMIC), and builds
  `NegTokenResp` messages.
- `ntlm.zig` builds the CHALLENGE with NetBIOS and DNS names and a timestamp,
  then verifies AUTHENTICATE. Only NTLMv2 responses are accepted; an NT
  response shorter than an NTLMv2 blob fails with `STATUS_LOGON_FAILURE`.
  When the blob's `MsvAvFlags` says the client sent a MIC, the AUTHENTICATE
  MIC (HMAC-MD5 of the exported session key over the NEGOTIATE, CHALLENGE,
  and AUTHENTICATE messages) must verify. A random session key (key exchange)
  is used only with sign or seal and must be 16 bytes; otherwise the
  logon fails.
  The proof is computed against the domain as sent, upper-cased, and empty,
  since clients differ. Comparison is constant-time. With key exchange, the
  exported session key is RC4-decrypted with the base key.
- An empty user with empty responses is an anonymous (null) session. It may
  connect only to `IPC$` and to shares marked `guest_ok`, and it cannot sign,
  so it is refused when signing is required unless it touches only `IPC$`.
- Admins have no SMB password and fail like unknown users.
- Every failure increments `logon_failures` and is logged with the
  connection and user name, but the response never says whether the user or
  the password was wrong. A failed exchange removes its session.
- `handshake.sessionSetup` drives the exchange. A request with session ID 0
  starts a session (at most 64 per connection, finished or not) whose preauth
  hash starts from the connection's; each request, and each
  `MORE_PROCESSING_REQUIRED` response, extends it, and keys are derived after
  the final request. SESSION_SETUP must be alone in its frame (else
  `STATUS_INVALID_PARAMETER`). An empty token gets the server's
  `NegTokenInit`; an optimistic token for another mechanism gets a
  `NegTokenResp` naming NTLMSSP. A client mechListMIC must verify, and the
  reply then carries the server's. The final response is signed for
  non-anonymous sessions.
- Not supported: binding (`STATUS_REQUEST_NOT_ACCEPTED`), reauthentication
  of a valid session (`STATUS_REQUEST_NOT_ACCEPTED`), and
  `PreviousSessionId` (ignored).

Key derivation (MS-SMB2 3.1.4.2), all with `crypto.kdf` (HMAC-SHA256 counter
mode, 128-bit output):

| Key | Label | Context |
|---|---|---|
| Signing | `SMBSigningKey` | preauth hash |
| Server → client encryption | `SMBS2CCipherKey` | preauth hash |
| Client → server decryption | `SMBC2SCipherKey` | preauth hash |

Signing uses AES-CMAC (`crypto.cmacSig`). Encryption uses AES-CCM (`crypto.ccmEncrypt`,
with SMB's 11-byte nonce, implemented in Zig because `std` only offers other
nonce sizes) or `std`'s AES-128-GCM. Each encrypted message uses a fresh
random nonce; the AEAD's associated data is the transform header from the
nonce onward.

Policy from settings: `signing_required` sets the NEGOTIATE security mode and
makes the server reject unsigned requests on authenticated sessions; a client
whose SESSION_SETUP security mode requires signing gets a signing session too.
`encrypt` sets `SMB2_SESSION_FLAG_ENCRYPT_DATA` on every session, so all
traffic after SESSION_SETUP must be encrypted.

### 7.5 TREE_CONNECT

The path `\\server\share` is split; the server part is not checked, and the
share part must be 1 to 80 characters without `\ / : * ? " < > |` or control
characters (else `STATUS_BAD_NETWORK_NAME`). The share is looked up in the
store (case-insensitively) at connect time, so share edits take effect for
new connections without a restart. `IPC$` is synthesized, never stored. The
share's path is resolved with `realpath` and must be a directory (else
`STATUS_BAD_NETWORK_NAME`, logged); that canonical root is what all later
path checks compare against. An anonymous session reaches `IPC$`, and other
shares only when they are `guest_ok` and signing is not required
(`STATUS_ACCESS_DENIED`). A session holds at most 256 trees. The tree's
maximal access is all file rights, or read and execute only for read-only
shares and `IPC$`; CREATE grants never exceed it. Shares get `no_caching`
flags (consistent with having no oplocks) and `encrypt_data` when
encryption is required.

### 7.6 File operations: `files.zig`

`files.zig` implements CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL,
QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, and SET_INFO on top of `vfs.zig`
and the node table.

The contract with the handler:

- The handler checks the session, tree, and signature, then calls
  `dispatch(ctx, cmd, msg, out)`. `ctx` holds the connection, session, tree,
  and the file ID inherited from the previous related compound request. `msg`
  is the whole message (offsets in requests count from the header). `out`
  already holds the 64-byte response header.
- `dispatch` appends the response body, or the standard error body, and
  returns a `Reply`: the status, the file ID that CREATE opened (for related
  requests), a `Notify` to queue when the status is `STATUS_PENDING`, and
  whether to drop the connection (any VALIDATE_NEGOTIATE_INFO).
- A file ID of all ones means "the previous related request's file". A file
  ID that is unknown, or belongs to another session or tree, gets
  `STATUS_FILE_CLOSED`.
- `closeOpen` and `closeAll` (by session or tree) close handles for
  TREE_DISCONNECT, LOGOFF, and teardown. Closing releases the node entry and
  locks, performs a pending delete on the last close, completes the handle's
  CHANGE_NOTIFYs with `STATUS_NOTIFY_CLEANUP`, and reports a change to the
  parent directory if the handle wrote data.

Commands:

- **CREATE** normalizes the name, resolves it inside the share, applies the
  disposition (supersede, open, create, open-if, overwrite, overwrite-if),
  checks directory versus non-directory options, computes granted access from
  the requested mask, `MAXIMUM_ALLOWED`, the tree maximum, and the read-only
  attribute, then opens the file with `O_NOFOLLOW` semantics provided by the
  resolver. Share modes and delete-pending are checked against the node in
  the same locked step that registers the open, so two racing opens cannot
  both pass. Overwrite and supersede truncate only after that check.
  Attribute-only opens of a file the server can't read keep no descriptor and
  work from the node's path. On `IPC$`, CREATE opens the `srvsvc` pipe. The response carries times, sizes, and attributes
  from `vfs.Info`. Create contexts the server does not implement (leases,
  durable handles, and so on) are ignored, which clients treat as
  "not granted". The `MxAc` (maximal access) and `QFid` (on-disk ID) contexts
  are answered because Windows and macOS ask for them on nearly every open.
- **READ and WRITE** use `pread` and `pwrite` at the request's offset up to
  4 MiB, after a byte-range lock check. Writes are not cached in the server.
  A write to offset all-ones appends. Exclusive locks of other handles block
  reads and writes; shared locks block writes, including the owner's.
- **LOCK** applies a request's locks all or nothing, and refuses conflicts
  immediately with `STATUS_LOCK_NOT_GRANTED`. Unlocks must match an existing
  lock of the same handle exactly (`STATUS_RANGE_NOT_LOCKED` otherwise).
- **QUERY_DIRECTORY** snapshots the directory's names on the first call (or
  on `restart_scans`), filters them with `vfs.wildcardMatch` (which
  understands the DOS wildcards `<`, `>`, and `"`), stats each entry, and
  fills as many entries as fit in the output buffer. `.` and `..` are
  synthesized (`..` of the share root reports the root itself). A symlink
  entry is resolved like a path and is left out when it leaves the share. The
  information classes clients actually use are supported: directory, full,
  both, ID-both, ID-full, and names.
- **CHANGE_NOTIFY** on a directory handle returns `STATUS_PENDING` with a
  `Notify` for the handler to queue (section 6).
- **QUERY_INFO and SET_INFO** cover the file classes in common use (basic,
  standard, internal, EA, access, position, mode, alignment, all, network
  open, attribute tag, stream, and normalized name), the file system classes
  (volume, size, full size, device, attribute, and sector size, from
  `vfs.volInfo`), and a synthesized security descriptor that grants Everyone
  what the tree allows. SET_INFO handles times, size (end of file and
  allocation), disposition, and rename (including replace-if-exists), and
  accepts attribute changes for the read-only bit, which maps to the owner
  write permission. Security descriptor changes are accepted and ignored.
  Renames refuse a target that is a directory or open, and a directory with
  anything open beneath it; a case-only rename is allowed. Deleting a
  non-empty directory fails with `STATUS_DIRECTORY_NOT_EMPTY`. The share root
  can be neither renamed nor deleted.
- **IOCTL** answers validate-negotiate-info, pipe transceive (for `IPC$`),
  server-side copy (`FSCTL_SRV_COPYCHUNK` and `FSCTL_SRV_REQUEST_RESUME_KEY`,
  so copies within the server do not cross the network; at most 256 chunks of
  1 MiB and 16 MiB per request), and set-sparse (accepted as a no-op). Everything else, including network interface queries
  and DFS referrals, returns `STATUS_NOT_SUPPORTED` or
  `STATUS_FS_DRIVER_REQUIRED` as clients expect.

### 7.7 File system confinement: `vfs.zig`

The most security-sensitive code is the mapping from client paths to host
paths. It runs in two steps.

**`normalize`** turns the client's backslash-separated UTF-8 path into a
`/`-separated relative path. It strips a trailing `::$DATA`, drops empty and
`.` components, and rejects `..`, `:` (which also rejects every named
stream), control characters, and the other Windows-illegal characters. A
client therefore can never express a path that climbs out of the share.

**`resolve`** walks the normalized path one component at a time from the
share's canonical root:

- Each component is `lstat`ed. If it is missing, a case-insensitive match is
  looked for in the parent directory, which gives Windows and macOS clients
  the case-insensitive behavior they expect on case-sensitive Linux file
  systems.
- A symbolic link is followed only if its `realpath` stays under the share
  root; otherwise the lookup fails with access denied. Dangling or looping
  links are treated as absent.
- A missing intermediate component is `STATUS_OBJECT_PATH_NOT_FOUND`; a
  missing final component is returned as "does not exist yet", so CREATE can
  create it.

The rest of `vfs.zig` is a thin errno-to-error layer over POSIX calls (open,
`pread`, `pwrite`, `fstat`/`statx`, `mkdir`, `unlink`, `rename`, `futimens`,
`fchmod`, `fsync`, and `statvfs`/`statfs`), plus `status`, which maps each
error to the NTSTATUS clients expect. File times are converted between Unix
and NT (100-nanosecond intervals since 1601) in `proto.zig`. Attributes are
derived: directory, read-only (no owner write bit), hidden (name starts with
a dot), and archive or normal for regular files. File IDs are inode numbers.

There is a known residual race: a local process on the host could swap a
directory for a symlink between resolution and open. zsmbd assumes the
directories it serves are not concurrently manipulated by hostile local
users.

### 7.8 Share browsing: `rpc.zig`

Clients list shares by opening the named pipe `srvsvc` on `IPC$` and speaking
DCE/RPC. `rpc.Pipe` is a byte-stream state machine: WRITE (or the transceive
IOCTL) feeds client bytes in; complete PDUs are processed; READ drains queued
responses. It implements BIND and ALTER_CONTEXT (NDR transfer syntax, with
bind-time feature negotiation acknowledged), request fragment reassembly, and
two operations: `NetrShareEnum` (levels 0 and 1) and `NetrShareGetInfo`.
Anything else returns an RPC fault. The share list is passed in by the caller
for each call, so the pipe never touches the database itself. The other pipes
clients probe (`lsarpc`, `samr`, `wkssvc`) are refused at CREATE with
`STATUS_OBJECT_NAME_NOT_FOUND`, which they handle.

---

## 8. Admin web server: `web/server.zig`

### Serving

`Admin.serve` listens (on the `--web` address; a bare port means
`127.0.0.1`), spawns a detached thread per
HTTP connection, and uses `std.http.Server` with keep-alive. Each request gets
an arena allocator freed when the request ends. Request bodies are capped at
64 KiB, and `Expect: 100-continue` is refused. The UI is a single HTML file
embedded in the binary with `@embedFile`, so the web server needs no files on
disk. It is served with a strict Content Security Policy: inline script and
style only, same-origin `fetch`, no framing, and `'wasm-unsafe-eval'` so the
page can instantiate the hashing module.

`GET /nthash.wasm` serves `src/nthash_wasm.zig`. That is `crypto.ntHash`
built by `build.zig` for `wasm32-freestanding` (ReleaseSmall, about 4 KB) and
embedded through a generated `nthash_wasm` module, so the browser computes
NT hashes, and rates strength, with exactly the code the server uses. Its
interface is minimal:
- JavaScript writes the UTF-8 password at `input_ptr()` (at most 1 KiB).
- It calls `nt_hash(len)`, which hashes the input and wipes it.
- It reads the 16-byte result at `output_ptr()`.
- For the strength meter, it calls `strength(len)` instead. That returns the
  estimated bits in the low 16 bits and the level (0 weak, 1 fair, 2 strong)
  above them, and also wipes the input.

### Security model

- **Login** (`POST /api/login`) accepts only users with a web password and
  verifies their web password, never an SMB password (section 4). Success creates a
  256-bit random session token held in memory and set as `zsmbd_session`
  with `HttpOnly; SameSite=Strict`. Sessions expire after 12 hours of
  inactivity (sliding expiry) and are dropped when their user is deleted,
  given a new web password, or has it cleared. Restarting the server logs everyone
  out.
- **CSRF**: every POST, PUT, and DELETE must carry `X-Zsmbd: 1`. Browsers
  will not add a custom header to a cross-origin request without a CORS
  preflight, and the server never answers preflights favorably, so a hostile
  page cannot forge state changes even if the cookie were sent.
- **Transport**: plain HTTP, bound to localhost by default. Exposing it
  elsewhere is a deliberate choice (`--web 0.0.0.0:8445`) and should sit
  behind a TLS proxy or SSH tunnel.

### JSON API

| Method and path | Purpose |
|---|---|
| `POST /api/login`, `POST /api/logout`, `GET /api/me` | Session management. |
| `GET /api/activity` | Live connections, recent events, and counters (from `Live.writeActivity`). |
| `POST /api/kick` | Drop a client connection by ID. |
| `GET`, `PUT`, `DELETE /api/shares` | List, create or replace, and delete shares. |
| `GET`, `PUT`, `DELETE /api/users` | List users (`name`, `has_smb`, `has_web`, a derived `access` label (`smb`, `web`, `both`, or `none`), and `created`); create a user (with no passwords unless given) or set its SMB password (`smb_password`, or `nt_hash` as 32 hex digits, not both) or `web_password`, or clear them (`no_smb_password`, `no_web_password`); delete a user. Empty or absent passwords stay unchanged, a password can't be both set and cleared, and unknown fields are refused. The response's `warnings` list carries both-passwords and weak-password warnings. |
| `GET`, `PUT /api/settings` | Read all settings with defaults and help text; update any subset. |

Validation errors come back as HTTP 400 with the same human-readable
messages the CLI prints, because both use `auth.describe`.

### Coupling to the SMB side: `web.Live`

The web server does not import `smb/server.zig`. Instead it holds a `Live` value:
a context pointer and five function pointers.

- `writeActivity` writes the activity view (below).
- `kick` drops a connection by ID.
- `reload` re-reads settings after a save.
- `shareChanged` and `userChanged` drop the connections whose access a
  share or user change tightened.

The defaults report `"smb_running": false`, which lets the admin server run,
and be tested, without the SMB side. `serve` (`cli.zig`, the one place that
sees both sides) points `Live` at `Server.writeActivity`, `Server.kick`
(which shuts the socket down so the connection's own thread tears it
down), and `Server.loadConfig` (a bad value is logged and the old settings
stay).

The activity view is
`{"smb_running","server":{name,port,start_ms,now_ms},"connections":[`
`{id,peer,connected_ms,opens,sessions:[{id,user,anonymous,since_ms,`
`trees:[{id,share,read_only,since_ms}]}]}],"events":[{time_ms,conn_id,`
`kind,msg}],"stats":{…}}`, events oldest first (up to 512). A connection's
sessions and trees belong to its own thread, so the view reads copies kept
under the server lock: `Server.watch` has one row per valid session or tree,
added in `handshake.zig` (logon, TREE_CONNECT) and removed by LOGOFF,
TREE_DISCONNECT, and `removeConn`. `opens` counts file and directory handles
from the node table, and `peer` is the client's address, set when the
connection is accepted.

Share changes and connected clients: each `Tree` copies the share's flags at
TREE_CONNECT, so a change reaches only later connections, except that
tightening revokes access clients already hold. After a change, the web
handlers call `shareChanged` and `userChanged`, and the control socket
(below) calls the same functions for CLI changes: `Server.reconcileShare`
compares the share in the store with what live connections hold (the
activity rows keep each tree's share, configured path, and read-only flag;
`staleOnShare` picks the connections) and shuts down the stale ones, so each
client reconnects under the new rules. Stale means: the share is now
read-only and the tree was writable, or its path changed, or it was deleted
(every connection using it), or guests are now off (only connections whose
session on that share is anonymous). Relaxing changes drop no one and apply
to new connections. The response of `PUT` and `DELETE /api/shares` reports
`disconnected`, and the Shares panel asks first, counting connections from
`/api/activity`. `reconcileUser` drops a user's connections when they lost
their SMB password or were deleted.

### Control socket: `control/control.zig`

The CLI is another process, so it can't touch a running server's
connections. After it writes the store it tells `serve` over a Unix domain
socket, and `serve` re-reads the store and drops the connections whose
access that tightened (the rule of the previous section).

- **Where.** `PATH.sock` beside the first persistent store: the `--db` path
  if SQLite is used, else `--config`, else `--users`. An in-memory store has
  none. Both `serve` and the CLI derive it from the same flags, so the CLI
  needs none. `--socket PATH` overrides it, and `--socket none` turns it
  off. A path over 100 bytes (the OS limit is 104 on macOS) disables it:
  `serve` warns, and the CLI is silent.
- **Who.** `serve` binds with umask 0177 (mode 0600) and accepts only the
  same user or root, checked on every connection (`SO_PEERCRED` on Linux,
  `getpeereid` elsewhere). A leftover socket is replaced only when nothing
  answers; a live one stops a second server (a warning, not a failure), and
  a regular file at the path is never touched. The file is removed on a
  normal exit.
- **What.** One request line per connection (at most 256 bytes, 2 s
  timeouts), one reply line:

  ```
  share NAME      -> ok N | err TEXT
  user NAME       -> ok N | err TEXT
  settings        -> ok 0 | err TEXT
  web start [[ADDR:]PORT] -> msg TEXT | err TEXT
  web stop        -> msg TEXT
  ```

  `N` is the number of connections dropped. The request names what changed
  and nothing else: `Server.reconcileShare` and `reconcileUser` compare the
  new store contents with what live connections hold (`Server.watch`
  rows keep each tree's share, configured path, and read-only flag), so a
  request can't make the server do more than re-check. `user` drops a
  user's connections only if they lost their SMB password or were deleted.
  `web` starts or stops the console (`Admin.start`/`stop`; a new listener
  thread per start, `generation` ending old keep-alive connections); an
  omitted address reuses `Admin.last_addr`. New verbs (a log level,
  shutdown) would be added to `parse` and `Hooks`.
- **CLI.** After `share`, `user`, and `set` commands, the CLI sends the
  matching line and prints only when something was dropped (or a warning if
  the socket exists but refuses it). With no server it prints nothing.
- **Wiring.** `cli.zig` passes `control.Hooks` to `Listener.start`, with the
  same server functions the web console's `web.Live` hooks use.

### Browser UI (`index.html`, partly written)

A single page with no build step and no external assets. So far it has:
- **Sign-in** with the web password, and sign-out.
- **Set SMB password**, which defaults to the signed-in user. It loads
  `/nthash.wasm` and runs a self-test (the NT hash of `password` must be
  `8846f7eaee8fb117ad06bdd830b7586c`). A live strength meter rates the
  password as it is typed, and says so when the browser can't run the
  estimator. On submit it checks only that the two entries match, then sends
  `nt_hash`, or `password` when browser hashing is unavailable. It shows any
  warnings the server returns.
- **Shares** panel: each share with its path and comment, an `ephemeral`
  badge, and Read-only and Allow guests switches (real checkboxes, so
  keyboard and screen readers work). A switch sends the whole share in a
  `PUT /api/shares` with that one flag flipped, disables the row's switches
  while it saves, then redraws from `GET /api/shares`; a failure puts the
  switch back and shows the server's message, and the server's warnings (such
  as the ephemeral one) appear under the list. The panel says that changes
  apply to new connections, since each `Tree` copies the share's flags at
  TREE_CONNECT (section 8, "Coupling to the SMB side").

Still to come: tabs for Activity (polled every few seconds; connections with user, client
address, dialect, signing and encryption state, trees, and open files, plus a
kick button, the event log, and counters), Users, and Settings, and adding,
renaming, and deleting shares.
Every mutating `fetch` sends `X-Zsmbd: 1`.

---

## 9. Concurrency model

| Shared thing | Protection | Notes |
|---|---|---|
| SQLite | `Db.mutex` (plus SQLite's own full mutex) | Short critical sections; results copied out before unlock. |
| `server.Server` registries, nodes, config, and events | `Server.mutex` | Structural changes to a connection's sessions, trees, and opens also take it, so the monitor can read them safely. |
| Counters | atomics | No lock. |
| A connection's socket writes | per-connection write mutex | Writers are the connection's own thread and threads completing its CHANGE_NOTIFYs. |
| A connection's pending notifies | per-connection mutex | Read and removed by other threads. |
| Web sessions | `Admin.mutex` | |

Rules that keep this deadlock-free:

1. Lock order is `Server.mutex` → per-connection mutexes. `Db.mutex` is a
   leaf: no other lock is acquired while it is held, and the server lock is
   never held across a database call.
2. No socket I/O happens while `Server.mutex` is held. `dirChanged` and the
   monitor copy what they need, take references, and unlock first.
3. Only a connection's own thread mutates its sessions, trees, and opens, so
   that thread can read them without locking.

Connection lifetime is reference-counted. The connection thread owns the
initial reference. On exit it marks the connection closed (which turns
`completeNotifies` into a no-op), closes its opens (releasing nodes and
locks, and performing delete-pending unlinks), unregisters with `removeConn`,
and drops its reference. The last `unref`, possibly on another thread that
was completing a notify, closes the socket and frees the memory.

Kicking a client from the web UI calls `shutdown` on its socket. The
connection thread's blocked read then fails and it runs the normal teardown,
so cleanup is always done by the thread that owns the state.

---

## 10. Error handling

- Protocol parsing never trusts lengths: `wire.slice` and the TLV parser
  return `error.Malformed`, which becomes `STATUS_INVALID_PARAMETER` for one
  request. Framing errors, or a bad signature or decryption failure on an
  authenticated session, close the connection.
- File system errors go through `vfs.mapErrno` and `vfs.status` to a fixed,
  tested set of NTSTATUS codes.
- Out-of-memory in a request becomes `STATUS_INSUFFICIENT_RESOURCES` for that
  request rather than a crash.
- Every connection thread catches all errors at its top level, logs one
  event, and tears down; one misbehaving client cannot take down the process.
- Admin API handlers return JSON errors with HTTP status codes; unexpected
  errors close only that HTTP connection.

---

## 11. Platform notes

| Concern | Linux | macOS |
|---|---|---|
| File metadata | `statx` for birth time when available | `stat` with `st_birthtimespec` |
| Volume sizes | `statvfs` | `statfs` (Darwin struct layout declared in `vfs.zig`) |
| Case sensitivity | usually case-sensitive; resolver falls back to a case-insensitive scan | APFS is usually case-insensitive already; the fallback rarely runs |
| Port 445 | needs root or `CAP_NET_BIND_SERVICE` | needs root, and the built-in `smbd` must be off; macOS share listing (`smbutil view`) works only on 445 |
| SQLite | distribution package (Fedora `sqlite-devel`, Alpine `sqlite-dev`) | system `libsqlite3` from the SDK; `-Dsqlite-prefix` for Homebrew |

Supported build targets are macOS and Linux on x86_64 and aarch64.

---

## 12. Build and test

- `zig build` produces `zig-out/bin/zsmbd`; `zig build run -- …` runs it.
  The version comes from `build.zig.zon` alone and reaches the code as
  `@import("build_options").version` (`zsmbd --version`, the startup log).
  The build first compiles `src/nthash_wasm.zig` to WebAssembly and embeds
  it in the binary.
- `zig build test` runs the unit tests: MD4 and AES-CCM test vectors (CCM is
  checked against `std`'s 13-byte-nonce implementation), the MS-NLMP 4.2.4
  NTLMv2 vectors, SPNEGO round trips, UTF-16 round trips, path normalization
  and wildcard matching, srvsvc bind plus `NetrShareEnum`/`NetrShareGetInfo`
  encodings, input validation, cookie and query parsing, user access and
  password warnings against an in-memory database, strength estimates, and
  the WebAssembly exports (run natively against the server's own results),
  the plain-text store (edits that keep comments, the users file and its
  mode, outside edits, and broken files), and the file commands against a
  temporary directory (create dispositions,
  reads and writes, listings, share modes, delete-on-close, rename, locks,
  information classes, read-only shares, path escapes, and server-side copy),
  the request loop (frame limits, compound linking and padding, the
  credit window and charges, related-request rules, LOGOFF and
  TREE_DISCONNECT, and the fail-closed signature check), and the handshake
  (NEGOTIATE contexts, refusals, and the preauth hash; the SMB1 upgrade;
  TREE_CONNECT for shares, `IPC$`, read-only shares, and anonymous
  sessions).
- Fuzz targets (`src/shared/fuzz.zig`) cover every parser of untrusted
  input listed in [SECURITY.md](SECURITY.md). `zig build test` runs each on
  its seeds plus 400 deterministic mutations per seed; `zig build test
  --fuzz=N` adds Zig's coverage-guided fuzzer.
- `zig build check -Dtarget=x86_64-linux-gnu` (or `aarch64-linux-gnu`)
  type-checks everything reachable from `main` and from the tests for Linux
  without linking, so Linux-only code paths are verified from a macOS
  development machine.
- CI (`.github/workflows/ci.yml`) builds and tests on Fedora and Alpine
  (x86_64 and aarch64) and macOS, runs the type checks, and fuzzes for 500K
  runs per push and 20M weekly, keeping crashing inputs as artifacts.
- Interoperability testing, once the handler exists, uses the real clients:
  Windows 11 Explorer and `net use`; macOS Finder and `mount_smbfs`; Linux
  `mount -t cifs` (with `vers=3.1.1`) and `smbclient`.

---

## 13. Status and next steps

| Component | State |
|---|---|
| `proto`, `wire`, `crypto`, `spnego`, `ntlm`, `vfs`, `rpc` | Written and unit-tested. |
| `db`, `auth`, CLI | Written and unit-tested. |
| Admin JSON API | Written; exercised with curl. |
| `nthash_wasm` | Written; unit-tested natively, and checked in a browser against server-side hashing. |
| `smb/server.zig` | Written; exercised through the `files.zig` tests. `serve` runs its accept loop, checked with a raw NEGOTIATE over TCP. |
| `smb/conn.zig` | `Conn` core and the request loop (framing, chains, credits, ECHO, LOGOFF, TREE_DISCONNECT, CANCEL, dispatch), signature verification, and decryption, unit-tested and fuzzed; not yet tried with real clients. |
| `smb/handshake.zig` | NEGOTIATE, the SMB1 upgrade, SESSION_SETUP, and TREE_CONNECT, unit-tested (SESSION_SETUP against an in-test NTLMv2 client) and fuzzed; not yet tried with real clients. |
| `smb/files.zig` | Written and unit-tested; macOS 15 `mount_smbfs` mounts a read-only share, lists it, and reads files byte-identical. |
| macOS 15 interop | Keys and signatures verified independently from a capture. `smbutil view` lists shares through `srvsvc` on port 445; on any other port it fails ("Broken pipe", RPC error `0x16c9a042`) because macOS's RPC layer dials 445 for the pipe. Windows and Linux clients are untested. |
| `web.Live` over `server.Server` | Written: activity, kick, and settings reload, with unit tests and a live run (a raw TCP client listed, kicked, and gone; a settings save reloaded), and a macOS `mount_smbfs` session and tree appeared and vanished on unmount. |
| `web/index.html` | Sign-in and SMB password form; the rest is still to come. |
| CI | Green on Fedora and Alpine (x86_64 and aarch64) and macOS: build, unit tests, Linux type checks, and a coverage-guided fuzz run. No real Linux or Windows client is involved. |

Planned order of work:

1. Run interoperability tests against Windows and Linux clients.
2. Finish the browser UI (activity table, kick, shares, users,
   settings); share changes for connected clients.
