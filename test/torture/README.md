# zsmbt: protocol tests

`zsmbt` speaks SMB 3.1.1 directly over TCP and checks a server's replies
test by test. It replaces `smbtorture`, which needs a Samba build, assumes
Samba's behavior, and can't assert zsmbd's own choices. Unlike
[test/interop](../interop/README.md), which drives real clients, `zsmbt`
needs no root, kernel module, or client packages, and runs on macOS.

```bash
zig build torture                       # installs zig-out/bin/zsmbt
zig build
zig-out/bin/zsmbt --server zig-out/bin/zsmbd
zig-out/bin/zsmbt --target 10.0.0.5:445 --profile samba --user u%pw
```

* `--server PATH` starts that `zsmbd` on a random loopback port with a
  share and a user of its own (in `var/torture/`, removed afterward unless
  `--keep`), and judges it as profile `zsmbd`. Its log is printed after a
  failure.
* `--target HOST:PORT` tests a running server. `--profile` and `--user` are
  required, so a result always says what it was judged against; `--share`
  names a read-write disk share (default `data`).
* Profiles: `zsmbd`, `samba`, `windows`. A test of a choice that is zsmbd's
  own (no older dialect, AES-CMAC only, signing required) skips under the
  others.
* `-f PATTERN` selects tests (`*` and `?`; a bare suite name matches its
  tests), `--list` lists them, `--timeout` bounds each read, `-v` shows the
  frames of passing tests.

Output is `PASS`, `FAIL`, or `SKIP` per test, then a summary. A failure
shows the reason, the specification section, and the frames each
connection saw. The exit status is 1 on any failure and 2 for a usage
error.

## Suites

| Suite | Covers |
|---|---|
| `negotiate` | Dialect choice, 3.1.1 required, the contexts (missing, repeated, no overlap), a repeated NEGOTIATE, the SMB1 upgrade |
| `session` | NTLMv2 logon, wrong password and unknown user, LOGOFF, no session, another connection's session ID, unsigned and mis-signed requests |
| `tcon` | A share, `IPC$`, case folding, unknown and missing share names, distinct tree IDs, TREE_DISCONNECT |

## Layout

* [main.zig](main.zig): arguments, the server fixture, the runner.
* [harness.zig](harness.zig): `Env`, `Test`, and `T`, which opens clients
  and records failures.
* [client.zig](client.zig): framing, NEGOTIATE, NTLMv2 through SPNEGO,
  signing, and the session and tree commands. Its encoders are written
  apart from the server's; it imports only `smb/proto.zig` (constants) and
  `shared/crypto.zig` (primitives), never server code.
* [suites/](suites): one file per area, each listing its `tests`.

A new test is a function `fn (*T) !void` in a suite, listed with its name
and the specification section it checks. Use `t.session()` for a logged-on
connection, `t.expectStatus`, and `t.only(.zsmbd)` for a zsmbd choice.
Each test opens its own connections and shares no state, and a new one
must fail on the code it guards.

Not yet covered: forged fields (raw mode), file operations, compounds and
credits, encryption, and hostile input.
