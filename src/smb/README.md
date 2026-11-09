# libsmbd

libsmbd is zsmbd's SMB 3.1.1 file server packaged for other Zig programs to
embed. It handles connections, sessions, signing, encryption, and files. The
program that embeds it, the *host*, supplies the shares and users and
receives the log, so libsmbd stores nothing itself. zsmbd is a host too: its
store adapter is in [cli.zig](../cli.zig).

The library is `src/smbd.zig` (the `smbd` module) plus this directory and
`src/shared/`. It links only libc, not SQLite. The design is in
[ARCHITECTURE.md](../../ARCHITECTURE.md) section 6, "Embedding".

## Using it

In the host's `build.zig.zon`, depend on zsmbd (its package name is
`smbd_agentic`). Then, in `build.zig`:

```zig
const dep = b.dependency("smbd_agentic", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("smbd", dep.module("smbd"));
```

A host implements `smbd.Host`. Its three functions run on connection
tasks, so they must be thread-safe:

| Function | Returns |
|---|---|
| `listShares(ctx, gpa)` | every share, allocated with `gpa` (libsmbd frees it with `smbd.freeShares`) |
| `ntHash(ctx, name)` | the user's NT hash (`smbd.ntHash` of the password), or null |
| `log(ctx, level, conn_id, kind, msg)` | nothing; `msg` lasts only for the call |

Shares and users are matched case-insensitively. A share's `path` must be an
absolute directory. libsmbd resolves it with `realpath` on every
TREE_CONNECT, so changes apply to the next connection without telling the
server.

```zig
var srv: smbd.Server = try .init(gpa, io, host, .{
    .server_name = "perihelion",
});
defer srv.deinit();
var listener = try addr.listen(io, .{
    .reuse_address = true,
});
defer listener.deinit(io);
try srv.start(&listener);
// ... until the host wants to quit:
srv.stop();
```

`io` must support concurrency (`std.Io.Threaded` does). Each client is
served in a task of the server's `Io.Group`.

## API

- `Server.init(gpa, io, host, config)` creates a server that serves nothing
  yet. The server must not move after it starts.
- `start(&listener)` accepts clients until `stop`. `adopt(stream)` serves
  one client the host accepted itself; on error the host still owns the
  stream.
- `stop()` refuses new clients, drops every client, and returns once all
  their tasks have finished. Call it once, and never from a `Host` function.
  `wait()` blocks until `stop` has finished. `deinit()` frees the server.
- `setConfig(config)` replaces the settings: `server_name`, `workgroup`,
  `signing_required` (default true), and `encrypt` (default false). A
  session keeps the signing rule it negotiated.
- `reconcileShare(name, kick)` and `reconcileUser(name)`: call these after
  changing a share or user, to drop the clients whose access tightened.
  `kick` (`.writable` or `.guests`) also drops the clients still on stricter
  rules after a relaxing change. Both return how many were dropped.
- `kick(conn_id)` drops one client.
- `writeActivity(gpa, writer)` writes the JSON activity view: connections,
  sessions, trees, the last 512 events, and the counters. `stats` holds the
  same counters as atomics.

## From C

`zig build lib` installs `zig-out/lib/libsmbd.a`, the shared library
(`libsmbd.so` or `libsmbd.dylib`), and `zig-out/include/smbd.h`, which
documents every function. Link with `-lsmbd`; it needs only libc.

```c
static int shares(void *ctx, smbd_shares *out) {
    smbd_share s = {.name = "docs", .path = ctx};
    return smbd_shares_add(out, &s);
}

static int hash(void *ctx, const char *user,
                unsigned char nt[16]) {
    if (strcmp(user, "hal") != 0) return 0;
    return smbd_nt_hash("daisy", nt) == SMBD_OK
               ? 1 : -1;
}

smbd_host host = {.ctx = "/srv/docs",
                  .list_shares = shares,
                  .nt_hash = hash};
smbd_config cfg;
smbd_config_init(&cfg);
cfg.server_name = "perihelion";
smbd_server *srv = smbd_new(&host, &cfg);
smbd_listen(srv, NULL, 4450);
/* ... */
smbd_free(srv); /* stops, then frees */
```

Callbacks run on libsmbd's threads and must be thread-safe. While any
server exists, libsmbd installs do-nothing SIGIO and SIGPIPE handlers. The
C interface is unstable before 1.0. [test/c/smoke.c](../../test/c/smoke.c)
exercises all of it.

## Limits

Only POSIX directories on Linux and macOS can be served; there is no
pluggable file system. Not supported: Kerberos, SMB before 3.1.1, oplocks
and leases, multichannel, DFS, named streams, durable handles, and Windows
ACLs (see [AGENTS.md](../../AGENTS.md)).
