//! The control socket: how another process, usually the CLI, tells a running
//! `serve` that something changed in the store, so it can act at once (drop
//! connections whose access was tightened, reload settings) instead of at
//! the next connection. A Unix domain socket beside the store, mode 0600,
//! one request line per connection and one reply line:
//!
//!     share NAME   a share changed or was deleted
//!     user NAME    a user changed or was deleted
//!     settings     reload the settings
//!
//!     ok N         done; N connections were dropped
//!     err TEXT     refused
//!
//! The server never trusts the line for what changed: it re-reads the store.
//! This component imports nothing from `smb/`; `Hooks` are how `serve` wires
//! it to the SMB server, as with web.Live.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

pub const max_line = 256;
pub const suffix = ".sock";
/// Longest socket path accepted (the OS limit is 104 on macOS, 108 on Linux).
pub const max_path = 100;

pub const Request = union(enum) {
    share: []const u8,
    user: []const u8,
    settings,
};

/// One request line, without its newline; null when it isn't a command.
pub fn parse(line: []const u8) ?Request {
    const l = std.mem.trimEnd(u8, line, "\r");
    if (std.mem.eql(u8, l, "settings")) return .settings;
    const space = std.mem.indexOfScalar(u8, l, ' ') orelse return null;
    const arg = l[space + 1 ..];
    if (arg.len == 0 or arg.len > 128) return null;
    for (arg) |ch| if (ch < 0x20 or ch == 0x7f) return null;
    if (std.mem.eql(u8, l[0..space], "share")) return .{ .share = arg };
    if (std.mem.eql(u8, l[0..space], "user")) return .{ .user = arg };
    return null;
}

pub const Reply = union(enum) {
    ok: usize,
    err: []const u8,
};

/// `ok N\n` or `err TEXT\n` in `buf`.
pub fn formatReply(buf: []u8, r: Reply) []const u8 {
    return switch (r) {
        .ok => |n| std.fmt.bufPrint(buf, "ok {d}\n", .{n}) catch "err reply\n",
        .err => |t| std.fmt.bufPrint(buf, "err {s}\n", .{t}) catch "err reply\n",
    };
}

pub fn parseReply(line: []const u8) ?Reply {
    const l = std.mem.trimEnd(u8, line, "\r\n");
    if (std.mem.startsWith(u8, l, "ok ")) return .{ .ok = std.fmt.parseInt(usize, l[3..], 10) catch return null };
    if (std.mem.startsWith(u8, l, "err ")) return .{ .err = l[4..] };
    return null;
}

/// What `serve` does for each request; `ctx` is passed back. Each action
/// returns how many connections it dropped.
pub const Hooks = struct {
    ctx: ?*anyopaque = null,
    share: *const fn (ctx: ?*anyopaque, name: []const u8) usize,
    user: *const fn (ctx: ?*anyopaque, name: []const u8) usize,
    settings: *const fn (ctx: ?*anyopaque) void,
};

/// Runs one request line against the hooks.
pub fn handle(h: Hooks, line: []const u8) Reply {
    const req = parse(line) orelse return .{ .err = "unknown command" };
    return switch (req) {
        .share => |name| .{ .ok = h.share(h.ctx, name) },
        .user => |name| .{ .ok = h.user(h.ctx, name) },
        .settings => blk: {
            h.settings(h.ctx);
            break :blk .{ .ok = 0 };
        },
    };
}

// ---------------------------------------------------------------- location

/// Where the store lives, as the command line gave it.
pub const Where = struct {
    /// `--socket`: a path, or "none".
    arg: ?[]const u8 = null,
    /// The SQLite database, when a part uses one.
    db: ?[]const u8 = null,
    config: ?[]const u8 = null,
    users: ?[]const u8 = null,
};

/// The socket path, or null for none: `--socket` wins ("none" disables);
/// otherwise beside the first persistent store (database, then `--config`,
/// then `--users`); an in-memory store has nothing to notify about. The
/// caller frees the result.
pub fn pathFor(gpa: Allocator, w: Where) error{ NameTooLong, OutOfMemory }!?[]u8 {
    if (w.arg) |a| {
        if (std.mem.eql(u8, a, "none")) return null;
        if (a.len > max_path) return error.NameTooLong;
        return try gpa.dupe(u8, a);
    }
    const base = blk: {
        if (w.db) |d| if (!std.mem.eql(u8, d, ":memory:")) break :blk d;
        if (w.config) |c| break :blk c;
        if (w.users) |u| break :blk u;
        return null;
    };
    if (base.len + suffix.len > max_path) return error.NameTooLong;
    return try std.fmt.allocPrint(gpa, "{s}{s}", .{ base, suffix });
}

// ---------------------------------------------------------------- server

const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };
extern "c" fn getpeereid(fd: c_int, uid: *c_uint, gid: *c_uint) c_int;

/// The user ID of the process at the other end of a Unix socket.
fn peerUid(fd: std.posix.fd_t) ?u32 {
    switch (builtin.os.tag) {
        .linux => {
            var cred: Ucred = undefined;
            var len: std.c.socklen_t = @sizeOf(Ucred);
            if (std.c.getsockopt(fd, std.c.SOL.SOCKET, std.c.SO.PEERCRED, &cred, &len) != 0) return null;
            return cred.uid;
        },
        else => {
            var uid: c_uint = undefined;
            var gid: c_uint = undefined;
            if (getpeereid(fd, &uid, &gid) != 0) return null;
            return uid;
        },
    }
}

/// A silent peer can't hold the server or the CLI for long.
fn setTimeouts(fd: std.posix.fd_t) void {
    const tv: std.c.timeval = .{ .sec = 2, .usec = 0 };
    _ = std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.RCVTIMEO, &tv, @sizeOf(std.c.timeval));
    _ = std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.SNDTIMEO, &tv, @sizeOf(std.c.timeval));
}

pub const Listener = struct {
    gpa: Allocator,
    io: Io,
    path: [:0]u8,
    server: net.Server,
    hooks: Hooks,
    thread: ?std.Thread = null,

    /// Binds `path` (mode 0600) and serves requests on a thread. A socket
    /// left by a dead server is replaced; one that answers is
    /// `error.AddressInUse`; any other kind of file is left alone and an
    /// error.
    pub fn start(gpa: Allocator, io: Io, path: []const u8, hooks: Hooks) !*Listener {
        const ua = try net.UnixAddress.init(path);
        const z = try gpa.dupeSentinel(u8, path, 0);
        errdefer gpa.free(z);
        if (Io.Dir.cwd().statFile(io, path, .{})) |st| {
            if (st.kind != .unix_domain_socket) return error.NotASocket;
            if (ua.connect(io)) |live| {
                live.close(io);
                return error.AddressInUse;
            } else |_| {}
            _ = std.c.unlink(z);
        } else |_| {}
        // The socket file is created with the umask's permissions.
        const old = std.c.umask(0o177);
        defer _ = std.c.umask(old);
        var server = try ua.listen(io, .{});
        errdefer server.deinit(io);
        const l = try gpa.create(Listener);
        errdefer gpa.destroy(l);
        l.* = .{ .gpa = gpa, .io = io, .path = z, .server = server, .hooks = hooks };
        l.thread = try std.Thread.spawn(.{}, acceptLoop, .{l});
        l.thread.?.detach();
        return l;
    }

    /// Removes the socket file. The accept thread ends with the process.
    pub fn stop(l: *Listener) void {
        _ = std.c.unlink(l.path);
    }
};

fn acceptLoop(l: *Listener) void {
    while (true) {
        const stream = l.server.accept(l.io) catch |e| {
            std.log.warn("control accept: {s}", .{@errorName(e)});
            return;
        };
        serveOne(l, stream);
    }
}

/// One request: same user (or root) only, one line in, one line out.
fn serveOne(l: *Listener, stream: net.Stream) void {
    defer stream.close(l.io);
    const fd = stream.socket.handle;
    const uid = peerUid(fd) orelse return;
    if (uid != 0 and uid != std.c.geteuid()) return;
    setTimeouts(fd);
    var rbuf: [max_line + 1]u8 = undefined;
    var r = stream.reader(l.io, &rbuf);
    const reply: Reply = if (r.interface.takeDelimiter('\n')) |maybe|
        (if (maybe) |line| handle(l.hooks, line) else Reply{ .err = "empty request" })
    else |_|
        Reply{ .err = "bad request" };
    var out: [96]u8 = undefined;
    var wbuf: [96]u8 = undefined;
    var w = stream.writer(l.io, &wbuf);
    w.interface.writeAll(formatReply(&out, reply)) catch return;
    w.interface.flush() catch {};
}

// ---------------------------------------------------------------- client

pub const Result = union(enum) {
    /// The server did it, dropping this many connections.
    done: usize,
    /// Nothing is listening: no server is running. Not a problem.
    no_server,
    /// The socket exists but this user may not use it.
    denied,
    /// Anything else, as text.
    failed: []const u8,
};

/// Sends `line` to the server at `path` and waits (briefly) for its reply.
pub fn notify(io: Io, path: []const u8, line: []const u8) Result {
    const ua = net.UnixAddress.init(path) catch return .{ .failed = "the control path is too long" };
    const stream = ua.connect(io) catch |e| return switch (e) {
        error.FileNotFound, error.ConnectionRefused, error.NotDir => .no_server,
        error.AccessDenied, error.PermissionDenied => .denied,
        else => .{ .failed = @errorName(e) },
    };
    defer stream.close(io);
    setTimeouts(stream.socket.handle);
    var wbuf: [max_line + 2]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.print("{s}\n", .{line}) catch return .{ .failed = "could not send" };
    w.interface.flush() catch return .{ .failed = "could not send" };
    var rbuf: [96]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const got = r.interface.takeDelimiter('\n') catch return .{ .failed = "no reply (timed out?)" };
    const reply = parseReply(got orelse return .{ .failed = "no reply" }) orelse return .{ .failed = "unreadable reply" };
    return switch (reply) {
        .ok => |n| .{ .done = n },
        .err => .{ .failed = "the server refused the request" },
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const long: [200]u8 = @splat('x');

test "requests parse, and everything else is refused" {
    try testing.expectEqualStrings("docs", parse("share docs").?.share);
    try testing.expectEqualStrings("hal 9000", parse("user hal 9000\r").?.user);
    try testing.expect(parse("settings").? == .settings);
    try testing.expect(parse("settings now") == null);
    try testing.expect(parse("share") == null);
    try testing.expect(parse("share ") == null);
    try testing.expect(parse("shutdown now") == null);
    try testing.expect(parse("share a\x00b") == null);
    try testing.expect(parse("") == null);
    try testing.expect(parse("share " ++ &long) == null);
}

test "replies round trip" {
    var buf: [96]u8 = undefined;
    try testing.expectEqualStrings("ok 3\n", formatReply(&buf, .{ .ok = 3 }));
    try testing.expectEqual(@as(usize, 3), parseReply("ok 3\n").?.ok);
    try testing.expectEqualStrings("no", parseReply("err no\n").?.err);
    try testing.expect(parseReply("ok x") == null);
    try testing.expect(parseReply("what") == null);
}

const Count = struct {
    shares: usize = 0,
    users: usize = 0,
    reloads: usize = 0,
    last: [32]u8 = undefined,
    last_len: usize = 0,

    fn from(ctx: ?*anyopaque) *Count {
        return @ptrCast(@alignCast(ctx.?));
    }
    fn note(c: *Count, name: []const u8) void {
        c.last_len = @min(name.len, c.last.len);
        @memcpy(c.last[0..c.last_len], name[0..c.last_len]);
    }
    fn share(ctx: ?*anyopaque, name: []const u8) usize {
        const c = from(ctx);
        c.shares += 1;
        c.note(name);
        return 2;
    }
    fn user(ctx: ?*anyopaque, name: []const u8) usize {
        const c = from(ctx);
        c.users += 1;
        c.note(name);
        return 1;
    }
    fn settings(ctx: ?*anyopaque) void {
        from(ctx).reloads += 1;
    }
    fn hooks(c: *Count) Hooks {
        return .{ .ctx = c, .share = share, .user = user, .settings = settings };
    }
};

test "requests run the hooks" {
    var c: Count = .{};
    const h = c.hooks();
    try testing.expectEqual(@as(usize, 2), handle(h, "share docs").ok);
    try testing.expectEqualStrings("docs", c.last[0..c.last_len]);
    try testing.expectEqual(@as(usize, 1), handle(h, "user art").ok);
    try testing.expectEqual(@as(usize, 0), handle(h, "settings").ok);
    try testing.expectEqualStrings("unknown command", handle(h, "reboot").err);
    try testing.expectEqual(@as(usize, 1), c.shares);
    try testing.expectEqual(@as(usize, 1), c.users);
    try testing.expectEqual(@as(usize, 1), c.reloads);
}

test "the socket sits beside the first persistent store" {
    const g = testing.allocator;
    const a = (try pathFor(g, .{ .db = "var/z.db", .config = "c.conf" })).?;
    defer g.free(a);
    try testing.expectEqualStrings("var/z.db.sock", a);
    const b = (try pathFor(g, .{ .db = ":memory:", .users = "etc/users" })).?;
    defer g.free(b);
    try testing.expectEqualStrings("etc/users.sock", b);
    const c = (try pathFor(g, .{ .arg = "/run/zsmbd.sock", .db = "z.db" })).?;
    defer g.free(c);
    try testing.expectEqualStrings("/run/zsmbd.sock", c);
    try testing.expectEqual(null, try pathFor(g, .{ .arg = "none", .db = "z.db" }));
    try testing.expectEqual(null, try pathFor(g, .{ .db = ":memory:" }));
    try testing.expectEqual(null, try pathFor(g, .{}));
    try testing.expectError(error.NameTooLong, pathFor(g, .{ .db = long[0..99] }));
}

fn tmpSocket(tmp: *testing.TmpDir, buf: []u8) ![]const u8 {
    var dir: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(testing.io, &dir);
    return std.fmt.bufPrint(buf, "{s}/c.sock", .{dir[0..n]});
}

test "a client reaches a listening server; stale sockets are replaced" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpSocket(&tmp, &pbuf);
    if (path.len > max_path) return error.SkipZigTest;

    // Nobody listening.
    try testing.expect(notify(testing.io, path, "settings") == .no_server);

    var c: Count = .{};
    const l = try Listener.start(testing.allocator, testing.io, path, c.hooks());
    defer {
        l.stop();
        testing.allocator.free(l.path);
        testing.allocator.destroy(l);
    }
    const st = try tmp.dir.statFile(testing.io, "c.sock", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);

    try testing.expectEqual(@as(usize, 2), notify(testing.io, path, "share docs").done);
    try testing.expectEqualStrings("docs", c.last[0..c.last_len]);
    try testing.expectEqual(@as(usize, 1), notify(testing.io, path, "user art").done);
    try testing.expectEqual(@as(usize, 0), notify(testing.io, path, "settings").done);
    try testing.expect(notify(testing.io, path, "reboot") == .failed);
    try testing.expectEqual(@as(usize, 1), c.reloads);

    // A second server on a live socket refuses to start.
    try testing.expectError(error.AddressInUse, Listener.start(testing.allocator, testing.io, path, c.hooks()));
}

test "a regular file is never replaced" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "c.sock", .data = "precious" });
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpSocket(&tmp, &pbuf);
    if (path.len > max_path) return error.SkipZigTest;
    var c: Count = .{};
    try testing.expectError(error.NotASocket, Listener.start(testing.allocator, testing.io, path, c.hooks()));
    const kept = try tmp.dir.readFileAlloc(testing.io, "c.sock", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("precious", kept);
}

test "fuzz: control requests and replies" {
    try @import("../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            if (parse(in)) |req| switch (req) {
                .share, .user => |name| try testing.expect(name.len > 0 and name.len <= 128),
                .settings => {},
            };
            _ = parseReply(in);
        }
    }.one, &.{ "share docs", "user hal\r", "settings", "ok 12\n", "err nope" });
}
