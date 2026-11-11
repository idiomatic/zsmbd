//! What a test sees: the target (`Env`), a `T` that opens clients and
//! records failures, and the `Test` entry the suites list.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const proto = @import("proto");
const client = @import("client.zig");

/// The server a run is judged against. A test names the behavior it expects
/// of `zsmbd` and skips under another profile when that behavior is
/// zsmbd's own choice.
pub const Profile = enum { zsmbd, samba, windows };

pub const Env = struct {
    gpa: Allocator,
    io: Io,
    addr: net.IpAddress,
    /// The host part of share paths.
    host: []const u8,
    /// A disk share the user can read and write.
    share: []const u8,
    user: []const u8,
    password: []const u8,
    profile: Profile,
    timeout_s: u32 = 5,
};

pub const Test = struct {
    /// `suite.name`.
    name: []const u8,
    /// The specification section the test checks.
    spec: []const u8,
    run: *const fn (*T) anyerror!void,
};

pub const T = struct {
    env: *const Env,
    gpa: Allocator,
    clients: std.ArrayList(*client.Client) = .empty,
    failure: ?[]u8 = null,

    pub fn init(env: *const Env) T {
        return .{ .env = env, .gpa = env.gpa };
    }

    pub fn deinit(t: *T) void {
        for (t.clients.items) |c| c.deinit();
        t.clients.deinit(t.gpa);
        if (t.failure) |f| t.gpa.free(f);
    }

    // ------------------------------------------------------------ clients

    /// A connection with nothing sent.
    pub fn dial(t: *T) !*client.Client {
        const c = try client.Client.connect(t.gpa, t.env.io, t.env.addr, t.env.timeout_s);
        errdefer c.deinit();
        try t.clients.append(t.gpa, c);
        return c;
    }

    /// A connection after a successful NEGOTIATE.
    pub fn negotiated(t: *T) !*client.Client {
        const c = try t.dial();
        const r = try c.negotiate(.{});
        defer r.deinit();
        try t.expectStatus(proto.Status.success, r.status());
        return c;
    }

    /// A logged-on connection.
    pub fn session(t: *T) !*client.Client {
        const c = try t.negotiated();
        const res = try c.login(t.env.user, t.env.password);
        try t.expectStatus(proto.Status.success, res.status);
        return c;
    }

    // ------------------------------------------------------------ outcomes

    /// Skips the test unless the run is judged against `p`.
    pub fn only(t: *T, p: Profile) !void {
        if (t.env.profile != p) return error.SkipTest;
    }

    pub fn fail(t: *T, comptime fmt: []const u8, args: anytype) error{TestFailed} {
        if (t.failure) |f| t.gpa.free(f);
        t.failure = std.fmt.allocPrint(t.gpa, fmt, args) catch null;
        return error.TestFailed;
    }

    pub fn expect(t: *T, ok: bool, comptime fmt: []const u8, args: anytype) !void {
        if (!ok) return t.fail(fmt, args);
    }

    pub fn expectEq(t: *T, want: anytype, got: @TypeOf(want), what: []const u8) !void {
        if (want != got) return t.fail("{s}: want {any}, got {any}", .{ what, want, got });
    }

    pub fn expectStatus(t: *T, want: u32, got: u32) !void {
        if (want != got) return t.fail("status: want {s} (0x{x:0>8}), got {s} (0x{x:0>8})", .{
            proto.Status.name(want), want, proto.Status.name(got), got,
        });
    }

    /// Frames each client saw, newest last.
    pub fn writeTrace(t: *T, w: *Io.Writer) !void {
        for (t.clients.items, 0..) |c, i| {
            try w.print("  connection {d}:\n", .{i + 1});
            try c.writeTrace(w);
        }
    }
};
