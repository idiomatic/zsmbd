//! What libsmbd asks of the program that embeds it: the shares, the NT hash
//! of each SMB user, and somewhere to send log lines. The host answers from
//! wherever it keeps them (zsmbd: its store); libsmbd never stores anything.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    OutOfMemory,
    /// The host could not answer (its store failed); the request fails.
    HostFailed,
};

pub const Share = struct {
    name: []const u8,
    /// Absolute path of the directory the share serves.
    path: []const u8,
    comment: []const u8 = "",
    read_only: bool = false,
    /// Anonymous sessions may connect (only while signing is not required).
    guest_ok: bool = false,

    pub fn free(s: Share, gpa: Allocator) void {
        gpa.free(s.name);
        gpa.free(s.path);
        gpa.free(s.comment);
    }
};

/// Frees a share list returned by `Host.listShares`.
pub fn freeShares(gpa: Allocator, shares: []const Share) void {
    for (shares) |s| s.free(gpa);
    gpa.free(shares);
}

/// Which clients a relaxing share change also drops, once: those that
/// connected under the stricter rules and still act on them.
pub const Kick = enum {
    none,
    /// Trees opened read-only on a share now writable.
    writable,
    /// Connections with an anonymous session, on a share now open to guests.
    guests,
};

pub const Level = enum { err, warn, info };

/// Called from any connection thread, so each function must be thread-safe.
pub const Host = struct {
    ctx: ?*anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Every share (not IPC$), names matching case-insensitively. The
        /// slice and its strings come from `gpa` (see `freeShares`).
        listShares: *const fn (ctx: ?*anyopaque, gpa: Allocator) Error![]Share,
        /// The NT hash (MD4 of the UTF-16LE password) of SMB user `name`,
        /// matched case-insensitively; null when the user has no SMB
        /// password or doesn't exist.
        ntHash: *const fn (ctx: ?*anyopaque, name: []const u8) Error!?[16]u8,
        /// One event; `conn_id` 0 is the server itself. `kind` and `msg`
        /// last only for the call.
        log: *const fn (ctx: ?*anyopaque, level: Level, conn_id: u64, kind: []const u8, msg: []const u8) void,
    };

    pub fn listShares(h: Host, gpa: Allocator) Error![]Share {
        return h.vtable.listShares(h.ctx, gpa);
    }
    pub fn ntHash(h: Host, name: []const u8) Error!?[16]u8 {
        return h.vtable.ntHash(h.ctx, name);
    }
    pub fn log(h: Host, level: Level, conn_id: u64, kind: []const u8, msg: []const u8) void {
        h.vtable.log(h.ctx, level, conn_id, kind, msg);
    }
};

/// An in-memory host for tests: shares and users added directly, and log
/// lines dropped.
pub const TestHost = struct {
    gpa: Allocator,
    shares: std.ArrayList(Share) = .empty,
    users: std.ArrayList(struct { name: []const u8, nt: [16]u8 }) = .empty,

    pub fn deinit(t: *TestHost) void {
        t.shares.deinit(t.gpa);
        t.users.deinit(t.gpa);
    }

    pub fn host(t: *TestHost) Host {
        return .{ .ctx = t, .vtable = &.{ .listShares = listShares_, .ntHash = ntHash_, .log = log_ } };
    }

    /// `s`'s strings must outlive the host.
    pub fn putShare(t: *TestHost, s: Share) !void {
        try t.shares.append(t.gpa, s);
    }

    /// A user whose SMB password is `password`.
    pub fn putUser(t: *TestHost, name: []const u8, password: []const u8) !void {
        try t.users.append(t.gpa, .{ .name = name, .nt = try @import("../shared/crypto.zig").ntHash(t.gpa, password) });
    }

    fn self(ctx: ?*anyopaque) *TestHost {
        return @ptrCast(@alignCast(ctx.?));
    }

    fn listShares_(ctx: ?*anyopaque, gpa: Allocator) Error![]Share {
        const t = self(ctx);
        const out = try gpa.alloc(Share, t.shares.items.len);
        var n: usize = 0;
        errdefer {
            for (out[0..n]) |s| s.free(gpa);
            gpa.free(out);
        }
        for (t.shares.items) |s| {
            const name = try gpa.dupe(u8, s.name);
            errdefer gpa.free(name);
            const path = try gpa.dupe(u8, s.path);
            errdefer gpa.free(path);
            out[n] = .{ .name = name, .path = path, .comment = try gpa.dupe(u8, s.comment), .read_only = s.read_only, .guest_ok = s.guest_ok };
            n += 1;
        }
        return out;
    }

    fn ntHash_(ctx: ?*anyopaque, name: []const u8) Error!?[16]u8 {
        for (self(ctx).users.items) |u| if (std.ascii.eqlIgnoreCase(u.name, name)) return u.nt;
        return null;
    }

    fn log_(_: ?*anyopaque, _: Level, _: u64, _: []const u8, _: []const u8) void {}
};
