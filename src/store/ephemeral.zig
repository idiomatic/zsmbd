//! Shares and users given to `serve` on the command line or on stdin: kept in
//! memory only, never written to the store, and read-only to every command.
//! They shadow stored entries of the same name.
//!
//! Callers serialize access (Db.mutex).

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const Share = types.Share;

pub const User = struct {
    name: []u8,
    nt_hash: ?[16]u8,
    /// argon2id PHC string; empty when the user has no web password.
    web_hash: []u8,
};

pub const Ephemeral = struct {
    gpa: Allocator,
    users: std.ArrayList(User) = .empty,
    shares: std.ArrayList(Share) = .empty,

    pub fn create(gpa: Allocator) Allocator.Error!*Ephemeral {
        const e = try gpa.create(Ephemeral);
        e.* = .{ .gpa = gpa };
        return e;
    }

    pub fn destroy(e: *Ephemeral) void {
        const gpa = e.gpa;
        for (e.users.items) |u| {
            gpa.free(u.name);
            std.crypto.secureZero(u8, u.web_hash);
            gpa.free(u.web_hash);
        }
        e.users.deinit(gpa);
        for (e.shares.items) |s| s.free(gpa);
        e.shares.deinit(gpa);
        gpa.destroy(e);
    }

    pub fn findUser(e: *Ephemeral, name: []const u8) ?*User {
        for (e.users.items) |*u| if (std.ascii.eqlIgnoreCase(u.name, name)) return u;
        return null;
    }

    pub fn findShare(e: *Ephemeral, name: []const u8) ?*Share {
        for (e.shares.items) |*s| if (std.ascii.eqlIgnoreCase(s.name, name)) return s;
        return null;
    }

    /// Adds a copy; a name already present is `error.Store`.
    pub fn addUser(e: *Ephemeral, name: []const u8, nt_hash: ?[16]u8, web_hash: []const u8) !void {
        if (e.findUser(name) != null) return error.Store;
        const n = try e.gpa.dupe(u8, name);
        errdefer e.gpa.free(n);
        const w = try e.gpa.dupe(u8, web_hash);
        errdefer e.gpa.free(w);
        try e.users.append(e.gpa, .{ .name = n, .nt_hash = nt_hash, .web_hash = w });
    }

    /// Sets, keeps, or clears each hash of `u` in memory (same rules as the
    /// stores' `putUser`). Nothing changes on failure.
    pub fn changeUser(e: *Ephemeral, u: *User, nt_hash: types.Change([16]u8), web_hash: types.Change([]const u8)) Allocator.Error!void {
        const new_web: ?[]u8 = switch (web_hash) {
            .keep => null,
            .clear => try e.gpa.alloc(u8, 0),
            .set => |h| try e.gpa.dupe(u8, h),
        };
        switch (nt_hash) {
            .keep => {},
            .clear => u.nt_hash = null,
            .set => |h| u.nt_hash = h,
        }
        if (new_web) |w| {
            std.crypto.secureZero(u8, u.web_hash);
            e.gpa.free(u.web_hash);
            u.web_hash = w;
        }
    }

    /// Removes user `name`; false when there is none.
    pub fn removeUser(e: *Ephemeral, name: []const u8) bool {
        for (e.users.items, 0..) |u, i| if (std.ascii.eqlIgnoreCase(u.name, name)) {
            e.gpa.free(u.name);
            std.crypto.secureZero(u8, u.web_hash);
            e.gpa.free(u.web_hash);
            _ = e.users.orderedRemove(i);
            return true;
        };
        return false;
    }

    /// Removes share `name`; false when there is none.
    pub fn removeShare(e: *Ephemeral, name: []const u8) bool {
        for (e.shares.items, 0..) |s, i| if (std.ascii.eqlIgnoreCase(s.name, name)) {
            s.free(e.gpa);
            _ = e.shares.orderedRemove(i);
            return true;
        };
        return false;
    }

    /// Replaces share `old`'s fields with a copy of `share`'s (the name keeps
    /// its stored spelling); the share stays ephemeral.
    pub fn changeShare(e: *Ephemeral, old: *Share, share: Share) Allocator.Error!void {
        var n = try share.dupe(e.gpa);
        n.ephemeral = true;
        old.free(e.gpa);
        old.* = n;
    }

    /// Adds a copy marked ephemeral; a name already present is `error.Store`.
    pub fn addShare(e: *Ephemeral, share: Share) !void {
        if (e.findShare(share.name) != null) return error.Store;
        var s = try share.dupe(e.gpa);
        s.ephemeral = true;
        errdefer s.free(e.gpa);
        try e.shares.append(e.gpa, s);
    }
};

test "an ephemeral user's hashes can be set, kept, and cleared" {
    const t = std.testing;
    const e = try Ephemeral.create(t.allocator);
    defer e.destroy();
    try e.addUser("hal", null, "$argon2id$old");
    const u = e.findUser("hal").?;
    const nt: [16]u8 = @splat(7);
    try e.changeUser(u, .{ .set = nt }, .keep);
    try t.expectEqual(nt, u.nt_hash.?);
    try t.expectEqualStrings("$argon2id$old", u.web_hash);
    try e.changeUser(u, .clear, .{ .set = "$argon2id$new" });
    try t.expect(u.nt_hash == null);
    try t.expectEqualStrings("$argon2id$new", u.web_hash);
    try e.changeUser(u, .keep, .clear);
    try t.expectEqual(@as(usize, 0), u.web_hash.len);
}

test "entries are found without regard to case and names stay unique" {
    const t = std.testing;
    const e = try Ephemeral.create(t.allocator);
    defer e.destroy();
    try e.addUser("Hal", null, "");
    try t.expect(e.findUser("hal") != null);
    try t.expectError(error.Store, e.addUser("HAL", null, ""));
    try e.addShare(.{ .name = "Docs", .path = "/srv" });
    try t.expect(e.findShare("docs").?.ephemeral);
    try t.expectError(error.Store, e.addShare(.{ .name = "DOCS", .path = "/x" }));
}
