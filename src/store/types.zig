//! Records shared by every store backend and its callers.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{ Sqlite, Store, OutOfMemory };

pub const Share = struct {
    name: []const u8,
    path: []const u8,
    comment: []const u8 = "",
    read_only: bool = false,
    guest_ok: bool = false,
    /// Given on the command line; kept in memory only.
    ephemeral: bool = false,

    pub fn dupe(s: Share, gpa: Allocator) !Share {
        return .{
            .name = try gpa.dupe(u8, s.name),
            .path = try gpa.dupe(u8, s.path),
            .comment = try gpa.dupe(u8, s.comment),
            .read_only = s.read_only,
            .guest_ok = s.guest_ok,
            .ephemeral = s.ephemeral,
        };
    }
    pub fn free(s: Share, gpa: Allocator) void {
        gpa.free(s.name);
        gpa.free(s.path);
        gpa.free(s.comment);
    }
};

/// How `putUser` treats one stored password hash.
pub fn Change(comptime T: type) type {
    return union(enum) { keep, clear, set: T };
}

/// A user signs in to SMB with an SMB password and to the web console with a
/// web password; a user may have either, both, or neither.
pub const User = struct {
    name: []const u8,
    has_smb: bool,
    has_web: bool,
    created: i64,
    /// Given on the command line or stdin; kept in memory only.
    ephemeral: bool = false,
};

pub const UserAuth = struct {
    name: []u8,
    /// argon2id PHC string; empty when the user has no web password.
    web_hash: []u8,
    has_smb: bool,

    pub fn free(u: UserAuth, gpa: Allocator) void {
        gpa.free(u.name);
        gpa.free(u.web_hash);
    }
};

pub fn freeShares(gpa: Allocator, shares: []Share) void {
    for (shares) |s| s.free(gpa);
    gpa.free(shares);
}

pub fn freeUsers(gpa: Allocator, users: []User) void {
    for (users) |u| gpa.free(u.name);
    gpa.free(users);
}

