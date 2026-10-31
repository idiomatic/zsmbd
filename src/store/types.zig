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

    pub fn dupe(s: Share, gpa: Allocator) !Share {
        return .{
            .name = try gpa.dupe(u8, s.name),
            .path = try gpa.dupe(u8, s.path),
            .comment = try gpa.dupe(u8, s.comment),
            .read_only = s.read_only,
            .guest_ok = s.guest_ok,
        };
    }
    pub fn free(s: Share, gpa: Allocator) void {
        gpa.free(s.name);
        gpa.free(s.path);
        gpa.free(s.comment);
    }
};

/// What a user may sign in to. Each role has only the passwords it uses.
pub const Role = enum {
    /// Web console only (web password).
    admin,
    /// SMB only (SMB password).
    client,
    /// Both, with separate passwords.
    hybrid,

    pub fn web(r: Role) bool {
        return r != .client;
    }
    pub fn smb(r: Role) bool {
        return r != .admin;
    }
    pub fn parse(s: []const u8) ?Role {
        return std.meta.stringToEnum(Role, s);
    }
};

pub const User = struct {
    name: []const u8,
    role: Role,
    created: i64,
};

pub const UserAuth = struct {
    name: []u8,
    role: Role,
    /// argon2id PHC string; empty when the user has no web password.
    pw_hash: []u8,
    has_smb: bool,

    pub fn free(u: UserAuth, gpa: Allocator) void {
        gpa.free(u.name);
        gpa.free(u.pw_hash);
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

