//! Persistent configuration store (users, shares, settings). Each part,
//! settings with shares and users, is backed by SQLite (sqlite.zig) or by a
//! plain-text file (textconf.zig, textusers.zig), independently. All access
//! is serialized through a mutex; the SMB and web threads share it.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const Sqlite = @import("sqlite.zig").Sqlite;
const textconf = @import("textconf.zig");
const textusers = @import("textusers.zig");

pub const Error = types.Error;
pub const Change = types.Change;
pub const Share = types.Share;
pub const User = types.User;
pub const UserAuth = types.UserAuth;
pub const freeShares = types.freeShares;
pub const freeUsers = types.freeUsers;
pub const userLine = textusers.formatLine;

pub const Db = struct {
    /// Set when either part uses SQLite.
    sqlite: ?Sqlite = null,
    /// Settings and shares in a text file instead of SQLite.
    conf: ?*textconf.Conf = null,
    /// Users in a text file instead of SQLite.
    users: ?*textusers.Users = null,
    mutex: Io.Mutex = .init,
    io: Io,

    pub const Location = struct {
        /// The SQLite database, opened only when a part below is null.
        db: [:0]const u8 = "zsmbd.db",
        /// Text file for settings and shares.
        config: ?[]const u8 = null,
        /// Text file for users.
        users: ?[]const u8 = null,

        pub fn usesSqlite(l: Location) bool {
            return l.config == null or l.users == null;
        }
    };

    pub fn openAt(gpa: Allocator, io: Io, loc: Location) Error!Db {
        var d: Db = .{ .io = io };
        errdefer d.close();
        if (loc.usesSqlite()) d.sqlite = try Sqlite.open(loc.db);
        if (loc.config) |p| d.conf = try textconf.Conf.open(gpa, io, p);
        if (loc.users) |p| d.users = try textusers.Users.open(gpa, io, p);
        return d;
    }

    /// Everything in one SQLite database (tests use ":memory:").
    pub fn open(io: Io, path: [:0]const u8) Error!Db {
        return .{ .sqlite = try Sqlite.open(path), .io = io };
    }

    pub fn close(db: *Db) void {
        if (db.conf) |t| t.close();
        if (db.users) |t| t.close();
        if (db.sqlite) |*s| s.close();
        db.conf = null;
        db.users = null;
        db.sqlite = null;
    }

    // ------------------------------------------------------------ settings and shares

    pub fn getSetting(db: *Db, gpa: Allocator, key: []const u8) Error!?[]u8 {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.conf) |t| return t.getSetting(gpa, key);
        return db.sqlite.?.getSetting(gpa, key);
    }

    pub fn setSetting(db: *Db, key: []const u8, value: []const u8) Error!void {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.conf) |t| return t.setSetting(key, value);
        return db.sqlite.?.setSetting(key, value);
    }

    // ------------------------------------------------------------ users

    /// NT hash for SMB logins; null for unknown users and users without one.
    pub fn ntHash(db: *Db, name: []const u8) Error!?[16]u8 {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users) |t| return t.ntHash(name);
        return db.sqlite.?.ntHash(name);
    }

    pub fn userAuth(db: *Db, gpa: Allocator, name: []const u8) Error!?UserAuth {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users) |t| return t.userAuth(gpa, name);
        return db.sqlite.?.userAuth(gpa, name);
    }

    /// Create or update a user, setting, keeping, or clearing each password
    /// hash; a kept hash of a new user is absent.
    pub fn putUser(db: *Db, name: []const u8, nt_hash: Change([16]u8), web_hash: Change([]const u8), now: i64) Error!void {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users) |t| return t.putUser(name, nt_hash, web_hash, now);
        return db.sqlite.?.putUser(name, nt_hash, web_hash, now);
    }

    pub fn deleteUser(db: *Db, name: []const u8) Error!bool {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users) |t| return t.deleteUser(name);
        return db.sqlite.?.deleteUser(name);
    }

    /// Users who can sign in to the web console (those with a web password).
    pub fn countWebUsers(db: *Db) Error!i64 {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users) |t| return t.countWebUsers();
        return db.sqlite.?.countWebUsers();
    }

    pub fn listUsers(db: *Db, gpa: Allocator) Error![]User {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users) |t| return t.listUsers(gpa);
        return db.sqlite.?.listUsers(gpa);
    }

    // ------------------------------------------------------------ settings and shares

    pub fn listShares(db: *Db, gpa: Allocator) Error![]Share {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.conf) |t| return t.listShares(gpa);
        return db.sqlite.?.listShares(gpa);
    }

    pub fn putShare(db: *Db, s: Share) Error!void {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.conf) |t| return t.putShare(s);
        return db.sqlite.?.putShare(s);
    }

    pub fn deleteShare(db: *Db, name: []const u8) Error!bool {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.conf) |t| return t.deleteShare(name);
        return db.sqlite.?.deleteShare(name);
    }
};
