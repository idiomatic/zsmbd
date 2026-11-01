//! Persistent configuration store (users, shares, settings). Each part,
//! settings with shares and users, is backed by SQLite (sqlite.zig) or by a
//! plain-text file (textconf.zig, textusers.zig), independently. Ephemeral
//! shares and users (ephemeral.zig) sit in front of them: they are found
//! first, shadow stored entries, and refuse changes. All access is
//! serialized through a mutex; the SMB and web threads share it.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const Sqlite = @import("sqlite.zig").Sqlite;
const textconf = @import("textconf.zig");
const textusers = @import("textusers.zig");
const ephemeral = @import("ephemeral.zig");

pub const Error = types.Error;
pub const Change = types.Change;
pub const Share = types.Share;
pub const User = types.User;
pub const UserAuth = types.UserAuth;
pub const freeShares = types.freeShares;
pub const freeUsers = types.freeUsers;
pub const Ephemeral = ephemeral.Ephemeral;
pub const userLine = textusers.formatLine;
pub const parseUsers = textusers.parseUsers;
pub const UserRec = textusers.UserRec;
pub const freeUserRec = textusers.freeUser;

pub const Db = struct {
    /// Set when either part uses SQLite.
    sqlite: ?Sqlite = null,
    /// Settings and shares in a text file instead of SQLite.
    conf: ?*textconf.Conf = null,
    /// Users in a text file instead of SQLite.
    users: ?*textusers.Users = null,
    /// Shares and users given on the command line or stdin (null: none).
    ephemeral: ?*ephemeral.Ephemeral = null,
    /// `--users -`: no users are stored; those on stdin are ephemeral.
    users_stdin: bool = false,
    /// No `--db`: the store is in memory and only ephemeral entries exist.
    ephemeral_only: bool = false,
    mutex: Io.Mutex = .init,
    io: Io,

    pub const Location = struct {
        /// The SQLite database, opened only when a part below is null; there
        /// is no default, so a caller that needs it must set it.
        db: ?[:0]const u8 = null,
        /// Text file for settings and shares.
        config: ?[]const u8 = null,
        /// Text file for users.
        users: ?[]const u8 = null,
        /// Users come from stdin (`--users -`) instead.
        users_stdin: bool = false,

        pub fn usesSqlite(l: Location) bool {
            return l.config == null or (l.users == null and !l.users_stdin);
        }
    };

    pub fn openAt(gpa: Allocator, io: Io, loc: Location) Error!Db {
        var d: Db = .{ .io = io, .users_stdin = loc.users_stdin };
        errdefer d.close();
        if (loc.usesSqlite()) d.sqlite = try Sqlite.open(loc.db orelse return error.Store);
        if (loc.config) |p| d.conf = try textconf.Conf.open(gpa, io, p);
        if (loc.users) |p| d.users = try textusers.Users.open(gpa, io, p);
        return d;
    }

    /// Everything in one SQLite database (tests use ":memory:").
    pub fn open(io: Io, path: [:0]const u8) Error!Db {
        return .{ .sqlite = try Sqlite.open(path), .io = io };
    }

    pub fn close(db: *Db) void {
        if (db.ephemeral) |e| e.destroy();
        if (db.conf) |t| t.close();
        if (db.users) |t| t.close();
        if (db.sqlite) |*s| s.close();
        db.conf = null;
        db.users = null;
        db.sqlite = null;
        db.ephemeral = null;
    }

    // ------------------------------------------------------------ ephemeral entries

    /// Adds a user that exists only in memory, shadowing a stored one of the
    /// same name; `name` must not be ephemeral already. Call before serving.
    pub fn addEphemeralUser(db: *Db, gpa: Allocator, name: []const u8, nt_hash: ?[16]u8, web_hash: []const u8) Error!void {
        const e = try db.ephemeralLayer(gpa);
        try e.addUser(name, nt_hash, web_hash);
        if (try db.storedUser(gpa, name)) std.log.warn("ephemeral user {s} shadows a stored user of that name", .{name});
    }

    /// Adds a share that exists only in memory, shadowing a stored one of the
    /// same name; `share.name` must not be ephemeral already.
    pub fn addEphemeralShare(db: *Db, gpa: Allocator, share: Share) Error!void {
        const e = try db.ephemeralLayer(gpa);
        try e.addShare(share);
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        const stored = try db.storedShares(gpa);
        defer types.freeShares(gpa, stored);
        for (stored) |s| if (std.ascii.eqlIgnoreCase(s.name, share.name)) {
            std.log.warn("ephemeral share {s} shadows a stored share of that name", .{share.name});
            break;
        };
    }

    fn ephemeralLayer(db: *Db, gpa: Allocator) Allocator.Error!*ephemeral.Ephemeral {
        if (db.ephemeral == null) db.ephemeral = try ephemeral.Ephemeral.create(gpa);
        return db.ephemeral.?;
    }

    /// Whether `name` is an ephemeral user, whose passwords can't change.
    pub fn isEphemeralUser(db: *Db, name: []const u8) bool {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        const e = db.ephemeral orelse return false;
        return e.findUser(name) != null;
    }

    /// Whether anyone is given a web password outside the store, so the
    /// first-run `admin` isn't needed.
    pub fn hasEphemeralWebLogin(db: *Db) bool {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        const e = db.ephemeral orelse return false;
        for (e.users.items) |u| if (u.web_hash.len > 0) return true;
        return false;
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
        if (db.ephemeral) |e| if (e.findUser(name)) |u| return u.nt_hash;
        if (db.users_stdin) return null;
        if (db.users) |t| return t.ntHash(name);
        return db.sqlite.?.ntHash(name);
    }

    pub fn userAuth(db: *Db, gpa: Allocator, name: []const u8) Error!?UserAuth {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.ephemeral) |e| if (e.findUser(name)) |u| {
            const n = try gpa.dupe(u8, u.name);
            errdefer gpa.free(n);
            return .{ .name = n, .web_hash = try gpa.dupe(u8, u.web_hash), .has_smb = u.nt_hash != null };
        };
        if (db.users_stdin) return null;
        if (db.users) |t| return t.userAuth(gpa, name);
        return db.sqlite.?.userAuth(gpa, name);
    }

    /// Create or update a user, setting, keeping, or clearing each password
    /// hash; a kept hash of a new user is absent. Ephemeral users are
    /// `error.Ephemeral`, and with `--users -` every change is
    /// `error.ReadOnly`.
    pub fn putUser(db: *Db, name: []const u8, nt_hash: Change([16]u8), web_hash: Change([]const u8), now: i64) Error!void {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.ephemeral) |e| if (e.findUser(name) != null) return error.Ephemeral;
        if (db.users_stdin) return error.ReadOnly;
        if (db.users) |t| return t.putUser(name, nt_hash, web_hash, now);
        return db.sqlite.?.putUser(name, nt_hash, web_hash, now);
    }

    pub fn deleteUser(db: *Db, name: []const u8) Error!bool {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.ephemeral) |e| if (e.findUser(name) != null) return error.Ephemeral;
        if (db.users_stdin) return false;
        if (db.users) |t| return t.deleteUser(name);
        return db.sqlite.?.deleteUser(name);
    }

    /// Stored users who can sign in to the web console (those with a web
    /// password); ephemeral users are not counted, since a restart drops them.
    pub fn countWebUsers(db: *Db) Error!i64 {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users_stdin) return 0;
        if (db.users) |t| return t.countWebUsers();
        return db.sqlite.?.countWebUsers();
    }

    /// Stored users, then ephemeral ones, which hide stored users of the
    /// same name; sorted by name.
    pub fn listUsers(db: *Db, gpa: Allocator) Error![]User {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        const stored: []User = if (db.users_stdin) try gpa.alloc(User, 0) else if (db.users) |t| try t.listUsers(gpa) else try db.sqlite.?.listUsers(gpa);
        const e = db.ephemeral orelse return stored;
        var out: std.ArrayList(User) = .fromOwnedSlice(stored);
        errdefer {
            for (out.items) |u| gpa.free(u.name);
            out.deinit(gpa);
        }
        var i: usize = 0;
        while (i < out.items.len) {
            if (e.findUser(out.items[i].name) != null) gpa.free(out.orderedRemove(i).name) else i += 1;
        }
        for (e.users.items) |u| {
            const n = try gpa.dupe(u8, u.name);
            errdefer gpa.free(n);
            try out.append(gpa, .{ .name = n, .has_smb = u.nt_hash != null, .has_web = u.web_hash.len > 0, .created = 0, .ephemeral = true });
        }
        std.mem.sort(User, out.items, {}, struct {
            fn lt(_: void, a: User, b: User) bool {
                return std.ascii.lessThanIgnoreCase(a.name, b.name);
            }
        }.lt);
        return out.toOwnedSlice(gpa);
    }

    /// Whether the store (not the ephemeral layer) has user `name`; caller
    /// holds no lock.
    fn storedUser(db: *Db, gpa: Allocator, name: []const u8) Error!bool {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.users_stdin) return false;
        const u = (if (db.users) |t| try t.userAuth(gpa, name) else try db.sqlite.?.userAuth(gpa, name)) orelse return false;
        u.free(gpa);
        return true;
    }

    // ------------------------------------------------------------ settings and shares

    /// Stored shares, then ephemeral ones, which hide stored shares of the
    /// same name.
    pub fn listShares(db: *Db, gpa: Allocator) Error![]Share {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        const stored = try db.storedShares(gpa);
        const e = db.ephemeral orelse return stored;
        var out: std.ArrayList(Share) = .fromOwnedSlice(stored);
        errdefer {
            for (out.items) |x| x.free(gpa);
            out.deinit(gpa);
        }
        var i: usize = 0;
        while (i < out.items.len) {
            if (e.findShare(out.items[i].name) != null) out.orderedRemove(i).free(gpa) else i += 1;
        }
        for (e.shares.items) |s| {
            const c = try s.dupe(gpa);
            errdefer c.free(gpa);
            try out.append(gpa, c);
        }
        return out.toOwnedSlice(gpa);
    }

    /// Caller holds the lock.
    fn storedShares(db: *Db, gpa: Allocator) Error![]Share {
        if (db.conf) |t| return t.listShares(gpa);
        return db.sqlite.?.listShares(gpa);
    }

    pub fn putShare(db: *Db, s: Share) Error!void {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.ephemeral) |e| if (e.findShare(s.name) != null) return error.Ephemeral;
        if (db.conf) |t| return t.putShare(s);
        return db.sqlite.?.putShare(s);
    }

    pub fn deleteShare(db: *Db, name: []const u8) Error!bool {
        db.mutex.lockUncancelable(db.io);
        defer db.mutex.unlock(db.io);
        if (db.ephemeral) |e| if (e.findShare(name) != null) return error.Ephemeral;
        if (db.conf) |t| return t.deleteShare(name);
        return db.sqlite.?.deleteShare(name);
    }
};
