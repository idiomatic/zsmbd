//! SQLite backend for the store, through hand-written libsqlite3 bindings.
//! Callers serialize access (Db.mutex); SQLite's full mutex is a backstop.

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const Error = types.Error;
const Change = types.Change;
const Share = types.Share;
const User = types.User;
const UserAuth = types.UserAuth;

// ---------------------------------------------------------------- libsqlite3 bindings

const sqlite3 = opaque {};
const sqlite3_stmt = opaque {};
const SQLITE_OK = 0;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_OPEN_READWRITE = 0x00000002;
const SQLITE_OPEN_CREATE = 0x00000004;
const SQLITE_OPEN_FULLMUTEX = 0x00010000;
const SQLITE_TRANSIENT: ?*const anyopaque = @ptrFromInt(std.math.maxInt(usize));

extern "c" fn sqlite3_open_v2(filename: [*:0]const u8, db: *?*sqlite3, flags: c_int, vfs: ?[*:0]const u8) c_int;
extern "c" fn sqlite3_close_v2(db: *sqlite3) c_int;
extern "c" fn sqlite3_errmsg(db: *sqlite3) [*:0]const u8;
extern "c" fn sqlite3_exec(db: *sqlite3, sql: [*:0]const u8, cb: ?*const anyopaque, arg: ?*anyopaque, err: ?*?[*:0]u8) c_int;
extern "c" fn sqlite3_prepare_v2(db: *sqlite3, sql: [*]const u8, n: c_int, stmt: *?*sqlite3_stmt, tail: ?*?[*]const u8) c_int;
extern "c" fn sqlite3_finalize(stmt: *sqlite3_stmt) c_int;
extern "c" fn sqlite3_step(stmt: *sqlite3_stmt) c_int;
extern "c" fn sqlite3_bind_text(stmt: *sqlite3_stmt, idx: c_int, text: [*]const u8, n: c_int, destructor: ?*const anyopaque) c_int;
extern "c" fn sqlite3_bind_blob(stmt: *sqlite3_stmt, idx: c_int, data: [*]const u8, n: c_int, destructor: ?*const anyopaque) c_int;
extern "c" fn sqlite3_bind_int64(stmt: *sqlite3_stmt, idx: c_int, v: i64) c_int;
extern "c" fn sqlite3_column_text(stmt: *sqlite3_stmt, col: c_int) ?[*]const u8;
extern "c" fn sqlite3_column_blob(stmt: *sqlite3_stmt, col: c_int) ?[*]const u8;
extern "c" fn sqlite3_column_bytes(stmt: *sqlite3_stmt, col: c_int) c_int;
extern "c" fn sqlite3_column_int64(stmt: *sqlite3_stmt, col: c_int) i64;
extern "c" fn sqlite3_changes(db: *sqlite3) c_int;


const Stmt = struct {
    s: *sqlite3_stmt,

    fn bind(st: Stmt, args: anytype) void {
        inline for (args, 1..) |a, i| {
            const T = @TypeOf(a);
            switch (@typeInfo(T)) {
                .int, .comptime_int => _ = sqlite3_bind_int64(st.s, i, @intCast(a)),
                .bool => _ = sqlite3_bind_int64(st.s, i, @intFromBool(a)),
                else => {
                    const sl: []const u8 = a;
                    _ = sqlite3_bind_text(st.s, i, sl.ptr, @intCast(sl.len), SQLITE_TRANSIENT);
                },
            }
        }
    }
    fn text(st: Stmt, col: c_int) []const u8 {
        const p = sqlite3_column_text(st.s, col) orelse return "";
        return p[0..@intCast(sqlite3_column_bytes(st.s, col))];
    }
    fn int(st: Stmt, col: c_int) i64 {
        return sqlite3_column_int64(st.s, col);
    }
    fn step(st: Stmt) Error!bool {
        return switch (sqlite3_step(st.s)) {
            SQLITE_ROW => true,
            SQLITE_DONE => false,
            else => error.Sqlite,
        };
    }
    fn deinit(st: Stmt) void {
        _ = sqlite3_finalize(st.s);
    }
};

pub const Sqlite = struct {
    handle: *sqlite3,

    const schema =
        \\PRAGMA journal_mode=WAL;
        \\CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        \\CREATE TABLE IF NOT EXISTS users(
        \\  name TEXT PRIMARY KEY COLLATE NOCASE,
        \\  nt_hash BLOB NOT NULL,  -- SMB password; empty = none
        \\  web_hash TEXT NOT NULL,  -- web password; empty = none
        \\  created INTEGER NOT NULL);
        \\CREATE TABLE IF NOT EXISTS shares(
        \\  name TEXT PRIMARY KEY COLLATE NOCASE,
        \\  path TEXT NOT NULL,
        \\  comment TEXT NOT NULL DEFAULT '',
        \\  read_only INTEGER NOT NULL DEFAULT 0,
        \\  guest_ok INTEGER NOT NULL DEFAULT 0);
    ;

    pub fn open(path: [:0]const u8) Error!Sqlite {
        var h: ?*sqlite3 = null;
        if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, null) != SQLITE_OK) {
            if (h) |x| _ = sqlite3_close_v2(x);
            return error.Sqlite;
        }
        var db: Sqlite = .{ .handle = h.? };
        if (sqlite3_exec(db.handle, schema, null, null, null) != SQLITE_OK) {
            std.log.err("sqlite schema: {s}", .{sqlite3_errmsg(db.handle)});
            db.close();
            return error.Sqlite;
        }
        return db;
    }

    pub fn close(db: *Sqlite) void {
        _ = sqlite3_close_v2(db.handle);
    }

    fn prepare(db: *Sqlite, sql: []const u8) Error!Stmt {
        var s: ?*sqlite3_stmt = null;
        if (sqlite3_prepare_v2(db.handle, sql.ptr, @intCast(sql.len), &s, null) != SQLITE_OK) {
            std.log.err("sqlite prepare: {s}", .{sqlite3_errmsg(db.handle)});
            return error.Sqlite;
        }
        return .{ .s = s.? };
    }

    fn execArgs(db: *Sqlite, sql: []const u8, args: anytype) Error!usize {
        const st = try db.prepare(sql);
        defer st.deinit();
        st.bind(args);
        _ = st.step() catch {
            std.log.err("sqlite: {s}", .{sqlite3_errmsg(db.handle)});
            return error.Sqlite;
        };
        return @intCast(sqlite3_changes(db.handle));
    }

    // ------------------------------------------------------------ settings

    pub fn getSetting(db: *Sqlite, gpa: Allocator, key: []const u8) Error!?[]u8 {
        const st = try db.prepare("SELECT value FROM settings WHERE key=?");
        defer st.deinit();
        st.bind(.{key});
        if (!try st.step()) return null;
        return try gpa.dupe(u8, st.text(0));
    }

    pub fn setSetting(db: *Sqlite, key: []const u8, value: []const u8) Error!void {
        _ = try db.execArgs("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", .{ key, value });
    }

    // ------------------------------------------------------------ users

    /// NT hash for SMB logins; null for unknown users and users without one.
    pub fn ntHash(db: *Sqlite, name: []const u8) Error!?[16]u8 {
        const st = try db.prepare("SELECT nt_hash FROM users WHERE name=?");
        defer st.deinit();
        st.bind(.{name});
        if (!try st.step()) return null;
        const p = sqlite3_column_blob(st.s, 0) orelse return null;
        if (sqlite3_column_bytes(st.s, 0) != 16) return null;
        return p[0..16].*;
    }

    pub fn userAuth(db: *Sqlite, gpa: Allocator, name: []const u8) Error!?UserAuth {
        const st = try db.prepare("SELECT name, web_hash, length(nt_hash)=16 FROM users WHERE name=?");
        defer st.deinit();
        st.bind(.{name});
        if (!try st.step()) return null;
        const n = try gpa.dupe(u8, st.text(0));
        errdefer gpa.free(n);
        return .{ .name = n, .web_hash = try gpa.dupe(u8, st.text(1)), .has_smb = st.int(2) != 0 };
    }

    /// Create or update a user, setting, keeping, or clearing each password
    /// hash; a kept hash of a new user is absent.
    pub fn putUser(db: *Sqlite, name: []const u8, nt_hash: Change([16]u8), web_hash: Change([]const u8), now: i64) Error!void {
        // Unbound parameters are NULL, which keeps the stored value.
        const st = try db.prepare(
            \\INSERT INTO users(name,nt_hash,web_hash,created) VALUES(?1, coalesce(?2,x''), coalesce(?3,''), ?4)
            \\ON CONFLICT(name) DO UPDATE SET nt_hash=coalesce(?2,nt_hash), web_hash=coalesce(?3,web_hash)
        );
        defer st.deinit();
        _ = sqlite3_bind_text(st.s, 1, name.ptr, @intCast(name.len), SQLITE_TRANSIENT);
        switch (nt_hash) {
            .keep => {},
            .clear => _ = sqlite3_bind_blob(st.s, 2, "", 0, SQLITE_TRANSIENT),
            .set => |h| _ = sqlite3_bind_blob(st.s, 2, &h, 16, SQLITE_TRANSIENT),
        }
        switch (web_hash) {
            .keep => {},
            .clear => _ = sqlite3_bind_text(st.s, 3, "", 0, SQLITE_TRANSIENT),
            .set => |h| _ = sqlite3_bind_text(st.s, 3, h.ptr, @intCast(h.len), SQLITE_TRANSIENT),
        }
        _ = sqlite3_bind_int64(st.s, 4, now);
        _ = try st.step();
    }

    pub fn deleteUser(db: *Sqlite, name: []const u8) Error!bool {
        return try db.execArgs("DELETE FROM users WHERE name=?", .{name}) > 0;
    }

    /// Users who can sign in to the web console (those with a web password).
    pub fn countWebUsers(db: *Sqlite) Error!i64 {
        const st = try db.prepare("SELECT count(*) FROM users WHERE web_hash<>''");
        defer st.deinit();
        _ = try st.step();
        return st.int(0);
    }

    pub fn listUsers(db: *Sqlite, gpa: Allocator) Error![]User {
        const st = try db.prepare("SELECT name, length(nt_hash)=16, web_hash<>'', created FROM users ORDER BY name");
        defer st.deinit();
        var out: std.ArrayList(User) = .empty;
        errdefer {
            for (out.items) |u| gpa.free(u.name);
            out.deinit(gpa);
        }
        while (try st.step()) {
            try out.append(gpa, .{ .name = try gpa.dupe(u8, st.text(0)), .has_smb = st.int(1) != 0, .has_web = st.int(2) != 0, .created = st.int(3) });
        }
        return out.toOwnedSlice(gpa);
    }

    // ------------------------------------------------------------ shares

    pub fn listShares(db: *Sqlite, gpa: Allocator) Error![]Share {
        const st = try db.prepare("SELECT name, path, comment, read_only, guest_ok FROM shares ORDER BY name");
        defer st.deinit();
        var out: std.ArrayList(Share) = .empty;
        errdefer {
            for (out.items) |s| s.free(gpa);
            out.deinit(gpa);
        }
        while (try st.step()) {
            const s: Share = .{ .name = st.text(0), .path = st.text(1), .comment = st.text(2), .read_only = st.int(3) != 0, .guest_ok = st.int(4) != 0 };
            try out.append(gpa, try s.dupe(gpa));
        }
        return out.toOwnedSlice(gpa);
    }

    pub fn putShare(db: *Sqlite, s: Share) Error!void {
        _ = try db.execArgs(
            \\INSERT INTO shares(name,path,comment,read_only,guest_ok) VALUES(?,?,?,?,?)
            \\ON CONFLICT(name) DO UPDATE SET path=excluded.path, comment=excluded.comment,
            \\  read_only=excluded.read_only, guest_ok=excluded.guest_ok
        , .{ s.name, s.path, s.comment, s.read_only, s.guest_ok });
    }

    pub fn deleteShare(db: *Sqlite, name: []const u8) Error!bool {
        return try db.execArgs("DELETE FROM shares WHERE name=?", .{name}) > 0;
    }
};
