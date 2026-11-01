//! Users in a plain-text file (`--users FILE`), in place of SQLite. One user
//! per line, `name:nt_hash:web_hash`, where nt_hash is 32 hex digits and
//! web_hash an argon2id PHC string. A blank hash disables sign-in to that
//! service. The file may
//! be edited by hand; a changed file is reloaded on the next lookup. zsmbd
//! rewrites it whole, with mode 0600, because NT hashes are
//! password-equivalent.
//!
//! Callers serialize access (Db.mutex).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const db = @import("types.zig");
const tf = @import("textfile.zig");
const File = tf.File;
const Error = tf.Error;
const fail = tf.fail;
const trim = tf.trim;
const Change = db.Change;
const User = db.User;
const UserAuth = db.UserAuth;

const UserRec = struct {
    name: []u8,
    nt_hash: ?[16]u8,
    web_hash: []u8,
};

/// Users in one file.
pub const Users = struct {
    file: File,
    users: std.ArrayList(UserRec) = .empty,

    pub fn open(gpa: Allocator, io: Io, path: []const u8) Error!*Users {
        const u = try gpa.create(Users);
        errdefer gpa.destroy(u);
        u.* = .{ .file = try File.open(gpa, io, path) };
        errdefer u.close();
        try u.refresh();
        if (u.file.broken) return error.Store;
        return u;
    }

    pub fn close(u: *Users) void {
        const gpa = u.file.gpa;
        u.clear();
        u.file.close();
        gpa.destroy(u);
    }

    fn clear(u: *Users) void {
        for (u.users.items) |x| freeUser(u.file.gpa, x);
        u.users.deinit(u.file.gpa);
    }

    fn refresh(u: *Users) Error!void {
        const gpa = u.file.gpa;
        const text = try u.file.changed() orelse return;
        defer freeSecret(gpa, text);
        if (parseUsers(gpa, u.file.path, text)) |users| {
            u.clear();
            u.users = users;
            u.file.broken = false;
            if (u.file.stamp.exists) u.file.checkPrivate();
        } else |e| {
            if (e == error.OutOfMemory) return e;
            u.file.broken = true;
        }
    }

    fn commit(u: *Users) Error!void {
        const gpa = u.file.gpa;
        var out: std.ArrayList(u8) = .empty;
        defer {
            std.crypto.secureZero(u8, out.items);
            out.deinit(gpa);
        }
        try out.appendSlice(gpa,
            \\# zsmbd users, one per line: name:nt_hash:web_hash
            \\# A blank hash disables sign-in to SMB (nt_hash) or the web console (web_hash).
            \\# nt_hash is password-equivalent: keep this file private.
            \\# Use `zsmbd user` to change passwords.
            \\
        );
        for (u.users.items) |x| {
            const line = try formatLine(gpa, x.name, x.nt_hash, x.web_hash);
            defer freeSecret(gpa, line);
            try out.appendSlice(gpa, line);
        }
        try u.file.write(out.items, 0o600);
    }

    fn find(u: *Users, name: []const u8) ?usize {
        for (u.users.items, 0..) |x, i| if (std.ascii.eqlIgnoreCase(x.name, name)) return i;
        return null;
    }

    pub fn ntHash(u: *Users, name: []const u8) Error!?[16]u8 {
        try u.refresh();
        return u.users.items[u.find(name) orelse return null].nt_hash;
    }

    pub fn userAuth(u: *Users, gpa: Allocator, name: []const u8) Error!?UserAuth {
        try u.refresh();
        const x = u.users.items[u.find(name) orelse return null];
        const n = try gpa.dupe(u8, x.name);
        errdefer gpa.free(n);
        return .{ .name = n, .web_hash = try gpa.dupe(u8, x.web_hash), .has_smb = x.nt_hash != null };
    }

    /// Same rules as the SQLite store: each hash is set, kept, or cleared,
    /// and a kept hash of a new user is absent. The file keeps no creation
    /// time.
    pub fn putUser(u: *Users, name: []const u8, nt_hash: Change([16]u8), web_hash: Change([]const u8), now: i64) Error!void {
        _ = now;
        try u.refresh();
        try u.file.writable();
        const gpa = u.file.gpa;
        // The new web hash, or null to keep the old one.
        var pw: ?[]u8 = switch (web_hash) {
            .keep => null,
            .clear => try gpa.alloc(u8, 0),
            .set => |h| try gpa.dupe(u8, h),
        };
        errdefer if (pw) |p| gpa.free(p);
        const i = u.find(name) orelse blk: {
            const n = try gpa.dupe(u8, name);
            errdefer gpa.free(n);
            try u.users.append(gpa, .{ .name = n, .nt_hash = null, .web_hash = try gpa.alloc(u8, 0) });
            break :blk u.users.items.len - 1;
        };
        const x = &u.users.items[i];
        switch (nt_hash) {
            .keep => {},
            .clear => x.nt_hash = null,
            .set => |h| x.nt_hash = h,
        }
        if (pw) |p| {
            freeSecret(gpa, x.web_hash);
            x.web_hash = p;
            pw = null;
        }
        try u.commit();
    }

    pub fn deleteUser(u: *Users, name: []const u8) Error!bool {
        try u.refresh();
        try u.file.writable();
        const i = u.find(name) orelse return false;
        freeUser(u.file.gpa, u.users.orderedRemove(i));
        try u.commit();
        return true;
    }

    pub fn countWebUsers(u: *Users) Error!i64 {
        try u.refresh();
        var n: i64 = 0;
        for (u.users.items) |x| {
            if (x.web_hash.len > 0) n += 1;
        }
        return n;
    }

    pub fn listUsers(u: *Users, gpa: Allocator) Error![]User {
        try u.refresh();
        var out: std.ArrayList(User) = .empty;
        errdefer {
            for (out.items) |x| gpa.free(x.name);
            out.deinit(gpa);
        }
        for (u.users.items) |x| try out.append(gpa, .{ .name = try gpa.dupe(u8, x.name), .has_smb = x.nt_hash != null, .has_web = x.web_hash.len > 0, .created = 0 });
        std.mem.sort(User, out.items, {}, struct {
            fn lt(_: void, a: User, b: User) bool {
                return std.ascii.lessThanIgnoreCase(a.name, b.name);
            }
        }.lt);
        return out.toOwnedSlice(gpa);
    }
};

/// One users-file line, `name:nt_hash:web_hash\n`; an absent hash is blank.
pub fn formatLine(gpa: Allocator, name: []const u8, nt_hash: ?[16]u8, web_hash: []const u8) Allocator.Error![]u8 {
    const hex = if (nt_hash) |h| std.fmt.bytesToHex(h, .lower) else undefined;
    const nt: []const u8 = if (nt_hash != null) &hex else "";
    return std.fmt.allocPrint(gpa, "{s}:{s}:{s}\n", .{ name, nt, web_hash });
}

fn freeSecret(gpa: Allocator, b: []u8) void {
    std.crypto.secureZero(u8, b);
    gpa.free(b);
}

fn freeUser(gpa: Allocator, u: UserRec) void {
    gpa.free(u.name);
    freeSecret(gpa, u.web_hash);
}
fn parseUsers(gpa: Allocator, file: []const u8, text: []const u8) Error!std.ArrayList(UserRec) {
    var users: std.ArrayList(UserRec) = .empty;
    errdefer {
        for (users.items) |u| freeUser(gpa, u);
        users.deinit(gpa);
    }
    var it = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (it.next()) |raw| {
        n += 1;
        const l = trim(raw);
        if (l.len == 0 or l[0] == '#') continue;
        var f: [3][]const u8 = undefined;
        var fields = std.mem.splitScalar(u8, l, ':');
        for (&f) |*x| x.* = trim(fields.next() orelse return fail("{s}:{d}: expected name:nt_hash:web_hash", .{ file, n }));
        if (fields.next() != null or f[0].len == 0) return fail("{s}:{d}: expected name:nt_hash:web_hash", .{ file, n });
        var nt: ?[16]u8 = null;
        if (f[1].len != 0) {
            var h: [16]u8 = undefined;
            if (f[1].len != 32) return fail("{s}:{d}: nt_hash is 32 hex digits", .{ file, n });
            _ = std.fmt.hexToBytes(&h, f[1]) catch return fail("{s}:{d}: nt_hash is 32 hex digits", .{ file, n });
            nt = h;
        }
        for (users.items) |u| if (std.ascii.eqlIgnoreCase(u.name, f[0])) return fail("{s}:{d}: user {s} appears twice", .{ file, n, f[0] });
        const name = try gpa.dupe(u8, f[0]);
        errdefer gpa.free(name);
        const pw = try gpa.dupe(u8, f[2]);
        errdefer gpa.free(pw);
        try users.append(gpa, .{ .name = name, .nt_hash = nt, .web_hash = pw });
    }
    return users;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const tmpPath = tf.tmpPath;
const readBack = tf.readBack;

test "users file round trip and outside edits" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    // The directory is created when missing.
    const u = try Users.open(testing.allocator, testing.io, try tmpPath(&tmp, &buf, "etc/users"));
    defer u.close();

    const h: [16]u8 = @splat(0xab);
    try u.putUser("hal", .{ .set = h }, .keep, 100);
    try u.putUser("admin", .keep, .{ .set = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA" }, 101);
    try testing.expectEqual(h, (try u.ntHash("HAL")).?);
    try testing.expectEqual(null, try u.ntHash("admin"));
    try testing.expectEqual(@as(i64, 1), try u.countWebUsers());
    // Keeping a hash leaves it; clearing one removes it.
    try u.putUser("admin", .{ .set = h }, .keep, 0);
    try testing.expectEqual(@as(i64, 1), try u.countWebUsers());
    try u.putUser("admin", .clear, .clear, 0);
    try testing.expectEqual(@as(i64, 0), try u.countWebUsers());
    try testing.expectEqual(null, try u.ntHash("admin"));

    const st = try tmp.dir.statFile(testing.io, "etc/users", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);

    // A hand edit is picked up on the next lookup.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "etc/users", .data = "art:00112233445566778899aabbccddeeff:$argon2id$x\n" });
    try testing.expectEqual(null, try u.ntHash("hal"));
    try testing.expect((try u.ntHash("art")) != null);
    const users = try u.listUsers(testing.allocator);
    defer db.freeUsers(testing.allocator, users);
    try testing.expectEqual(@as(usize, 1), users.len);
    try testing.expect(users[0].has_smb and users[0].has_web);

    // Blank hashes disable that service.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "etc/users", .data = "hal:00112233445566778899aabbccddeeff:\nadmin::$argon2id$x\nart::\n" });
    try testing.expect((try u.ntHash("hal")) != null);
    try testing.expectEqual(null, try u.ntHash("admin"));
    try testing.expectEqual(null, try u.ntHash("art"));
    try testing.expectEqual(@as(i64, 1), try u.countWebUsers());
    const art = (try u.userAuth(testing.allocator, "art")).?;
    defer art.free(testing.allocator);
    try testing.expect(!art.has_smb and art.web_hash.len == 0);
    const hal = (try u.userAuth(testing.allocator, "hal")).?;
    defer hal.free(testing.allocator);
    try testing.expect(hal.has_smb and hal.web_hash.len == 0);

    // A broken edit keeps the last good users and blocks changes.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "etc/users", .data = "skynet:overlord:x\n" });
    try testing.expect((try u.ntHash("hal")) != null);
    try testing.expectError(error.Store, u.putUser("skynet", .{ .set = h }, .keep, 0));
    const kept = try readBack(&tmp, "etc/users");
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("skynet:overlord:x\n", kept);
}

test "fuzz: users file parsing" {
    try @import("../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            var users = parseUsers(testing.allocator, "fuzz.users", in) catch return;
            defer {
                for (users.items) |u| freeUser(testing.allocator, u);
                users.deinit(testing.allocator);
            }
            for (users.items) |u| try testing.expect(u.name.len > 0);
        }
    }.one, &.{ "# h\nhal:00112233445566778899aabbccddeeff:\nadmin::$argon2id$x\n", "art:00112233445566778899AABBCCDDEEFF:$a\n" });
}
