//! The ephemeral shares and logins `serve` takes on its command line and
//! stdin (`--share`, `--user`, `--smb-user`, `--web-user`, `--users -`):
//! parsed, validated like `share add` and `user add`, merged per login, and
//! handed to the store's ephemeral layer. Specs may carry secrets: callers
//! wipe them after parsing.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const crypto = @import("../shared/crypto.zig");
const strength = @import("strength.zig");
const store = @import("../store/store.zig");
const Share = store.Share;

pub const Service = enum { smb, web };

/// One login, with the hashes of each service it may use.
pub const Login = struct {
    name: []u8,
    nt_hash: ?[16]u8 = null,
    /// argon2id PHC string; empty without a web password.
    web_hash: []u8,
};

pub const Spec = struct {
    gpa: Allocator,
    logins: std.ArrayList(Login) = .empty,
    shares: std.ArrayList(Share) = .empty,

    pub fn init(gpa: Allocator) Spec {
        return .{ .gpa = gpa };
    }

    pub fn deinit(s: *Spec) void {
        for (s.logins.items) |l| {
            s.gpa.free(l.name);
            std.crypto.secureZero(u8, l.web_hash);
            s.gpa.free(l.web_hash);
        }
        s.logins.deinit(s.gpa);
        for (s.shares.items) |x| x.free(s.gpa);
        s.shares.deinit(s.gpa);
    }

    /// `NAME:PATH[:OPTIONS[:TEXT]]`: OPTIONS is a comma-separated list of
    /// `ro`, `rw`, `guest`, and `noguest`; TEXT is the comment, and may
    /// contain colons. A share name may be given once.
    pub fn addShare(s: *Spec, spec: []const u8) !void {
        var it = std.mem.splitScalar(u8, spec, ':');
        const name = it.first();
        const path = it.next() orelse return error.InvalidShareSpec;
        const options = it.next() orelse "";
        const text = it.rest();
        if (path.len == 0) return error.InvalidShareSpec;
        // A relative path means relative to where `serve` started.
        const resolved = if (path[0] == '/') null else try resolveFromCwd(s.gpa, path);
        defer if (resolved) |r| s.gpa.free(r);
        var share: Share = .{ .name = name, .path = resolved orelse path, .comment = text };
        if (options.len > 0) {
            var opts = std.mem.splitScalar(u8, options, ',');
            while (opts.next()) |o| {
                if (std.mem.eql(u8, o, "ro")) share.read_only = true //
                else if (std.mem.eql(u8, o, "rw")) share.read_only = false //
                else if (std.mem.eql(u8, o, "guest")) share.guest_ok = true //
                else if (std.mem.eql(u8, o, "noguest")) share.guest_ok = false //
                else return error.InvalidOption;
            }
        }
        try auth.validateShareName(name);
        try auth.validateSharePath(s.gpa, share.path);
        try auth.validateComment(text);
        for (s.shares.items) |x| if (std.ascii.eqlIgnoreCase(x.name, name)) return error.DuplicateShare;
        const copy = try share.dupe(s.gpa);
        errdefer copy.free(s.gpa);
        try s.shares.append(s.gpa, copy);
    }

    /// `path` made absolute against the current directory, `.` and `..` folded.
    fn resolveFromCwd(gpa: Allocator, path: []const u8) ![]u8 {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const cwd = std.c.getcwd(&buf, buf.len) orelse return error.PathNotDirectory;
        return std.fs.path.resolve(gpa, &.{ std.mem.sliceTo(cwd, 0), path });
    }

    /// One users-file line, `LOGIN:NT_HASH:WEB_HASH` (`--user`).
    pub fn addLine(s: *Spec, line: []const u8) !void {
        if (std.mem.indexOfScalar(u8, line, '\n') != null) return error.InvalidLogin;
        try s.addText("--user", line, true);
    }

    /// Users-file text, one login per line (stdin). `file` names it in
    /// error messages.
    pub fn addText(s: *Spec, file: []const u8, text: []const u8, single: bool) !void {
        var recs = store.parseUsers(s.gpa, file, text) catch |e| return if (e == error.OutOfMemory) e else error.InvalidLogin;
        defer {
            for (recs.items) |r| store.freeUserRec(s.gpa, r);
            recs.deinit(s.gpa);
        }
        if (single and recs.items.len != 1) return error.InvalidLogin;
        for (recs.items) |r| {
            try auth.validateUserName(r.name);
            _ = try s.merge(r.name, r.nt_hash, r.web_hash);
        }
    }

    /// `LOGIN:PASSWORD` for one service (`--smb-user`, `--web-user`); the
    /// password follows the first colon. Returns the warnings about it.
    pub fn addPassword(s: *Spec, io: Io, spec: []const u8, service: Service) !auth.Warnings {
        const colon = std.mem.indexOfScalar(u8, spec, ':') orelse return error.InvalidLogin;
        const name = spec[0..colon];
        const pw = spec[colon + 1 ..];
        try auth.validateUserName(name);
        try auth.validatePassword(pw);
        var warnings: auth.Warnings = .empty;
        const weak = strength.estimate(pw).level == .weak;
        const login = switch (service) {
            .smb => blk: {
                if (weak) warnings.insert(.weak_smb);
                break :blk try s.merge(name, try crypto.ntHash(s.gpa, pw), "");
            },
            .web => blk: {
                if (weak) warnings.insert(.weak_web);
                const phc = try auth.hashPassword(s.gpa, io, pw);
                defer s.gpa.free(phc);
                break :blk try s.merge(name, null, phc);
            },
        };
        // The other service's password, if given, may be the same.
        const same = switch (service) {
            .smb => login.web_hash.len > 0 and auth.verifyPassword(s.gpa, io, login.web_hash, pw),
            .web => if (login.nt_hash) |nt| std.crypto.timing_safe.eql([16]u8, nt, try crypto.ntHash(s.gpa, pw)) else false,
        };
        if (same) warnings.insert(.same_password);
        return warnings;
    }

    /// Adds the hashes to the login `name` (created if new); a hash already
    /// there for the same service is `error.DuplicateLogin`.
    fn merge(s: *Spec, name: []const u8, nt: ?[16]u8, web: []const u8) !*const Login {
        const l: *Login = for (s.logins.items) |*x| {
            if (std.ascii.eqlIgnoreCase(x.name, name)) break x;
        } else blk: {
            const n = try s.gpa.dupe(u8, name);
            errdefer s.gpa.free(n);
            const w = try s.gpa.alloc(u8, 0);
            errdefer s.gpa.free(w);
            try s.logins.append(s.gpa, .{ .name = n, .web_hash = w });
            break :blk &s.logins.items[s.logins.items.len - 1];
        };
        if (nt != null and l.nt_hash != null) return error.DuplicateLogin;
        if (web.len > 0 and l.web_hash.len > 0) return error.DuplicateLogin;
        if (nt) |h| l.nt_hash = h;
        if (web.len > 0) {
            const w = try s.gpa.dupe(u8, web);
            s.gpa.free(l.web_hash);
            l.web_hash = w;
        }
        return l;
    }

    /// Hands every share and login to the store's ephemeral layer.
    pub fn apply(s: *const Spec, db: *store.Db) !void {
        for (s.shares.items) |x| try db.addEphemeralShare(s.gpa, x);
        for (s.logins.items) |l| try db.addEphemeralUser(s.gpa, l.name, l.nt_hash, l.web_hash);
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const hash_a = "00112233445566778899aabbccddeeff";
const argon_a = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";

test "share specs" {
    var s: Spec = .init(testing.allocator);
    defer s.deinit();
    try s.addShare("docs:/:ro,guest:Team: files");
    try s.addShare("plain:/");
    try s.addShare("rw:/:rw");
    const d = s.shares.items[0];
    try testing.expectEqualStrings("docs", d.name);
    try testing.expectEqualStrings("Team: files", d.comment);
    try testing.expect(d.read_only and d.guest_ok);
    try testing.expect(!s.shares.items[1].read_only and !s.shares.items[1].guest_ok);
    try testing.expectEqualStrings("", s.shares.items[1].comment);
    try testing.expectError(error.DuplicateShare, s.addShare("DOCS:/"));
    try testing.expectError(error.InvalidShareSpec, s.addShare("nopath"));
    try testing.expectError(error.InvalidOption, s.addShare("x:/:ro,"));
    try testing.expectError(error.InvalidOption, s.addShare("x:/:readonly"));
    try testing.expectError(error.InvalidShareName, s.addShare(":/"));
    try testing.expectError(error.ReservedShareName, s.addShare("IPC$:/"));
    try testing.expectError(error.InvalidShareSpec, s.addShare("x:"));
    try testing.expectError(error.PathNotDirectory, s.addShare("x:no/such/dir"));
    // A relative path is made absolute against the current directory.
    try s.addShare("here:.");
    try s.addShare("up:../");
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = std.mem.sliceTo(std.c.getcwd(&buf, buf.len).?, 0);
    try testing.expectEqualStrings(cwd, s.shares.items[3].path);
    try testing.expectEqualStrings(std.fs.path.dirname(cwd) orelse "/", s.shares.items[4].path);
    try testing.expectError(error.PathNotDirectory, s.addShare("x:/nonexistent/skynet"));
    try testing.expectError(error.InvalidComment, s.addShare("x:/:ro:bad\x01"));
    try testing.expectEqual(@as(usize, 5), s.shares.items.len);
}

test "login lines and merging by service" {
    var s: Spec = .init(testing.allocator);
    defer s.deinit();
    try s.addLine("hal:" ++ hash_a ++ ":");
    // The blank web side stays free for the other flag.
    try s.addLine("HAL::" ++ argon_a);
    try testing.expectEqual(@as(usize, 1), s.logins.items.len);
    try testing.expect(s.logins.items[0].nt_hash != null and s.logins.items[0].web_hash.len > 0);
    try testing.expectError(error.DuplicateLogin, s.addLine("hal:" ++ hash_a ++ ":"));
    try testing.expectError(error.DuplicateLogin, s.addLine("hal::" ++ argon_a));
    try testing.expectError(error.InvalidLogin, s.addLine("art"));
    try testing.expectError(error.InvalidLogin, s.addLine("art:zz:"));
    try testing.expectError(error.InvalidLogin, s.addLine("a:" ++ hash_a ++ ":\nb::"));
    try testing.expectError(error.InvalidLogin, s.addLine("# only a comment"));
    try testing.expectError(error.InvalidUserName, s.addLine("a@b::"));
    try s.addText("stdin", "# users\nart:" ++ hash_a ++ ":\nskynet::" ++ argon_a ++ "\n", false);
    try testing.expectEqual(@as(usize, 3), s.logins.items.len);
}

test "passwords are hashed, merged, and checked for reuse" {
    var s: Spec = .init(testing.allocator);
    defer s.deinit();
    const w1 = try s.addPassword(testing.io, "hal:a-long-and-unusual passphrase 1", .smb);
    try testing.expect(w1.count() == 0);
    const nt = s.logins.items[0].nt_hash.?;
    try testing.expectEqual(try crypto.ntHash(testing.allocator, "a-long-and-unusual passphrase 1"), nt);
    // The password may contain colons; a second flag for the same service is refused.
    try testing.expectError(error.DuplicateLogin, s.addPassword(testing.io, "hal:x:y", .smb));
    const w2 = try s.addPassword(testing.io, "HAL:a-long-and-unusual passphrase 1", .web);
    try testing.expect(w2.contains(.same_password));
    try testing.expect(s.logins.items[0].web_hash.len > 0 and s.logins.items.len == 1);
    const w3 = try s.addPassword(testing.io, "art:pw", .smb);
    try testing.expect(w3.contains(.weak_smb));
    try testing.expectError(error.InvalidLogin, s.addPassword(testing.io, "nocolon", .web));
    try testing.expectError(error.EmptyPassword, s.addPassword(testing.io, "art:", .web));
    try testing.expectError(error.InvalidUserName, s.addPassword(testing.io, ":pw", .web));
}

test "applied entries shadow stored ones and change like stored ones" {
    var db = try store.Db.open(testing.io, ":memory:");
    defer db.close();
    try db.putShare(.{ .name = "docs", .path = "/tmp" });
    try db.putShare(.{ .name = "kept", .path = "/tmp" });
    try db.putUser("hal", .{ .set = @splat(1) }, .keep, 1);
    try db.putUser("art", .keep, .{ .set = argon_a }, 1);

    var s: Spec = .init(testing.allocator);
    defer s.deinit();
    try s.addShare("DOCS:/:ro");
    try s.addLine("hal::" ++ argon_a);
    try s.apply(&db);

    const shares = try db.listShares(testing.allocator);
    defer store.freeShares(testing.allocator, shares);
    try testing.expectEqual(@as(usize, 2), shares.len);
    for (shares) |x| try testing.expectEqual(std.ascii.eqlIgnoreCase(x.name, "docs"), x.ephemeral and x.read_only);
    // hal's stored SMB hash is hidden; the ephemeral login has none.
    try testing.expectEqual(null, try db.ntHash("hal"));
    try testing.expect(db.isEphemeralUser("HAL") and !db.isEphemeralUser("art"));
    const users = try db.listUsers(testing.allocator);
    defer store.freeUsers(testing.allocator, users);
    try testing.expectEqual(@as(usize, 2), users.len);
    try testing.expectEqualStrings("art", users[0].name);
    try testing.expect(!users[0].ephemeral and users[1].ephemeral and users[1].has_web and !users[1].has_smb);

    // An ephemeral share edits in place and stays ephemeral; deleting it
    // reveals the stored share it hid.
    try testing.expect(db.isEphemeralShare("DOCS"));
    try db.putShare(.{ .name = "docs", .path = "/", .comment = "edited" });
    const edited = try db.listShares(testing.allocator);
    defer store.freeShares(testing.allocator, edited);
    for (edited) |x| if (std.ascii.eqlIgnoreCase(x.name, "docs")) {
        try testing.expect(x.ephemeral and !x.read_only);
        try testing.expectEqualStrings("edited", x.comment);
        try testing.expectEqualStrings("/", x.path);
    };
    try testing.expect(try db.deleteShare("Docs"));
    try testing.expect(!db.isEphemeralShare("docs"));
    const revealed = try db.listShares(testing.allocator);
    defer store.freeShares(testing.allocator, revealed);
    for (revealed) |x| try testing.expect(!x.ephemeral);
    try testing.expectEqual(@as(usize, 2), revealed.len);
    // Passwords of an ephemeral user change, in memory, with a warning; the
    // stored user of that name stays hidden and untouched.
    const ws = try auth.grantPasswords(testing.allocator, testing.io, &db, "hal", .{ .smb = "a long and unusual passphrase 3" });
    try testing.expect(ws.contains(.ephemeral));
    try testing.expect((try db.ntHash("hal")) != null);
    try auth.revokePasswords(testing.allocator, testing.io, &db, "hal", true, false);
    try testing.expectEqual(null, try db.ntHash("hal"));
    // hal's web login may go while another (stored) login remains, but the
    // last login of either kind may not.
    try auth.revokePasswords(testing.allocator, testing.io, &db, "hal", false, true);
    try testing.expectEqual(@as(i64, 1), try db.countWebLogins());
    try testing.expect(!db.hasEphemeralWebLogin());
    // Deleting the ephemeral user reveals the stored one it hid.
    try auth.deleteUser(testing.allocator, &db, "hal");
    try testing.expect(!db.isEphemeralUser("hal"));
    try testing.expect((try db.ntHash("hal")) != null);
    // Stored entries still change, and the guard counts stored web users only.
    try testing.expect(try db.deleteShare("kept"));
    try testing.expectEqual(@as(i64, 1), try db.countWebUsers());
    try testing.expectError(error.LastWebUser, auth.deleteUser(testing.allocator, &db, "art"));
}

test "users from stdin are the only users" {
    var db = try store.Db.open(testing.io, ":memory:");
    defer db.close();
    try db.putUser("old", .{ .set = @splat(1) }, .keep, 1);
    db.users_stdin = true;
    var s: Spec = .init(testing.allocator);
    defer s.deinit();
    try s.addText("stdin", "art:" ++ hash_a ++ ":\n", false);
    try s.apply(&db);
    try testing.expectEqual(null, try db.ntHash("old"));
    try testing.expect((try db.ntHash("ART")) != null);
    try testing.expectEqual(@as(i64, 0), try db.countWebUsers());
    // With `--users -` every user lives in memory: new ones are made there,
    // and any of them changes or goes like a stored user would.
    try db.putUser("new", .{ .set = @splat(2) }, .keep, 1);
    try testing.expect(db.isEphemeralUser("new") and (try db.ntHash("new")) != null);
    try db.putUser("art", .clear, .keep, 1);
    try testing.expectEqual(null, try db.ntHash("art"));
    try testing.expect(try db.deleteUser("new"));
    try testing.expect(!try db.deleteUser("new"));
    try testing.expect(!try db.deleteUser("old"));
    // No web login on stdin: bootstrap makes an ephemeral, web-only admin.
    try testing.expect(!db.hasEphemeralWebLogin());
    var pw: [16]u8 = undefined;
    const b = (try auth.bootstrap(testing.allocator, testing.io, &db, &pw)).?;
    try testing.expect(b.ephemeral and db.isEphemeralUser("admin") and db.hasEphemeralWebLogin());
    const admin = (try db.userAuth(testing.allocator, "admin")).?;
    defer admin.free(testing.allocator);
    try testing.expect(admin.web_hash.len > 0 and !admin.has_smb);
    try testing.expectEqual(null, try db.ntHash("admin"));
    try testing.expectEqual(null, try auth.bootstrap(testing.allocator, testing.io, &db, &pw));
    // The ephemeral admin is the only web login: its password can change but not go.
    try testing.expectError(error.LastWebUser, auth.revokePasswords(testing.allocator, testing.io, &db, "admin", false, true));
    const ws = try auth.grantPasswords(testing.allocator, testing.io, &db, "admin", .{ .web = "another long and unusual passphrase 5" });
    try testing.expect(ws.contains(.ephemeral));
    const users = try db.listUsers(testing.allocator);
    defer store.freeUsers(testing.allocator, users);
    try testing.expectEqual(@as(usize, 2), users.len);
}

test "in-memory mode makes an ephemeral admin unless the name is taken" {
    var db = try store.Db.open(testing.io, ":memory:");
    defer db.close();
    db.ephemeral_only = true;
    var s: Spec = .init(testing.allocator);
    defer s.deinit();
    try s.addLine("admin:" ++ hash_a ++ ":");
    try s.apply(&db);
    var pw: [16]u8 = undefined;
    // An SMB-only ephemeral admin can't gain a password, so none is made.
    try testing.expectEqual(null, try auth.bootstrap(testing.allocator, testing.io, &db, &pw));
    var db2 = try store.Db.open(testing.io, ":memory:");
    defer db2.close();
    db2.ephemeral_only = true;
    const b = (try auth.bootstrap(testing.allocator, testing.io, &db2, &pw)).?;
    try testing.expect(b.ephemeral);
    try testing.expectEqual(@as(i64, 0), try db2.countWebUsers());
}

test "fuzz: ephemeral login and share specs" {
    try @import("../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            var s: Spec = .init(testing.allocator);
            defer s.deinit();
            s.addShare(in) catch {};
            s.addLine(in) catch {};
            s.addText("fuzz", in, false) catch {};
            // Passwords are hashed with argon2id; the fuzz run keeps to the SMB side.
            _ = s.addPassword(testing.io, in, .smb) catch {};
            for (s.logins.items) |l| try testing.expect(l.name.len > 0);
            for (s.shares.items) |x| try testing.expect(x.name.len > 0 and x.path.len > 0 and x.path[0] == '/');
        }
    }.one, &.{ "docs:/:ro,guest:Team: files", "hal:00112233445566778899aabbccddeeff:", "hal:a:b:c", "a::$argon2id$x\nb:00112233445566778899aabbccddeeff:" });
}
