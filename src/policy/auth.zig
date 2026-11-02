//! User/share management shared by the CLI and the admin web server:
//! password hashing, input validation and first-run bootstrap.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const argon2 = std.crypto.pwhash.argon2;
const db_mod = @import("../store/store.zig");
const Db = db_mod.Db;
const crypto = @import("../shared/crypto.zig");
const strength = @import("strength.zig");

/// OWASP-recommended argon2id baseline: t=2, m=19 MiB, p=1.
const argon_params = argon2.Params.fromLimits(2, 19 * 1024 * 1024);


pub fn hashPassword(gpa: Allocator, io: Io, password: []const u8) ![]u8 {
    var buf: [128]u8 = undefined;
    const s = try argon2.strHash(password, .{ .allocator = gpa, .params = argon_params, .mode = .argon2id }, &buf, io);
    return gpa.dupe(u8, s);
}

pub fn verifyPassword(gpa: Allocator, io: Io, phc: []const u8, password: []const u8) bool {
    argon2.strVerify(phc, password, .{ .allocator = gpa }, io) catch return false;
    return true;
}

pub const ValidationError = error{
    InvalidUserName,
    EmptyPassword,
    InvalidShareName,
    ReservedShareName,
    PathNotAbsolute,
    PathNotDirectory,
    InvalidPath,
    InvalidComment,
    InvalidSetting,
};

pub fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidUserName => "user names are 1-64 characters and may not contain \\ / : @ \" or control characters",
        error.EmptyPassword => "a password can't be empty",
        error.InvalidShareName => "share names are 1-80 characters and may not contain \\ / : * ? \" < > | or control characters",
        error.ReservedShareName => "IPC$ is reserved",
        error.PathNotAbsolute => "the share path must be absolute",
        error.PathNotDirectory => "the share path must be an existing directory",
        error.InvalidPath => "the share path may not contain control characters",
        error.InvalidComment => "share comments are at most 256 characters, without control characters",
        error.InvalidSetting => "unknown setting or invalid value",
        error.InvalidPassword => "give the SMB password either as a password or as a 32-digit hex NT hash, not both",
        error.InvalidNtHash => "an NT hash is 32 hexadecimal digits",
        error.NotFound => "not found",
        error.Store => "a configuration or users file has errors (see above)",
        error.WebOff => "web passwords need the web console: add --web PORT",
        error.InvalidShareSpec => "expected NAME:PATH[:OPTIONS[:TEXT]]",
        error.InvalidOption => "share options are ro, rw, guest, and noguest, separated by commas",
        error.InvalidLogin => "expected LOGIN:NT_HASH:WEB_HASH, or LOGIN:PASSWORD",
        error.DuplicateLogin => "a login may be given once for SMB and once for the web console",
        error.DuplicateShare => "a share name may be given once",
        error.UserExists => "user exists; set its passwords with `user passwd [--web]`",
        else => @errorName(err),
    };
}

fn hasBadChar(s: []const u8, bad: []const u8) bool {
    for (s) |ch| {
        if (ch < 0x20 or ch == 0x7f) return true;
        if (std.mem.indexOfScalar(u8, bad, ch) != null) return true;
    }
    return false;
}

pub fn validateUserName(name: []const u8) ValidationError!void {
    if (name.len == 0 or name.len > 64 or hasBadChar(name, "\\/:@\"") or !std.unicode.utf8ValidateSlice(name))
        return error.InvalidUserName;
}

/// Strength is reported (see `Warning.weak_smb`), never enforced.
pub fn validatePassword(pw: []const u8) ValidationError!void {
    if (pw.len == 0) return error.EmptyPassword;
}

pub fn validateShareName(name: []const u8) ValidationError!void {
    if (name.len == 0 or name.len > 80 or hasBadChar(name, "\\/:*?\"<>|") or !std.unicode.utf8ValidateSlice(name))
        return error.InvalidShareName;
    if (std.ascii.eqlIgnoreCase(name, "IPC$")) return error.ReservedShareName;
}

pub fn validateComment(comment: []const u8) ValidationError!void {
    if (comment.len > 256 or hasBadChar(comment, "") or !std.unicode.utf8ValidateSlice(comment)) return error.InvalidComment;
}

/// Checks that `path` is an absolute path to an existing directory.
pub fn validateSharePath(gpa: Allocator, path: []const u8) !void {
    if (path.len == 0 or path[0] != '/') return error.PathNotAbsolute;
    if (hasBadChar(path, "")) return error.InvalidPath;
    const z = try gpa.dupeSentinel(u8, path, 0);
    defer gpa.free(z);
    // Opening it as a directory both checks that it exists and its type.
    const fd = std.c.openat(std.c.AT.FDCWD, z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, @as(c_uint, 0));
    if (fd < 0) return error.PathNotDirectory;
    _ = std.c.close(fd);
}

// ---------------------------------------------------------------- settings

pub const Setting = struct {
    key: []const u8,
    kind: enum { text, boolean },
    default: []const u8,
    help: []const u8,
};

/// The complete list of server settings. Everything else has a fixed default.
pub const settings = [_]Setting{
    .{ .key = "server_name", .kind = .text, .default = "", .help = "NetBIOS name shown to clients (default: host name, max 15 characters)" },
    .{ .key = "workgroup", .kind = .text, .default = "WORKGROUP", .help = "Workgroup / domain name shown to clients" },
    .{ .key = "signing_required", .kind = .boolean, .default = "true", .help = "Require message signing (recommended; required by Windows 11 24H2)" },
    .{ .key = "encrypt", .kind = .boolean, .default = "false", .help = "Require SMB 3 encryption for all sessions" },
};

pub fn findSetting(key: []const u8) ?Setting {
    for (settings) |s| if (std.mem.eql(u8, s.key, key)) return s;
    return null;
}

/// yes, true, or 1; no, false, or 0 (case-insensitive).
pub fn parseBool(value: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(value, "true") or std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(value, "false") or std.mem.eql(u8, value, "0") or std.ascii.eqlIgnoreCase(value, "no")) return false;
    return null;
}

/// Validates and normalizes a setting value (booleans become "true"/"false").
pub fn normalizeSetting(key: []const u8, value: []const u8) ValidationError![]const u8 {
    const s = findSetting(key) orelse return error.InvalidSetting;
    switch (s.kind) {
        .boolean => {
            const b = parseBool(value) orelse return error.InvalidSetting;
            return if (b) "true" else "false";
        },
        .text => {
            if (hasBadChar(value, "\\/:*?\"<>|")) return error.InvalidSetting;
            if (std.mem.eql(u8, key, "server_name") and value.len > 15) return error.InvalidSetting;
            if (value.len > 64) return error.InvalidSetting;
            return value;
        },
    }
}

// ---------------------------------------------------------------- users

pub fn nowSeconds(io: Io) i64 {
    return Io.Clock.real.now(io).toSeconds();
}

/// What a user may sign in to, as `user list` and the web API show it, named
/// like the `user passwd` flags: "smb", "web", "both", or "none".
pub fn accessName(has_smb: bool, has_web: bool) []const u8 {
    if (has_smb and has_web) return "both";
    if (has_smb) return "smb";
    return if (has_web) "web" else "none";
}

/// Passwords to set; null means unchanged. SMB passwords are stored as the
/// NT hash NTLM needs and web passwords as argon2id; they are never the same
/// secret by design, so a web login sent over the network does not reveal SMB
/// credentials. The SMB password may instead arrive already hashed
/// (`nt_hash`), as the web page does when it can hash in the browser.
pub const Passwords = struct {
    smb: ?[]const u8 = null,
    nt_hash: ?[16]u8 = null,
    web: ?[]const u8 = null,

    pub fn hasSmb(pw: Passwords) bool {
        return pw.smb != null or pw.nt_hash != null;
    }
};

/// Password hygiene warnings. The operation they come from still succeeds.
pub const Warning = enum {
    both_passwords,
    same_password,
    weak_smb,
    weak_web,
    ephemeral,

    pub fn text(w: Warning) []const u8 {
        return switch (w) {
            .weak_smb => "the SMB password is weak: a longer passphrase is much harder to guess",
            .weak_web => "the web password is weak: a longer passphrase is much harder to guess",
            .both_passwords => "users with both passwords sign in to SMB and the web console: give them different passwords, and keep the web console on localhost or behind TLS",
            .ephemeral => "this entry is ephemeral: the change lasts only until zsmbd exits",
            .same_password => "the SMB and web passwords are identical: anyone who captures the web login can also connect over SMB; set different passwords",
        };
    }
};

pub const Warnings = std.EnumSet(Warning);

/// Create a user with no passwords, who can't sign in until one is set.
pub fn addUser(io: Io, db: *Db, name: []const u8) !void {
    try validateUserName(name);
    try db.putUser(name, .keep, .keep, nowSeconds(io));
}

/// Set any of a user's passwords; returns the hygiene warnings, judged
/// against the stored passwords before the write.
pub fn grantPasswords(gpa: Allocator, io: Io, db: *Db, name: []const u8, pw: Passwords) !Warnings {
    if (pw.smb != null and pw.nt_hash != null) return error.InvalidPassword;
    if (pw.smb) |p| try validatePassword(p);
    if (pw.web) |p| try validatePassword(p);
    const u = (try db.userAuth(gpa, name)) orelse return error.NotFound;
    defer u.free(gpa);
    var warnings: Warnings = .empty;
    if (db.isEphemeralUser(u.name)) warnings.insert(.ephemeral);
    if (!pw.hasSmb() and pw.web == null) return warnings;
    // Only plaintext can be rated; a pre-hashed password was rated in the browser.
    if (pw.smb) |p| if (strength.estimate(p).level == .weak) warnings.insert(.weak_smb);
    if (pw.web) |p| if (strength.estimate(p).level == .weak) warnings.insert(.weak_web);
    if ((pw.hasSmb() or u.has_smb) and (pw.web != null or u.web_hash.len > 0)) {
        warnings.insert(.both_passwords);
        const same = blk: {
            if (pw.web) |w| {
                if (pw.smb) |p| break :blk std.mem.eql(u8, p, w);
                const stored_nt = pw.nt_hash orelse (try db.ntHash(u.name)) orelse break :blk false;
                break :blk std.crypto.timing_safe.eql([16]u8, stored_nt, try crypto.ntHash(gpa, w));
            }
            if (pw.smb) |p| break :blk u.web_hash.len > 0 and verifyPassword(gpa, io, u.web_hash, p);
            // A pre-hashed SMB password can't be checked against argon2id.
            break :blk false;
        };
        if (same) warnings.insert(.same_password);
    }
    const nt: ?[16]u8 = if (pw.smb) |p| try crypto.ntHash(gpa, p) else pw.nt_hash;
    const phc: ?[]u8 = if (pw.web) |p| try hashPassword(gpa, io, p) else null;
    defer if (phc) |h| gpa.free(h);
    try db.putUser(u.name, if (nt) |h| .{ .set = h } else .keep, if (phc) |h| .{ .set = h } else .keep, nowSeconds(io));
    return warnings;
}

/// Clear a user's SMB password, web password, or both, closing those
/// services to them.
pub fn revokePasswords(gpa: Allocator, io: Io, db: *Db, name: []const u8, smb: bool, web: bool) !void {
    const u = (try db.userAuth(gpa, name)) orelse return error.NotFound;
    defer u.free(gpa);
    try db.putUser(u.name, if (smb) .clear else .keep, if (web) .clear else .keep, nowSeconds(io));
}

/// Delete a user.
pub fn deleteUser(gpa: Allocator, db: *Db, name: []const u8) !void {
    const u = (try db.userAuth(gpa, name)) orelse return error.NotFound;
    defer u.free(gpa);
    _ = try db.deleteUser(name);
}

/// Hash passwords without a store, for a users file on another machine
/// (`zsmbd hash`). Supplied passwords must be non-empty; the caller frees
/// `web`. Only the identical-passwords warning applies: strength is rated as
/// passwords are read.
pub fn hashPasswords(gpa: Allocator, io: Io, pw: Passwords) !struct { nt: ?[16]u8, web: ?[]u8, same: bool } {
    if (pw.smb) |p| try validatePassword(p);
    if (pw.web) |p| try validatePassword(p);
    const same = pw.smb != null and pw.web != null and std.mem.eql(u8, pw.smb.?, pw.web.?);
    return .{
        .nt = if (pw.smb) |p| try crypto.ntHash(gpa, p) else null,
        .web = if (pw.web) |p| try hashPassword(gpa, io, p) else null,
        .same = same,
    };
}

/// Spend the time of a password check, so a failure takes as long whether
/// or not the user exists or has web access.
fn burnHash(gpa: Allocator, io: Io, password: []const u8) !void {
    const dummy = try hashPassword(gpa, io, password);
    gpa.free(dummy);
}

/// Returns the canonical user name when `password` is the user's web password.
pub fn checkWebLogin(gpa: Allocator, io: Io, db: *Db, name: []const u8, password: []const u8) !?[]u8 {
    const u = (try db.userAuth(gpa, name)) orelse {
        try burnHash(gpa, io, password);
        return null;
    };
    defer gpa.free(u.web_hash);
    errdefer gpa.free(u.name);
    if (u.web_hash.len == 0) {
        try burnHash(gpa, io, password);
        gpa.free(u.name);
        return null;
    }
    if (!verifyPassword(gpa, io, u.web_hash, password)) {
        gpa.free(u.name);
        return null;
    }
    return u.name;
}

/// Random password from an unambiguous alphabet.
pub fn randomPassword(io: Io, buf: *[16]u8) []const u8 {
    const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
    var raw: [16]u8 = undefined;
    io.random(&raw);
    for (buf, raw) |*o, r| o.* = alphabet[r % alphabet.len];
    return buf;
}

pub const Bootstrapped = struct {
    /// Point into the caller's buffer; print once.
    password: []const u8,
    /// The `admin` login lives in memory only and ends with the process.
    ephemeral: bool,
};

/// First-run setup: when nobody can sign in to the web console, give user
/// "admin" a random web password (no SMB password) and return it (caller
/// prints it once). The user is stored (created if missing), except when
/// nothing can be stored (no `--db`, or `--users -`): then it is an
/// ephemeral login, unless the name is already an ephemeral user. Returns
/// null when a web login exists, stored or ephemeral.
pub fn bootstrap(gpa: Allocator, io: Io, db: *Db, pw_buf: *[16]u8) !?Bootstrapped {
    if (db.hasEphemeralWebLogin()) return null;
    if (db.users_stdin or db.ephemeral_only) {
        if (db.isEphemeralUser("admin")) return null;
        const pw = randomPassword(io, pw_buf);
        const phc = try hashPassword(gpa, io, pw);
        defer gpa.free(phc);
        try db.addEphemeralUser(gpa, "admin", null, phc);
        return .{ .password = pw, .ephemeral = true };
    }
    if (try db.countWebUsers() > 0) return null;
    const pw = randomPassword(io, pw_buf);
    if (try db.userAuth(gpa, "admin")) |u| u.free(gpa) else try addUser(io, db, "admin");
    _ = try grantPasswords(gpa, io, db, "admin", .{ .web = pw });
    return .{ .password = pw, .ephemeral = false };
}

test "validation" {
    try validateUserName("alice");
    try std.testing.expectError(error.InvalidUserName, validateUserName("a\\b"));
    try std.testing.expectError(error.InvalidUserName, validateUserName(""));
    try validateShareName("Public Files");
    try std.testing.expectError(error.ReservedShareName, validateShareName("ipc$"));
    try std.testing.expectError(error.InvalidShareName, validateShareName("a/b"));
    try std.testing.expectEqualStrings("true", try normalizeSetting("encrypt", "YES"));
    try std.testing.expectError(error.InvalidSetting, normalizeSetting("server_name", "THIS-NAME-IS-TOO-LONG"));
    try std.testing.expectError(error.InvalidSetting, normalizeSetting("bogus", "x"));
}

fn testDb() !Db {
    return Db.open(std.testing.io, ":memory:");
}

fn canWebLogin(db: *Db, name: []const u8, pw: []const u8) !bool {
    const n = (try checkWebLogin(std.testing.allocator, std.testing.io, db, name, pw)) orelse return false;
    std.testing.allocator.free(n);
    return true;
}

/// A new user with these passwords.
fn newUser(db: *Db, name: []const u8, pw: Passwords) !Warnings {
    try addUser(std.testing.io, db, name);
    return grantPasswords(std.testing.allocator, std.testing.io, db, name, pw);
}

test "passwords open and close each service" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    try std.testing.expectEqual(0, (try newUser(&db, "ann", .{ .web = "web-secret" })).count());
    try std.testing.expectEqual(0, (try newUser(&db, "cal", .{ .smb = "smb-secret" })).count());
    try std.testing.expect((try db.ntHash("ann")) == null);
    try std.testing.expect((try db.ntHash("cal")) != null);
    try std.testing.expect(try canWebLogin(&db, "ann", "web-secret"));
    try std.testing.expect(!try canWebLogin(&db, "cal", "smb-secret"));

    // Adding a web password gives both; clearing the SMB one leaves web.
    try std.testing.expect((try grantPasswords(gpa, io, &db, "cal", .{ .web = "web-other" })).contains(.both_passwords));
    try std.testing.expect(try canWebLogin(&db, "cal", "web-other"));
    try revokePasswords(gpa, io, &db, "cal", true, false);
    try std.testing.expect((try db.ntHash("cal")) == null);
    try std.testing.expect(try canWebLogin(&db, "cal", "web-other"));

    // Any web login may go, even the last one.
    try revokePasswords(gpa, io, &db, "cal", false, true);
    try std.testing.expect(!try canWebLogin(&db, "cal", "web-other"));
    try deleteUser(gpa, &db, "cal");
    try std.testing.expectError(error.NotFound, revokePasswords(gpa, io, &db, "cal", true, true));

    const users = try db.listUsers(gpa);
    defer db_mod.freeUsers(gpa, users);
    try std.testing.expect(!users[0].has_smb and users[0].has_web);
    try std.testing.expectEqualStrings("web", accessName(users[0].has_smb, users[0].has_web));
    try std.testing.expectEqualStrings("none", accessName(false, false));
}

test "users with both passwords are warned about identical passwords" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    try std.testing.expect((try newUser(&db, "hal", .{ .smb = "same-secret", .web = "same-secret" })).contains(.same_password));
    try std.testing.expect((try grantPasswords(gpa, io, &db, "hal", .{ .web = "web-secret" })).contains(.both_passwords));
    // Matching the stored web password (argon2id) or SMB password (NT hash).
    try std.testing.expect((try grantPasswords(gpa, io, &db, "hal", .{ .smb = "web-secret" })).contains(.same_password));
    try std.testing.expect((try grantPasswords(gpa, io, &db, "hal", .{ .web = "web-secret" })).contains(.same_password));
}

test "SMB passwords may arrive pre-hashed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    const nt = try crypto.ntHash(gpa, "smb-secret");
    try std.testing.expectEqual(0, (try newUser(&db, "cal", .{ .nt_hash = nt })).count());
    try std.testing.expectEqual(nt, (try db.ntHash("cal")).?);
    try std.testing.expectError(error.InvalidPassword, grantPasswords(gpa, io, &db, "cal", .{ .smb = "smb-secret", .nt_hash = nt }));

    // A pre-hashed SMB password is still compared with a new web password.
    try std.testing.expect((try newUser(&db, "hal", .{ .nt_hash = nt, .web = "smb-secret" })).contains(.same_password));
    try std.testing.expect((try grantPasswords(gpa, io, &db, "hal", .{ .nt_hash = try crypto.ntHash(gpa, "other-secret") })).contains(.both_passwords));
}

test "weak passwords are reported, not refused" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    try std.testing.expect((try newUser(&db, "cal", .{ .smb = "abc" })).contains(.weak_smb));
    try std.testing.expect((try db.ntHash("cal")) != null);
    try std.testing.expect((try newUser(&db, "ann", .{ .web = "Password1!" })).contains(.weak_web));
    try std.testing.expect(try canWebLogin(&db, "ann", "Password1!"));
    try std.testing.expectEqual(0, (try grantPasswords(gpa, io, &db, "cal", .{ .smb = "correct horse battery staple" })).count());
    try std.testing.expectError(error.EmptyPassword, grantPasswords(gpa, io, &db, "cal", .{ .smb = "" }));
}

test "bootstrap creates an admin" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();
    var buf: [16]u8 = undefined;
    const b = (try bootstrap(gpa, io, &db, &buf)).?;
    const pw = b.password;
    try std.testing.expect(!b.ephemeral);
    try std.testing.expect((try db.ntHash("admin")) == null);
    try std.testing.expect(try canWebLogin(&db, "admin", pw));
    try std.testing.expect((try bootstrap(gpa, io, &db, &buf)) == null);
}

test "hashPasswords without a store" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const h = try hashPasswords(gpa, io, .{ .smb = "open-the-pod-bay-doors", .web = "open-the-pod-bay-doors" });
    defer gpa.free(h.web.?);
    try std.testing.expect(h.same and verifyPassword(gpa, io, h.web.?, "open-the-pod-bay-doors"));
    try std.testing.expectEqual(try crypto.ntHash(gpa, "open-the-pod-bay-doors"), h.nt.?);
    const line = try db_mod.userLine(gpa, "hal", h.nt, "");
    defer gpa.free(line);
    try std.testing.expectEqualStrings("hal:942ebbe1a8d15349adc17914761007a3:\n", line);
    try std.testing.expectError(error.EmptyPassword, hashPasswords(gpa, io, .{ .web = "" }));
}

test "a new user has no passwords" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();
    try addUser(io, &db, "hal");
    try std.testing.expectEqual(null, try db.ntHash("hal"));
    try std.testing.expect(!try canWebLogin(&db, "hal", ""));
    try std.testing.expectError(error.NotFound, grantPasswords(gpa, io, &db, "skynet", .{ .smb = "x" }));
    const both = try grantPasswords(gpa, io, &db, "hal", .{ .smb = "murderbot", .web = "murderbot" });
    try std.testing.expect(both.contains(.both_passwords) and both.contains(.same_password));
    try std.testing.expect(try canWebLogin(&db, "hal", "murderbot"));
    try std.testing.expectEqual(try crypto.ntHash(gpa, "murderbot"), (try db.ntHash("hal")).?);
}
