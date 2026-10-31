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
        error.LastAdmin => "at least one admin or hybrid user with a web password must remain",
        error.PasswordRequired => "admins need a web password, clients an SMB password, and hybrids both",
        error.PasswordNotForRole => "admins have only a web password and clients only an SMB password",
        error.InvalidRole => "roles are admin, client, and hybrid",
        error.InvalidPassword => "give the SMB password either as a password or as a 32-digit hex NT hash, not both",
        error.InvalidNtHash => "an NT hash is 32 hexadecimal digits",
        error.NotFound => "not found",
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

/// Validates and normalizes a setting value (booleans become "true"/"false").
pub fn normalizeSetting(key: []const u8, value: []const u8) ValidationError![]const u8 {
    const s = findSetting(key) orelse return error.InvalidSetting;
    switch (s.kind) {
        .boolean => {
            if (std.ascii.eqlIgnoreCase(value, "true") or std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "yes")) return "true";
            if (std.ascii.eqlIgnoreCase(value, "false") or std.mem.eql(u8, value, "0") or std.ascii.eqlIgnoreCase(value, "no")) return "false";
            return error.InvalidSetting;
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

pub const Role = db_mod.Role;

/// SMB passwords are stored as the NT hash NTLM needs; web passwords as
/// argon2id. They are never the same secret by design, so a web login sent
/// over the network does not reveal SMB credentials.
pub const PasswordKind = enum { smb, web };

/// Passwords supplied for a create or role change; null means not supplied.
/// The SMB password may instead arrive already hashed (`smb_nt`), as the web
/// page does when it can hash in the browser.
pub const Passwords = struct {
    smb: ?[]const u8 = null,
    smb_nt: ?[16]u8 = null,
    web: ?[]const u8 = null,

    fn hasSmb(pw: Passwords) bool {
        return pw.smb != null or pw.smb_nt != null;
    }
};

/// Password hygiene warnings. The operation they come from still succeeds.
pub const Warning = enum {
    hybrid,
    same_password,
    weak_smb,
    weak_web,

    pub fn text(w: Warning) []const u8 {
        return switch (w) {
            .weak_smb => "the SMB password is weak: a longer passphrase is much harder to guess",
            .weak_web => "the web password is weak: a longer passphrase is much harder to guess",
            .hybrid => "hybrid users sign in to both SMB and the web console: give them different SMB and web passwords, and keep the web console on localhost or behind TLS",
            .same_password => "the SMB and web passwords are identical: anyone who captures the web login can also connect over SMB; set different passwords",
        };
    }
};

pub const Warnings = std.EnumSet(Warning);

fn checkSupplied(role: Role, pw: Passwords) !void {
    if (pw.smb != null and pw.smb_nt != null) return error.InvalidPassword;
    if (pw.hasSmb() and !role.smb()) return error.PasswordNotForRole;
    if (pw.web != null and !role.web()) return error.PasswordNotForRole;
    if (pw.smb) |p| try validatePassword(p);
    if (pw.web) |p| try validatePassword(p);
}

/// Hash and store; returns the hygiene warning, judged against the stored
/// passwords before the write.
fn store(gpa: Allocator, io: Io, db: *Db, name: []const u8, role: Role, pw: Passwords, stored_pw_hash: []const u8) !Warnings {
    var warnings: Warnings = .empty;
    // Only plaintext can be rated; a pre-hashed password was rated in the browser.
    if (pw.smb) |p| if (strength.estimate(p).level == .weak) warnings.insert(.weak_smb);
    if (pw.web) |p| if (strength.estimate(p).level == .weak) warnings.insert(.weak_web);
    if (role == .hybrid) {
        warnings.insert(.hybrid);
        const same = blk: {
            if (pw.web) |w| {
                if (pw.smb) |p| break :blk std.mem.eql(u8, p, w);
                const smb_nt = pw.smb_nt orelse (try db.ntHash(name)) orelse break :blk false;
                break :blk std.crypto.timing_safe.eql([16]u8, smb_nt, try crypto.ntHash(gpa, w));
            }
            if (pw.smb) |p| break :blk stored_pw_hash.len > 0 and verifyPassword(gpa, io, stored_pw_hash, p);
            // A pre-hashed SMB password can't be checked against argon2id.
            break :blk false;
        };
        if (same) warnings.insert(.same_password);
    }
    const nt: ?[16]u8 = if (pw.smb) |p| try crypto.ntHash(gpa, p) else pw.smb_nt;
    const phc: ?[]u8 = if (pw.web) |p| try hashPassword(gpa, io, p) else null;
    defer if (phc) |h| gpa.free(h);
    try db.putUser(name, role, nt, phc, nowSeconds(io));
    return warnings;
}

/// Create a user with the passwords its role needs: admins a web password,
/// clients an SMB password, hybrids both.
pub fn createUser(gpa: Allocator, io: Io, db: *Db, name: []const u8, role: Role, pw: Passwords) !Warnings {
    try validateUserName(name);
    try checkSupplied(role, pw);
    if ((role.smb() and !pw.hasSmb()) or (role.web() and pw.web == null)) return error.PasswordRequired;
    return store(gpa, io, db, name, role, pw, "");
}

/// Set one of an existing user's passwords; the role must use it.
pub fn setPassword(gpa: Allocator, io: Io, db: *Db, name: []const u8, kind: PasswordKind, password: []const u8) !Warnings {
    return setPasswords(gpa, io, db, name, if (kind == .smb) .{ .smb = password } else .{ .web = password });
}

/// Set any of an existing user's passwords; the role must use each one.
pub fn setPasswords(gpa: Allocator, io: Io, db: *Db, name: []const u8, pw: Passwords) !Warnings {
    const u = (try db.userAuth(gpa, name)) orelse return error.NotFound;
    if (!pw.hasSmb() and pw.web == null) {
        u.free(gpa);
        return .empty;
    }
    defer u.free(gpa);
    try checkSupplied(u.role, pw);
    return store(gpa, io, db, u.name, u.role, pw, u.pw_hash);
}

/// Change a user's role. Passwords the new role uses but the user lacks must
/// be supplied; passwords it doesn't use are erased.
pub fn setRole(gpa: Allocator, io: Io, db: *Db, name: []const u8, role: Role, pw: Passwords) !Warnings {
    const u = (try db.userAuth(gpa, name)) orelse return error.NotFound;
    defer u.free(gpa);
    try checkSupplied(role, pw);
    if (role.smb() and !u.has_smb and !pw.hasSmb()) return error.PasswordRequired;
    if (role.web() and u.pw_hash.len == 0 and pw.web == null) return error.PasswordRequired;
    if (u.role.web() and !role.web() and try db.countAdmins() <= 1) return error.LastAdmin;
    return store(gpa, io, db, u.name, role, pw, u.pw_hash);
}

/// Delete a user, refusing to remove the last web console user.
pub fn deleteUser(gpa: Allocator, db: *Db, name: []const u8) !void {
    const u = (try db.userAuth(gpa, name)) orelse return error.NotFound;
    defer u.free(gpa);
    if (u.role.web() and try db.countAdmins() <= 1) return error.LastAdmin;
    _ = try db.deleteUser(name);
}

/// Returns the canonical user name when `password` is the web password of an
/// admin or hybrid user.
pub fn checkAdminLogin(gpa: Allocator, io: Io, db: *Db, name: []const u8, password: []const u8) !?[]u8 {
    const u = (try db.userAuth(gpa, name)) orelse {
        // Spend comparable time so unknown names aren't distinguishable.
        const dummy = try hashPassword(gpa, io, password);
        gpa.free(dummy);
        return null;
    };
    defer gpa.free(u.pw_hash);
    if (!u.role.web() or u.pw_hash.len == 0 or !verifyPassword(gpa, io, u.pw_hash, password)) {
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

/// First-run setup: when nobody can sign in to the web console, give user
/// "admin" a random web password and return it (caller prints it once).
/// A new "admin" is an admin; an existing client "admin" becomes a hybrid.
/// Returns null otherwise.
pub fn bootstrap(gpa: Allocator, io: Io, db: *Db, pw_buf: *[16]u8) !?[]const u8 {
    if (try db.countAdmins() > 0) return null;
    const pw = randomPassword(io, pw_buf);
    if (try db.userAuth(gpa, "admin")) |u| {
        defer u.free(gpa);
        _ = try setRole(gpa, io, db, u.name, if (u.role == .client) .hybrid else u.role, .{ .web = pw });
    } else {
        _ = try createUser(gpa, io, db, "admin", .admin, .{ .web = pw });
    }
    return pw;
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
    const n = (try checkAdminLogin(std.testing.allocator, std.testing.io, db, name, pw)) orelse return false;
    std.testing.allocator.free(n);
    return true;
}

test "roles get only their own passwords" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    try std.testing.expectEqual(0, (try createUser(gpa, io, &db, "ann", .admin, .{ .web = "web-secret" })).count());
    try std.testing.expectEqual(0, (try createUser(gpa, io, &db, "cal", .client, .{ .smb = "smb-secret" })).count());
    try std.testing.expectError(error.PasswordNotForRole, createUser(gpa, io, &db, "x", .client, .{ .smb = "smb-secret", .web = "web-secret" }));
    try std.testing.expectError(error.PasswordRequired, createUser(gpa, io, &db, "x", .hybrid, .{ .smb = "smb-secret" }));
    try std.testing.expectError(error.PasswordNotForRole, setPassword(gpa, io, &db, "ann", .smb, "smb-secret"));
    try std.testing.expectError(error.PasswordNotForRole, setPassword(gpa, io, &db, "cal", .web, "web-secret"));

    // Admins can't use SMB; clients can't use the web console.
    try std.testing.expect((try db.ntHash("ann")) == null);
    try std.testing.expect((try db.ntHash("cal")) != null);
    try std.testing.expect(try canWebLogin(&db, "ann", "web-secret"));
    try std.testing.expect(!try canWebLogin(&db, "cal", "smb-secret"));

    // Client -> hybrid needs a web password; hybrid -> admin erases the SMB one.
    try std.testing.expectError(error.PasswordRequired, setRole(gpa, io, &db, "cal", .hybrid, .{}));
    try std.testing.expect((try setRole(gpa, io, &db, "cal", .hybrid, .{ .web = "web-other" })).contains(.hybrid));
    try std.testing.expect(try canWebLogin(&db, "cal", "web-other"));
    _ = try setRole(gpa, io, &db, "cal", .admin, .{});
    try std.testing.expect((try db.ntHash("cal")) == null);
    try std.testing.expectError(error.PasswordRequired, setRole(gpa, io, &db, "cal", .hybrid, .{}));

    // The last web console user can't be removed or demoted.
    try deleteUser(gpa, &db, "cal");
    try std.testing.expectError(error.LastAdmin, deleteUser(gpa, &db, "ann"));
    try std.testing.expectError(error.LastAdmin, setRole(gpa, io, &db, "ann", .client, .{ .smb = "smb-secret" }));

    const users = try db.listUsers(gpa);
    defer db_mod.freeUsers(gpa, users);
    try std.testing.expectEqual(Role.admin, users[0].role);
}

test "hybrid users are warned about identical passwords" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    try std.testing.expect((try createUser(gpa, io, &db, "hal", .hybrid, .{ .smb = "same-secret", .web = "same-secret" })).contains(.same_password));
    try std.testing.expect((try setPassword(gpa, io, &db, "hal", .web, "web-secret")).contains(.hybrid));
    // Matching the stored web password (argon2id) or SMB password (NT hash).
    try std.testing.expect((try setPassword(gpa, io, &db, "hal", .smb, "web-secret")).contains(.same_password));
    try std.testing.expect((try setPassword(gpa, io, &db, "hal", .web, "web-secret")).contains(.same_password));
}

test "SMB passwords may arrive pre-hashed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    const nt = try crypto.ntHash(gpa, "smb-secret");
    try std.testing.expectEqual(0, (try createUser(gpa, io, &db, "cal", .client, .{ .smb_nt = nt })).count());
    try std.testing.expectEqual(nt, (try db.ntHash("cal")).?);
    try std.testing.expectError(error.InvalidPassword, setPasswords(gpa, io, &db, "cal", .{ .smb = "smb-secret", .smb_nt = nt }));
    try std.testing.expectError(error.PasswordNotForRole, createUser(gpa, io, &db, "ann", .admin, .{ .smb_nt = nt, .web = "web-secret" }));

    // A hybrid's pre-hashed SMB password is still compared with a new web password.
    try std.testing.expect((try createUser(gpa, io, &db, "hal", .hybrid, .{ .smb_nt = nt, .web = "smb-secret" })).contains(.same_password));
    try std.testing.expect((try setPasswords(gpa, io, &db, "hal", .{ .smb_nt = try crypto.ntHash(gpa, "other-secret") })).contains(.hybrid));
}

test "weak passwords are reported, not refused" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();

    try std.testing.expect((try createUser(gpa, io, &db, "cal", .client, .{ .smb = "abc" })).contains(.weak_smb));
    try std.testing.expect((try db.ntHash("cal")) != null);
    try std.testing.expect((try createUser(gpa, io, &db, "ann", .admin, .{ .web = "Password1!" })).contains(.weak_web));
    try std.testing.expect(try canWebLogin(&db, "ann", "Password1!"));
    try std.testing.expectEqual(0, (try setPassword(gpa, io, &db, "cal", .smb, "correct horse battery staple")).count());
    try std.testing.expectError(error.EmptyPassword, setPassword(gpa, io, &db, "cal", .smb, ""));
}

test "bootstrap creates an admin" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var db = try testDb();
    defer db.close();
    var buf: [16]u8 = undefined;
    const pw = (try bootstrap(gpa, io, &db, &buf)).?;
    try std.testing.expect((try db.ntHash("admin")) == null);
    try std.testing.expect(try canWebLogin(&db, "admin", pw));
    try std.testing.expect((try bootstrap(gpa, io, &db, &buf)) == null);
}
