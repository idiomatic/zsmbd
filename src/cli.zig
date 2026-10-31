//! zsmbd commands: run the server and manage users, shares, and settings.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Db = @import("store/store.zig").Db;
const db_mod = @import("store/store.zig");
const auth = @import("policy/auth.zig");
const web = @import("web/server.zig");
const strength = @import("policy/strength.zig");

pub const usage =
    \\usage: zsmbd [--db PATH] [--config FILE] [--users FILE] <command>
    \\
    \\  serve [--web ADDR:PORT]          run the server (default web UI 127.0.0.1:8445)
    \\  user list
    \\  user add NAME [--role ROLE]      ROLE: client (default), admin, or hybrid
    \\  user passwd NAME [--web]         --web: a hybrid's web password
    \\  user role NAME ROLE
    \\  user del NAME
    \\  share list
    \\  share add NAME PATH [--comment TEXT] [--read-only] [--guest]
    \\  share del NAME
    \\  get [KEY]                        show settings
    \\  set KEY VALUE
    \\
    \\Roles: client users sign in over SMB only, admin users to the web console
    \\only, and hybrid users to both, with separate SMB and web passwords.
    \\Passwords are read from stdin, one per line (SMB first for hybrids).
    \\The database defaults to ./zsmbd.db and is created on first use.
    \\--config FILE keeps settings and shares in a plain-text file instead, and
    \\--users FILE keeps users in one; either or both may be given, and the
    \\files may be edited by hand. With both, no database is used.
    \\On first start, an "admin" user with a random web password is created
    \\and the password is printed once.
    \\
;

pub const Cli = struct {
    gpa: Allocator,
    io: Io,
    db: *Db,
    out: *Io.Writer,
    args: []const [:0]const u8,
    pos: usize = 0,
    stdin_buf: [1024]u8 = undefined,
    stdin: ?Io.File.Reader = null,

    fn next(c: *Cli) ?[]const u8 {
        if (c.pos >= c.args.len) return null;
        defer c.pos += 1;
        return c.args[c.pos];
    }
    fn need(c: *Cli) ![]const u8 {
        return c.next() orelse error.Usage;
    }
};

pub fn run(c: *Cli) !void {
    const cmd = try c.need();
    if (std.mem.eql(u8, cmd, "serve")) return serve(c);
    if (std.mem.eql(u8, cmd, "user")) return userCmd(c);
    if (std.mem.eql(u8, cmd, "share")) return shareCmd(c);
    if (std.mem.eql(u8, cmd, "get")) return getCmd(c);
    if (std.mem.eql(u8, cmd, "set")) {
        const key = try c.need();
        const value = try auth.normalizeSetting(key, try c.need());
        try c.db.setSetting(key, value);
        return;
    }
    return error.Usage;
}

fn readPassword(c: *Cli, kind: auth.PasswordKind) ![]u8 {
    std.debug.print("{s} password: ", .{if (kind == .web) "web" else "SMB"});
    // One reader for the whole command, so consecutive lines aren't lost.
    if (c.stdin == null) c.stdin = Io.File.stdin().reader(c.io, &c.stdin_buf);
    const line = (try c.stdin.?.interface.takeDelimiter('\n')) orelse return error.PasswordRequired;
    const pw = std.mem.trimEnd(u8, line, "\r");
    // Inform about strength; never refuse a password for it.
    if (pw.len > 0) {
        const e = strength.estimate(pw);
        std.debug.print("\n  strength: {s} (about {d} bits){s}\n", .{
            @tagName(e.level),
            e.bits,
            if (e.level == .weak) "; a longer passphrase is much harder to guess" else "",
        });
    } else std.debug.print("\n", .{});
    return c.gpa.dupe(u8, pw);
}

/// Reads the passwords listed in `need`, SMB first.
fn readPasswords(c: *Cli, need_smb: bool, need_web: bool) !auth.Passwords {
    const smb = if (need_smb) try readPassword(c, .smb) else null;
    errdefer if (smb) |p| freeSecret(c, p);
    return .{ .smb = smb, .web = if (need_web) try readPassword(c, .web) else null };
}

fn freeSecret(c: *Cli, p: []const u8) void {
    std.crypto.secureZero(u8, @constCast(p));
    c.gpa.free(p);
}

fn freePasswords(c: *Cli, pw: auth.Passwords) void {
    if (pw.smb) |p| freeSecret(c, p);
    if (pw.web) |p| freeSecret(c, p);
}

fn warn(w: auth.Warning) void {
    std.debug.print("zsmbd: warning: {s}\n", .{w.text()});
}

/// Prints warnings not already shown: strength was reported as each password
/// was read, and the general hybrid warning before asking when `hybrid_shown`.
fn report(ws: auth.Warnings, hybrid_shown: bool) void {
    var it = ws.iterator();
    while (it.next()) |w| switch (w) {
        .weak_smb, .weak_web => {},
        .hybrid => if (!hybrid_shown) warn(w),
        else => warn(w),
    };
}

fn parseRole(s: []const u8) !auth.Role {
    return auth.Role.parse(s) orelse error.InvalidRole;
}

fn userCmd(c: *Cli) !void {
    const sub = try c.need();
    if (std.mem.eql(u8, sub, "list")) {
        const users = try c.db.listUsers(c.gpa);
        defer db_mod.freeUsers(c.gpa, users);
        for (users) |u| try c.out.print("{s}\t{s}\n", .{ u.name, @tagName(u.role) });
        return;
    }
    const name = try c.need();
    if (std.mem.eql(u8, sub, "add")) {
        var role: auth.Role = .client;
        while (c.next()) |opt| {
            if (std.mem.eql(u8, opt, "--role")) role = try parseRole(try c.need()) else return error.Usage;
        }
        try auth.validateUserName(name);
        if (try c.db.userAuth(c.gpa, name)) |u| {
            u.free(c.gpa);
            std.debug.print("zsmbd: user exists; use `user passwd` or `user role`\n", .{});
            std.process.exit(1);
        }
        if (role == .hybrid) warn(.hybrid);
        const pw = try readPasswords(c, role.smb(), role.web());
        defer freePasswords(c, pw);
        report(try auth.createUser(c.gpa, c.io, c.db, name, role, pw), role == .hybrid);
    } else if (std.mem.eql(u8, sub, "passwd")) {
        var web_pw = false;
        while (c.next()) |opt| {
            if (std.mem.eql(u8, opt, "--web")) web_pw = true else return error.Usage;
        }
        const u = (try c.db.userAuth(c.gpa, name)) orelse return error.NotFound;
        const role = u.role;
        u.free(c.gpa);
        // Admins have only a web password; otherwise SMB unless --web.
        const kind: auth.PasswordKind = if (web_pw or role == .admin) .web else .smb;
        const pw = try readPassword(c, kind);
        defer freeSecret(c, pw);
        report(try auth.setPassword(c.gpa, c.io, c.db, name, kind, pw), false);
    } else if (std.mem.eql(u8, sub, "role")) {
        const role = try parseRole(try c.need());
        const u = (try c.db.userAuth(c.gpa, name)) orelse return error.NotFound;
        const need_smb = role.smb() and !u.has_smb;
        const need_web = role.web() and u.pw_hash.len == 0;
        u.free(c.gpa);
        if (role == .hybrid) warn(.hybrid);
        const pw = try readPasswords(c, need_smb, need_web);
        defer freePasswords(c, pw);
        report(try auth.setRole(c.gpa, c.io, c.db, name, role, pw), role == .hybrid);
    } else if (std.mem.eql(u8, sub, "del")) {
        try auth.deleteUser(c.gpa, c.db, name);
    } else return error.Usage;
}

fn shareCmd(c: *Cli) !void {
    const sub = try c.need();
    if (std.mem.eql(u8, sub, "list")) {
        const shares = try c.db.listShares(c.gpa);
        defer db_mod.freeShares(c.gpa, shares);
        for (shares) |s| {
            try c.out.print("{s}\t{s}{s}{s}", .{ s.name, s.path, if (s.read_only) "\tread-only" else "", if (s.guest_ok) "\tguest" else "" });
            if (s.comment.len > 0) try c.out.print("\t# {s}", .{s.comment});
            try c.out.writeAll("\n");
        }
        return;
    }
    const name = try c.need();
    if (std.mem.eql(u8, sub, "add")) {
        const path = try c.need();
        var share: db_mod.Share = .{ .name = name, .path = path };
        while (c.next()) |opt| {
            if (std.mem.eql(u8, opt, "--read-only")) share.read_only = true //
            else if (std.mem.eql(u8, opt, "--guest")) share.guest_ok = true //
            else if (std.mem.eql(u8, opt, "--comment")) share.comment = try c.need() //
            else return error.Usage;
        }
        try auth.validateShareName(name);
        try auth.validateSharePath(c.gpa, path);
        try auth.validateComment(share.comment);
        try c.db.putShare(share);
    } else if (std.mem.eql(u8, sub, "del")) {
        if (!try c.db.deleteShare(name)) return error.NotFound;
    } else return error.Usage;
}

fn getCmd(c: *Cli) !void {
    const only = c.next();
    for (auth.settings) |s| {
        if (only) |k| if (!std.mem.eql(u8, k, s.key)) continue;
        const v = try c.db.getSetting(c.gpa, s.key);
        defer if (v) |x| c.gpa.free(x);
        try c.out.print("{s} = {s}\n", .{ s.key, v orelse if (s.default.len > 0) s.default else "(automatic)" });
    }
}

fn serve(c: *Cli) !void {
    var web_addr: []const u8 = "127.0.0.1:8445";
    while (c.next()) |opt| {
        if (std.mem.eql(u8, opt, "--web")) web_addr = try c.need() else return error.Usage;
    }
    const addr = try parseAddr(web_addr);

    var pw_buf: [16]u8 = undefined;
    if (try auth.bootstrap(c.gpa, c.io, c.db, &pw_buf)) |pw| {
        std.debug.print(
            \\
            \\  First run: created admin user "admin" with web password {s}
            \\  Sign in at http://{s}/ and change it. This is shown only once.
            \\  It is not an SMB password; set one with `zsmbd user passwd admin`.
            \\
            \\
        , .{ pw, web_addr });
    }

    // The SMB listener is started here once the connection handler exists
    // (src/smb/conn.zig); until then only the admin server runs and the
    // activity view reports the SMB service as not running.
    std.log.warn("SMB service not available in this build (connection handler missing)", .{});

    var admin: web.Admin = .{ .gpa = c.gpa, .io = c.io, .db = c.db };
    try admin.serve(addr);
}

fn parseAddr(s: []const u8) !Io.net.IpAddress {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.Usage;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.Usage;
    var host = s[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    return Io.net.IpAddress.parse(host, port);
}
