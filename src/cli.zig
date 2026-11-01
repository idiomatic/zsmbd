//! zsmbd commands: run the server and manage users, shares, and settings.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Db = @import("store/store.zig").Db;
const db_mod = @import("store/store.zig");
const auth = @import("policy/auth.zig");
const web = @import("web/server.zig");
const smb_server = @import("smb/server.zig");
const strength = @import("policy/strength.zig");

pub const usage =
    \\usage: zsmbd [--db PATH] [--config FILE] [--users FILE] <command>
    \\       zsmbd --version
    \\
    \\  serve [--smb [ADDR:]PORT] [--web [ADDR:]PORT]
    \\                                   defaults: 0.0.0.0:445, 127.0.0.1:8445
    \\  user list
    \\  user add LOGIN                   no password: can't sign in until one is set
    \\  user passwd [--web] LOGIN        prompts for the SMB (or web console) password
    \\  user passwd --both LOGIN       prompts for one password for both
    \\  user nopasswd [--web] LOGIN      clears the SMB (or web console) password
    \\  user nopasswd --both LOGIN     clears both
    \\  user del LOGIN
    \\  share list
    \\  share add SHARE PATH
    \\  share comment SHARE TEXT
    \\  share readonly SHARE
    \\  share readwrite SHARE
    \\  share guest SHARE                allow guests (no sign-in)
    \\  share noguest SHARE
    \\  share del SHARE
    \\  get [KEY]                        show settings
    \\  set KEY VALUE
    \\  hash [--web] [LOGIN]             hash an SMB (or web) password; with LOGIN,
    \\                                   print a users-file line
    \\  hash --both LOGIN              a users-file line with one password for both
    \\  help
    \\
    \\Each password opens one service; `user list` shows smb, web (console),
    \\both, or none. Passwords are read from stdin, one per line, without echo
    \\at a terminal. `hash` uses no store.
    \\The database defaults to ./zsmbd.db and is created on first use.
    \\--config FILE keeps settings and shares in a plain-text file instead, and
    \\--users FILE keeps users in one; either or both may be given, and the
    \\files may be edited by hand. With both, no database is used.
    \\On first start, an "admin" user with a random web password is created
    \\and the password is printed once.
    \\
;

/// The commands `run` takes, so main can reject others before opening a store.
pub const commands = [_][]const u8{ "serve", "user", "share", "get", "set", "hash", "help" };

pub fn isCommand(s: []const u8) bool {
    for (commands) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

/// The usage header and the synopsis lines of `cmd` (with their continuation
/// lines), or all of the usage when `cmd` is not a command.
pub fn printUsage(w: *Io.Writer, cmd: ?[]const u8) Io.Writer.Error!void {
    const name = cmd orelse return w.writeAll(usage);
    if (!isCommand(name) or std.mem.eql(u8, name, "help")) return w.writeAll(usage);
    var it = std.mem.splitScalar(u8, usage, '\n');
    try w.print("{s}\n", .{it.first()});
    var in_cmd = false;
    while (it.next()) |l| {
        if (std.mem.startsWith(u8, l, "    ")) {
            // A continuation of the line before.
            if (in_cmd) try w.print("{s}\n", .{l});
            continue;
        }
        const t = std.mem.trimStart(u8, l, " ");
        in_cmd = l.len > t.len and std.mem.startsWith(u8, t, name) and (t.len == name.len or t[name.len] == ' ');
        if (in_cmd) try w.print("{s}\n", .{l});
    }
    try w.writeAll("Run `zsmbd help` for more.\n");
}

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
    if (std.mem.eql(u8, cmd, "hash")) return hashCmd(c);
    if (std.mem.eql(u8, cmd, "set")) {
        const key = try c.need();
        const value = try auth.normalizeSetting(key, try c.need());
        try c.db.setSetting(key, value);
        return;
    }
    return error.Usage;
}

/// Prompts for an SMB password, a web password, or one for both.
fn readPassword(c: *Cli, for_smb: bool, for_web: bool) ![]u8 {
    std.debug.print("{s} password: ", .{if (for_smb and for_web) "SMB and web" else if (for_web) "web" else "SMB"});
    const stdin = Io.File.stdin();
    // One reader for the whole command, so consecutive lines aren't lost.
    if (c.stdin == null) c.stdin = stdin.reader(c.io, &c.stdin_buf);
    // At a terminal, don't echo the password.
    const saved: ?std.posix.termios = if (try stdin.isTty(c.io)) std.posix.tcgetattr(stdin.handle) catch null else null;
    if (saved) |t| {
        var quiet = t;
        quiet.lflag.ECHO = false;
        std.posix.tcsetattr(stdin.handle, .FLUSH, quiet) catch {};
    }
    defer if (saved) |t| std.posix.tcsetattr(stdin.handle, .FLUSH, t) catch {};
    const line = (try c.stdin.?.interface.takeDelimiter('\n')) orelse return error.EmptyPassword;
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

/// Prints warnings; strength was reported as each password was read.
fn report(ws: auth.Warnings) void {
    var it = ws.iterator();
    while (it.next()) |w| switch (w) {
        .weak_smb, .weak_web => {},
        else => warn(w),
    };
}

fn userCmd(c: *Cli) !void {
    const sub = try c.need();
    if (std.mem.eql(u8, sub, "list")) {
        const users = try c.db.listUsers(c.gpa);
        defer db_mod.freeUsers(c.gpa, users);
        for (users) |u| try c.out.print("{s}\t{s}\n", .{ u.name, auth.accessName(u.has_smb, u.has_web) });
        return;
    }
    // One LOGIN; `passwd` and `nopasswd` also take --web or --both, before
    // or after it.
    const takes_flag = std.mem.eql(u8, sub, "passwd") or std.mem.eql(u8, sub, "nopasswd");
    var name: ?[]const u8 = null;
    var flag: ?[]const u8 = null;
    while (c.next()) |a| {
        if ((std.mem.eql(u8, a, "--web") or std.mem.eql(u8, a, "--both")) and takes_flag and flag == null) flag = a //
        else if (name == null and !std.mem.startsWith(u8, a, "--")) name = a //
        else return error.Usage;
    }
    const login = name orelse return error.Usage;
    const for_web = flag != null;
    const for_smb = flag == null or std.mem.eql(u8, flag.?, "--both");
    if (std.mem.eql(u8, sub, "add")) {
        if (try c.db.userAuth(c.gpa, login)) |u| {
            u.free(c.gpa);
            return error.UserExists;
        }
        try auth.addUser(c.io, c.db, login);
    } else if (std.mem.eql(u8, sub, "nopasswd")) {
        try auth.revokePasswords(c.gpa, c.io, c.db, login, for_smb, for_web);
    } else if (std.mem.eql(u8, sub, "passwd")) {
        (try c.db.userAuth(c.gpa, login) orelse return error.NotFound).free(c.gpa);
        const pw = try readPassword(c, for_smb, for_web);
        defer freeSecret(c, pw);
        report(try auth.grantPasswords(c.gpa, c.io, c.db, login, .{ .smb = if (for_smb) pw else null, .web = if (for_web) pw else null }));
    } else if (std.mem.eql(u8, sub, "del")) {
        try auth.deleteUser(c.gpa, c.db, login);
    } else return error.Usage;
}

/// Prints a users-file line, or one hash, for a store on another machine,
/// from one password. Uses no store: `c.db` is unset.
fn hashCmd(c: *Cli) !void {
    // At most one flag and one name, in either order; SMB is the default.
    var flag: ?[]const u8 = null;
    var name: ?[]const u8 = null;
    while (c.next()) |a| {
        if (std.mem.startsWith(u8, a, "--")) {
            if (flag != null or !(std.mem.eql(u8, a, "--web") or std.mem.eql(u8, a, "--both"))) return error.Usage;
            flag = a;
        } else {
            if (name != null) return error.Usage;
            name = a;
        }
    }
    const both = flag != null and std.mem.eql(u8, flag.?, "--both");
    const for_web = flag != null;
    const for_smb = flag == null or both;
    if (both and name == null) return error.Usage;
    if (name) |n| try auth.validateUserName(n);
    const pw = try readPassword(c, for_smb, for_web);
    defer freeSecret(c, pw);
    const h = try auth.hashPasswords(c.gpa, c.io, .{ .smb = if (for_smb) pw else null, .web = if (for_web) pw else null });
    defer if (h.web) |w| freeSecret(c, w);
    if (h.same) {
        warn(.both_passwords);
        warn(.same_password);
    }
    if (name) |n| {
        const line = try db_mod.userLine(c.gpa, n, h.nt, h.web orelse "");
        defer freeSecret(c, line);
        return c.out.writeAll(line);
    }
    if (h.nt) |nt| try c.out.print("{s}\n", .{std.fmt.bytesToHex(nt, .lower)}) else try c.out.print("{s}\n", .{h.web.?});
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
        if (c.next() != null) return error.Usage;
        try auth.validateShareName(name);
        try auth.validateSharePath(c.gpa, path);
        try c.db.putShare(.{ .name = name, .path = path });
    } else if (std.mem.eql(u8, sub, "del")) {
        if (c.next() != null) return error.Usage;
        if (!try c.db.deleteShare(name)) return error.NotFound;
    } else {
        // Changes to one option of an existing share.
        const comment = if (std.mem.eql(u8, sub, "comment")) try c.need() else null;
        if (c.next() != null) return error.Usage;
        const shares = try c.db.listShares(c.gpa);
        defer db_mod.freeShares(c.gpa, shares);
        var share = for (shares) |s| {
            if (std.ascii.eqlIgnoreCase(s.name, name)) break s;
        } else return error.NotFound;
        if (comment) |t| {
            try auth.validateComment(t);
            share.comment = t;
        } else if (std.mem.eql(u8, sub, "readonly")) share.read_only = true //
        else if (std.mem.eql(u8, sub, "readwrite")) share.read_only = false //
        else if (std.mem.eql(u8, sub, "guest")) share.guest_ok = true //
        else if (std.mem.eql(u8, sub, "noguest")) share.guest_ok = false //
        else return error.Usage;
        try c.db.putShare(share);
    }
}

fn getCmd(c: *Cli) !void {
    const only = c.next();
    if (c.next() != null) return error.Usage;
    if (only) |k| _ = auth.findSetting(k) orelse return error.InvalidSetting;
    for (auth.settings) |s| {
        if (only) |k| if (!std.mem.eql(u8, k, s.key)) continue;
        const v = try c.db.getSetting(c.gpa, s.key);
        defer if (v) |x| c.gpa.free(x);
        try c.out.print("{s} = {s}\n", .{ s.key, v orelse if (s.default.len > 0) s.default else "(automatic)" });
    }
}

fn serve(c: *Cli) !void {
    var web_addr: []const u8 = "8445";
    var smb_addr: []const u8 = "445";
    while (c.next()) |opt| {
        if (std.mem.eql(u8, opt, "--web"))
            web_addr = try c.need()
        else if (std.mem.eql(u8, opt, "--smb"))
            smb_addr = try c.need()
        else
            return error.Usage;
    }
    const addr = try parseAddr(web_addr, "127.0.0.1");
    const saddr = try parseAddr(smb_addr, "0.0.0.0");

    var pw_buf: [16]u8 = undefined;
    if (try auth.bootstrap(c.gpa, c.io, c.db, &pw_buf)) |pw| {
        std.debug.print(
            \\
            \\  First run: gave user "admin" the web password {s}
            \\  Sign in at http://{f}/ and change it. This is shown only once.
            \\  It is not an SMB password; set one with `zsmbd user passwd admin`.
            \\
            \\
        , .{ pw, addr });
    }

    var guid: [16]u8 = undefined;
    c.io.random(&guid);
    var srv: smb_server.Server = .{
        .gpa = c.gpa,
        .io = c.io,
        .db = c.db,
        .guid = guid,
        .start_ms = Io.Clock.real.now(c.io).toMilliseconds(),
        .smb_port = saddr.getPort(),
        .cfg = .{ .server_name = &.{}, .workgroup = &.{}, .signing_required = true, .encrypt = false },
    };
    try srv.loadConfig();
    var listener = saddr.listen(c.io, .{ .reuse_address = true }) catch |e| {
        std.log.err("cannot listen for SMB on {f}: {s} (port 445 may need root; try --smb 4450)", .{ saddr, @errorName(e) });
        return e;
    };
    defer listener.deinit(c.io);
    std.log.info("zsmbd: SMB on {f} as {s}", .{ saddr, srv.cfg.server_name });
    const smb_thread = try std.Thread.spawn(.{}, smb_server.Server.acceptLoop, .{ &srv, &listener });
    smb_thread.detach();

    var admin: web.Admin = .{ .gpa = c.gpa, .io = c.io, .db = c.db };
    try admin.serve(addr);
}

/// `[ADDR]:PORT` or `PORT`; a missing address is `default_host`.
fn parseAddr(s: []const u8, default_host: []const u8) !Io.net.IpAddress {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':');
    const port = std.fmt.parseInt(u16, s[if (colon) |i| i + 1 else 0..], 10) catch return error.Usage;
    var host = if (colon) |i| s[0..i] else "";
    if (host.len == 0) host = default_host;
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    return Io.net.IpAddress.parse(host, port);
}

test "listen addresses default their host" {
    const t = std.testing;
    try t.expectEqual(try Io.net.IpAddress.parse("0.0.0.0", 4450), try parseAddr("4450", "0.0.0.0"));
    try t.expectEqual(try Io.net.IpAddress.parse("127.0.0.1", 8099), try parseAddr(":8099", "127.0.0.1"));
    try t.expectEqual(try Io.net.IpAddress.parse("192.168.1.9", 445), try parseAddr("192.168.1.9:445", "0.0.0.0"));
    try t.expectEqual(try Io.net.IpAddress.parse("::1", 8445), try parseAddr("[::1]:8445", "127.0.0.1"));
    try t.expectError(error.Usage, parseAddr("10.0.0.1", "0.0.0.0"));
    try t.expectError(error.Usage, parseAddr("", "0.0.0.0"));
}

test "usage for one command" {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try printUsage(&w, "hash");
    const s = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, s, "print a users-file line") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "hash --both LOGIN") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "share") == null);
    try std.testing.expect(isCommand("share") and !isCommand("shares"));
}
