//! zsmbt: protocol tests for an SMB 3.1.1 server. It starts a zsmbd of its
//! own (`--server`) or tests one that is running (`--target`), and prints
//! one line per test.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const h = @import("harness.zig");

const suites = .{
    @import("suites/negotiate.zig"),
    @import("suites/session.zig"),
    @import("suites/tcon.zig"),
};

const usage =
    \\usage: zsmbt --server PATH [options]
    \\       zsmbt --target HOST:PORT --profile NAME --user LOGIN%PASSWORD [options]
    \\
    \\  --server PATH      start this zsmbd with a share and a user of its own
    \\  --target ADDR      test a server that is running; needs --profile and --user
    \\  --profile NAME     zsmbd, samba, or windows: whose behavior is expected
    \\                     (zsmbd when --server starts it)
    \\  --user L%P         login for --target
    \\  --share NAME       a read-write disk share on --target (default: data)
    \\  -f PATTERN         only tests that match (* and ?; a bare suite name
    \\                     matches all its tests)
    \\  --list             list the tests and exit
    \\  --timeout SECONDS  per read (default: 5)
    \\  --keep             keep the --server run directory
    \\  -v                 show the frames of passing tests too
    \\
    \\Exit status: 0 if all tests passed or were skipped, 1 if any failed,
    \\2 for a usage error.
    \\
;

const Options = struct {
    server: ?[]const u8 = null,
    target: ?[]const u8 = null,
    profile: ?h.Profile = null,
    user: ?[]const u8 = null,
    share: []const u8 = "data",
    filter: ?[]const u8 = null,
    list: bool = false,
    timeout_s: u32 = 5,
    keep: bool = false,
    verbose: bool = false,
};

fn usageExit(msg: ?[]const u8) noreturn {
    if (msg) |m| std.debug.print("zsmbt: {s}\n", .{m});
    std.debug.print("{s}", .{usage});
    std.process.exit(2);
}

fn parseArgs(args: []const []const u8) Options {
    var o: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const has_value = i + 1 < args.len;
        if (std.mem.eql(u8, a, "--list")) {
            o.list = true;
        } else if (std.mem.eql(u8, a, "--keep")) {
            o.keep = true;
        } else if (std.mem.eql(u8, a, "-v")) {
            o.verbose = true;
        } else if (std.mem.eql(u8, a, "--help")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else if (!has_value) {
            usageExit(a);
        } else if (std.mem.eql(u8, a, "--server")) {
            i += 1;
            o.server = args[i];
        } else if (std.mem.eql(u8, a, "--target")) {
            i += 1;
            o.target = args[i];
        } else if (std.mem.eql(u8, a, "--profile")) {
            i += 1;
            o.profile = std.meta.stringToEnum(h.Profile, args[i]) orelse usageExit("unknown profile");
        } else if (std.mem.eql(u8, a, "--user")) {
            i += 1;
            o.user = args[i];
        } else if (std.mem.eql(u8, a, "--share")) {
            i += 1;
            o.share = args[i];
        } else if (std.mem.eql(u8, a, "-f")) {
            i += 1;
            o.filter = args[i];
        } else if (std.mem.eql(u8, a, "--timeout")) {
            i += 1;
            o.timeout_s = std.fmt.parseInt(u32, args[i], 10) catch usageExit("bad --timeout");
        } else usageExit(a);
    }
    if (!o.list and (o.server == null) == (o.target == null)) usageExit("give exactly one of --server and --target");
    if (o.target != null and (o.profile == null or o.user == null))
        usageExit("--target needs --profile and --user, so the results say what they were judged against");
    if (o.server != null and (o.user != null or o.profile != null and o.profile.? != .zsmbd))
        usageExit("--server runs zsmbd with its own user; --user and another --profile are for --target");
    return o;
}

/// `*` and `?` match; a pattern without them also matches a suite prefix.
fn globMatch(pattern: []const u8, name: []const u8) bool {
    if (std.mem.indexOfAny(u8, pattern, "*?") == null) {
        return std.mem.eql(u8, pattern, name) or
            (name.len > pattern.len and std.mem.startsWith(u8, name, pattern) and name[pattern.len] == '.');
    }
    var p: usize = 0;
    var n: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == name[n])) {
            p += 1;
            n += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = n;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            n = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

// ---------------------------------------------------------------- fixture

/// A zsmbd started for the run, with a share, a user, and a log file.
const Fixture = struct {
    child: std.process.Child,
    dir: []u8,
    log: []u8,
    password: []u8,
    addr: net.IpAddress,

    fn start(gpa: Allocator, io: Io, exe: []const u8) !Fixture {
        var rnd: [8]u8 = undefined;
        io.random(&rnd);
        const id = std.fmt.bytesToHex(rnd[0..4].*, .lower);
        const port: u16 = 20000 + std.mem.readInt(u16, rnd[4..6], .little) % 40000;
        const password = try std.fmt.allocPrint(gpa, "{x}", .{std.mem.readInt(u64, &rnd, .little)});
        errdefer gpa.free(password);
        const dir = try std.fmt.allocPrint(gpa, "var/torture/{s}", .{id});
        errdefer gpa.free(dir);
        const share_dir = try std.fmt.allocPrint(gpa, "{s}/data", .{dir});
        defer gpa.free(share_dir);
        try Io.Dir.cwd().createDirPath(io, share_dir);
        const log = try std.fmt.allocPrint(gpa, "{s}/server.log", .{dir});
        errdefer gpa.free(log);
        const log_file = try Io.Dir.cwd().createFile(io, log, .{});
        defer log_file.close(io);

        const listen = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{port});
        defer gpa.free(listen);
        const share_arg = try std.fmt.allocPrint(gpa, "data:{s}", .{share_dir});
        defer gpa.free(share_arg);
        const user_arg = try std.fmt.allocPrint(gpa, "hal:{s}", .{password});
        defer gpa.free(user_arg);
        var child = try std.process.spawn(io, .{
            .argv = &.{ exe, "--db", "none", "serve", "--smb", listen, "--share", share_arg, "--smb-user", user_arg },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = log_file },
        });
        errdefer child.kill(io);

        const addr = try net.IpAddress.parse("127.0.0.1", port);
        // Wait for the listener.
        var tries: u32 = 0;
        while (true) : (tries += 1) {
            if (addr.connect(io, .{ .mode = .stream })) |s| {
                s.close(io);
                break;
            } else |_| {
                if (tries >= 100) return error.ServerDidNotStart;
                try io.sleep(Io.Duration.fromMilliseconds(50), .awake);
            }
        }
        return .{ .child = child, .dir = dir, .log = log, .password = password, .addr = addr };
    }

    fn stop(f: *Fixture, gpa: Allocator, io: Io, keep: bool) void {
        f.child.kill(io);
        if (!keep) Io.Dir.cwd().deleteTree(io, f.dir) catch {};
        gpa.free(f.dir);
        gpa.free(f.log);
        gpa.free(f.password);
    }
};

// ---------------------------------------------------------------- run

pub fn main(init: std.process.Init) !void {
    // Exit only after `run` has stopped the server and removed its directory.
    const code = try run(init);
    if (code != 0) std.process.exit(code);
}

fn run(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const o = parseArgs(args);

    var out_buf: [4096]u8 = undefined;
    var out_w = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    if (o.list) {
        inline for (suites) |s| for (s.tests) |tc| try out.print("{s}\t{s}\n", .{ tc.name, tc.spec });
        return 0;
    }

    var fixture: ?Fixture = null;
    defer if (fixture) |*f| f.stop(gpa, io, o.keep);
    var env: h.Env = undefined;
    if (o.server) |exe| {
        fixture = Fixture.start(gpa, io, exe) catch |e| {
            std.debug.print("zsmbt: could not start {s}: {s}\n", .{ exe, @errorName(e) });
            return 1;
        };
        env = .{ .gpa = gpa, .io = io, .addr = fixture.?.addr, .host = "127.0.0.1", .share = "data", .user = "hal", .password = fixture.?.password, .profile = .zsmbd, .timeout_s = o.timeout_s };
    } else {
        const target = o.target.?;
        const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse usageExit("--target is HOST:PORT");
        const port = std.fmt.parseInt(u16, target[colon + 1 ..], 10) catch usageExit("bad port in --target");
        const user = o.user.?;
        const pct = std.mem.indexOfScalar(u8, user, '%') orelse usageExit("--user is LOGIN%PASSWORD");
        env = .{
            .gpa = gpa,
            .io = io,
            .addr = net.IpAddress.resolve(io, target[0..colon], port) catch usageExit("cannot resolve --target"),
            .host = target[0..colon],
            .share = o.share,
            .user = user[0..pct],
            .password = user[pct + 1 ..],
            .profile = o.profile.?,
            .timeout_s = o.timeout_s,
        };
    }
    try out.print("profile {s}\n", .{@tagName(env.profile)});

    var pass: usize = 0;
    var failed: usize = 0;
    var skipped: usize = 0;
    inline for (suites) |s| for (s.tests) |tc| {
        if (o.filter == null or globMatch(o.filter.?, tc.name)) {
            var t = h.T.init(&env);
            defer t.deinit();
            if (tc.run(&t)) |_| {
                pass += 1;
                try out.print("PASS {s}\n", .{tc.name});
                if (o.verbose) try t.writeTrace(out);
            } else |err| switch (err) {
                error.SkipTest => {
                    skipped += 1;
                    try out.print("SKIP {s}\n", .{tc.name});
                },
                else => {
                    failed += 1;
                    try out.print("FAIL {s}: {s} ({s})\n", .{ tc.name, t.failure orelse @errorName(err), tc.spec });
                    try t.writeTrace(out);
                },
            }
            try out.flush();
        }
    };
    try out.print("\n{d} passed, {d} failed, {d} skipped\n", .{ pass, failed, skipped });

    if (failed > 0) {
        if (fixture) |f| {
            const log = Io.Dir.cwd().readFileAlloc(io, f.log, gpa, .limited(1 << 20)) catch null;
            if (log) |l| {
                defer gpa.free(l);
                const tail = if (l.len > 4000) l[l.len - 4000 ..] else l;
                try out.print("server log (tail):\n{s}\n", .{tail});
            }
        }
        return 1;
    }
    return 0;
}

test "glob" {
    try std.testing.expect(globMatch("negotiate", "negotiate.basic"));
    try std.testing.expect(!globMatch("negotiate", "negotiated.basic"));
    try std.testing.expect(globMatch("negotiate.basic", "negotiate.basic"));
    try std.testing.expect(globMatch("*.basic", "negotiate.basic"));
    try std.testing.expect(globMatch("t*.d?sconnect", "tcon.disconnect"));
    try std.testing.expect(!globMatch("t*.d?sconnec", "tcon.disconnect"));
    try std.testing.expect(globMatch("tcon.disc*", "tcon.disconnect"));
    try std.testing.expect(globMatch("*", "x.y"));
}

test {
    _ = @import("client.zig");
}
