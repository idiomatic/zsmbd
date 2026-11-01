//! zsmbd entry point: global flags, the store, then the command (cli.zig).

const std = @import("std");
const Io = std.Io;
const Db = @import("store/store.zig").Db;
const auth = @import("policy/auth.zig");
const cli = @import("cli.zig");
const control = @import("control/control.zig");
const usage = cli.usage;
pub const version = @import("build_options").version;

/// SQLite's name for a database that lives only in memory.
const memory_db = ":memory:";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var out_buf: [4096]u8 = undefined;
    var out_w = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    var loc: Db.Location = .{};
    var db_given = false;
    var db_none = false;
    var socket_arg: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len and std.mem.startsWith(u8, args[i], "--")) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--db") and i + 1 < args.len) {
            i += 1;
            if (std.mem.eql(u8, args[i], ":memory:")) {
                std.debug.print("zsmbd: for an in-memory store use --db none (serve only)\n", .{});
                std.process.exit(2);
            }
            db_none = std.mem.eql(u8, args[i], "none");
            loc.db = if (db_none) null else args[i];
            db_given = true;
        } else if (std.mem.eql(u8, args[i], "--config") and i + 1 < args.len) {
            i += 1;
            loc.config = args[i];
        } else if (std.mem.eql(u8, args[i], "--users") and i + 1 < args.len) {
            i += 1;
            // Later `--users` wins: a file, or `-` for stdin (serve only).
            loc.users_stdin = std.mem.eql(u8, args[i], "-");
            loc.users = if (loc.users_stdin) null else args[i];
        } else if (std.mem.eql(u8, args[i], "--socket") and i + 1 < args.len) {
            i += 1;
            socket_arg = args[i];
        } else if (std.mem.eql(u8, args[i], "--version")) {
            try out.print("zsmbd {s}\n", .{version});
            return;
        } else if (std.mem.eql(u8, args[i], "--help")) {
            try out.writeAll(usage);
            return;
        } else break;
    }
    if (i >= args.len) {
        try out.writeAll(usage);
        return;
    }

    if (std.mem.eql(u8, args[i], "help")) return out.writeAll(usage);
    if (!cli.isCommand(args[i])) usageExit(args[i]);
    if (loc.users_stdin and !std.mem.eql(u8, args[i], "serve")) {
        std.debug.print("zsmbd: --users - works only with serve\n", .{});
        usageExit(args[i]);
    }
    if (db_none and !std.mem.eql(u8, args[i], "serve")) {
        std.debug.print("zsmbd: --db none works only with serve\n", .{});
        usageExit(args[i]);
    }
    // `hash` makes users-file lines for another machine, so it opens no store.
    const no_store = std.mem.eql(u8, args[i], "hash");
    if (db_given and !loc.usesSqlite() and !no_store) {
        std.log.err("--db is unused when both --config and --users are given", .{});
        std.process.exit(1);
    }
    // `--db none`, or `serve` given ephemeral entries and no `--db`, keeps the
    // store in memory: nothing is stored.
    var memory_only = false;
    if (!no_store and loc.usesSqlite() and (db_none or loc.db == null)) {
        if (db_none) {
            loc.db = memory_db;
            memory_only = true;
            std.log.info("--db none: the store is in memory, so only what this run creates exists", .{});
        } else if (std.mem.eql(u8, args[i], "serve") and givesEphemeral(args[i + 1 ..], loc.users_stdin)) {
            loc.db = memory_db;
            memory_only = true;
            std.log.info("no --db: the store is in memory, so only the ephemeral entries exist", .{});
        } else {
            std.debug.print("zsmbd: give --db PATH to name the SQLite database (or --config FILE and --users FILE)\n", .{});
            usageExit(args[i]);
        }
    }
    // The control socket sits beside the store (see control.zig); a path too
    // long for a socket just turns it off.
    const control_path: ?[]const u8 = if (no_store) null else control.pathFor(init.arena.allocator(), .{
        .arg = socket_arg,
        .db = if (loc.usesSqlite()) loc.db else null,
        .config = loc.config,
        .users = loc.users,
    }) catch |e| blk: {
        // Only `serve` says so; for the CLI no socket just means no notice.
        if (e == error.NameTooLong and std.mem.eql(u8, args[i], "serve"))
            std.log.warn("no control socket: its path is too long for a socket; give --socket PATH", .{});
        break :blk null;
    };
    var db: Db = undefined;
    if (!no_store) db = Db.openAt(gpa, io, loc) catch |e| {
        std.log.err("cannot open the store: {s}", .{@errorName(e)});
        std.process.exit(1);
    };
    defer if (!no_store) db.close();
    if (!no_store) db.ephemeral_only = memory_only;

    var c: cli.Cli = .{ .gpa = gpa, .io = io, .db = &db, .out = out, .args = args[i..], .control = control_path };
    cli.run(&c) catch |e| {
        out.flush() catch {};
        if (e == error.Usage) usageExit(args[i]);
        std.debug.print("zsmbd: {s}\n", .{auth.describe(e)});
        std.process.exit(1);
    };
}

/// Whether `serve`'s arguments give ephemeral shares or logins.
fn givesEphemeral(args: []const [:0]const u8, users_stdin: bool) bool {
    if (users_stdin) return true;
    for (args) |a| {
        for ([_][]const u8{ "--share", "--user", "--smb-user", "--web-user" }) |f| if (std.mem.eql(u8, a, f)) return true;
    }
    return false;
}

/// Prints the usage of `cmd` to stderr and exits with status 2.
fn usageExit(cmd: []const u8) noreturn {
    var buf: [1024]u8 = undefined;
    const w = std.debug.lockStderr(&buf);
    cli.printUsage(&w.file_writer.interface, cmd) catch {};
    std.debug.unlockStderr();
    std.process.exit(2);
}

test {
    _ = @import("cli.zig");
    _ = @import("policy/auth.zig");
    _ = @import("policy/ephemeral.zig");
    _ = @import("store/ephemeral.zig");
    _ = @import("store/textconf.zig");
    _ = @import("store/textusers.zig");
    _ = @import("web/server.zig");
    _ = @import("control/control.zig");
    _ = @import("smb/rpc.zig");
    _ = @import("smb/auth/ntlm.zig");
    _ = @import("smb/auth/spnego.zig");
    _ = @import("smb/vfs.zig");
    _ = @import("smb/files.zig");
    _ = @import("smb/conn.zig");
    _ = @import("smb/handshake.zig");
    _ = @import("shared/crypto.zig");
    _ = @import("shared/wire.zig");
    _ = @import("nthash_wasm.zig");
    _ = @import("policy/strength.zig");
}
