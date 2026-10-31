//! zsmbd entry point: global flags, the store, then the command (cli.zig).

const std = @import("std");
const Io = std.Io;
const Db = @import("store/store.zig").Db;
const auth = @import("policy/auth.zig");
const cli = @import("cli.zig");
const usage = cli.usage;

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
    var i: usize = 1;
    while (i < args.len and std.mem.startsWith(u8, args[i], "--")) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--db") and i + 1 < args.len) {
            i += 1;
            loc.db = args[i];
            db_given = true;
        } else if (std.mem.eql(u8, args[i], "--config") and i + 1 < args.len) {
            i += 1;
            loc.config = args[i];
        } else if (std.mem.eql(u8, args[i], "--users") and i + 1 < args.len) {
            i += 1;
            loc.users = args[i];
        } else if (std.mem.eql(u8, args[i], "--help")) {
            try out.writeAll(usage);
            return;
        } else break;
    }
    if (i >= args.len) {
        try out.writeAll(usage);
        return;
    }

    if (db_given and !loc.usesSqlite()) {
        std.log.err("--db is unused when both --config and --users are given", .{});
        std.process.exit(1);
    }
    var db = Db.openAt(gpa, io, loc) catch |e| {
        std.log.err("cannot open the store: {s}", .{@errorName(e)});
        std.process.exit(1);
    };
    defer db.close();

    var c: cli.Cli = .{ .gpa = gpa, .io = io, .db = &db, .out = out, .args = args[i..] };
    cli.run(&c) catch |e| {
        out.flush() catch {};
        if (e == error.Usage) {
            std.debug.print("{s}", .{usage});
        } else {
            std.debug.print("zsmbd: {s}\n", .{auth.describe(e)});
        }
        std.process.exit(1);
    };
}

test {
    _ = @import("cli.zig");
    _ = @import("policy/auth.zig");
    _ = @import("store/textconf.zig");
    _ = @import("store/textusers.zig");
    _ = @import("web/server.zig");
    _ = @import("smb/rpc.zig");
    _ = @import("smb/auth/ntlm.zig");
    _ = @import("smb/auth/spnego.zig");
    _ = @import("smb/vfs.zig");
    _ = @import("smb/files.zig");
    _ = @import("shared/crypto.zig");
    _ = @import("shared/wire.zig");
    _ = @import("nthash_wasm.zig");
    _ = @import("policy/strength.zig");
}
