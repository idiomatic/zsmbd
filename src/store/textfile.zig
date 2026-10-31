//! A plain-text file that zsmbd keeps in place of a SQLite table and that
//! may also be edited by hand: change detection, reading, and atomic
//! replacement. Shared by textconf.zig and textusers.zig.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const max_file = 16 * 1024 * 1024;

pub const Error = error{ Store, OutOfMemory };

/// File identity used to notice outside edits.
const Stamp = struct { inode: u64 = 0, size: u64 = 0, mtime: i96 = 0, exists: bool = false };

/// One text file: change detection, reading, and atomic replacement.
pub const File = struct {
    gpa: Allocator,
    io: Io,
    /// The directory holding the file (created if missing).
    dir: Io.Dir,
    /// The path as given, for messages.
    path: []u8,
    name: []const u8,
    stamp: Stamp = .{},
    /// The file on disk doesn't parse: lookups use the last good contents,
    /// and changes are refused so they can't overwrite the hand edit.
    broken: bool = false,

    pub fn open(gpa: Allocator, io: Io, path: []const u8) Error!File {
        const base = std.fs.path.basename(path);
        if (base.len == 0) return fail("{s}: expected a file name", .{path});
        const dir_path = std.fs.path.dirname(path) orelse ".";
        const cwd = Io.Dir.cwd();
        cwd.createDirPath(io, dir_path) catch |e| return fail("cannot create {s}: {s}", .{ dir_path, @errorName(e) });
        const dir = cwd.openDir(io, dir_path, .{}) catch |e| return fail("cannot open {s}: {s}", .{ dir_path, @errorName(e) });
        errdefer dir.close(io);
        const p = try gpa.dupe(u8, path);
        return .{ .gpa = gpa, .io = io, .dir = dir, .path = p, .name = p[p.len - base.len ..] };
    }

    pub fn close(f: *File) void {
        f.dir.close(f.io);
        f.gpa.free(f.path);
    }

    pub fn current(f: *File) Error!Stamp {
        const st = f.dir.statFile(f.io, f.name, .{}) catch |e| switch (e) {
            error.FileNotFound => return .{},
            else => return fail("cannot stat {s}: {s}", .{ f.path, @errorName(e) }),
        };
        return .{ .inode = @intCast(st.inode), .size = st.size, .mtime = st.mtime.nanoseconds, .exists = true };
    }

    /// The file's new contents when it changed since the last look, else null.
    pub fn changed(f: *File) Error!?[]u8 {
        const s = try f.current();
        if (std.meta.eql(s, f.stamp)) return null;
        const text = f.dir.readFileAlloc(f.io, f.name, f.gpa, .limited(max_file)) catch |e| switch (e) {
            error.FileNotFound => try f.gpa.alloc(u8, 0),
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail("cannot read {s}: {s}", .{ f.path, @errorName(e) }),
        };
        f.stamp = s;
        return text;
    }

    pub fn writable(f: *File) Error!void {
        if (f.broken) return fail("{s} has errors; fix it before making changes", .{f.path});
    }

    pub fn write(f: *File, data: []const u8, mode: std.posix.mode_t) Error!void {
        // On failure, the next lookup rereads the file.
        f.stamp = .{};
        var af = f.dir.createFileAtomic(f.io, f.name, .{ .replace = true, .permissions = .fromMode(mode) }) catch |e|
            return fail("cannot write {s}: {s}", .{ f.path, @errorName(e) });
        defer af.deinit(f.io);
        af.file.writeStreamingAll(f.io, data) catch |e| return fail("cannot write {s}: {s}", .{ f.path, @errorName(e) });
        af.file.sync(f.io) catch {};
        af.replace(f.io) catch |e| return fail("cannot replace {s}: {s}", .{ f.path, @errorName(e) });
        f.stamp = try f.current();
    }

    pub fn checkPrivate(f: *File) void {
        const st = f.dir.statFile(f.io, f.name, .{}) catch return;
        if (@hasDecl(Io.File.Permissions, "toMode") and st.permissions.toMode() & 0o077 != 0)
            std.log.warn("{s} is readable by other users; it holds password hashes (chmod 600)", .{f.path});
    }
};

/// Report a store problem. A warning, because a running server keeps
/// working with the last good contents; callers that can't go on log errors.
pub fn fail(comptime fmt: []const u8, args: anytype) error{Store} {
    std.log.warn(fmt, args);
    return error.Store;
}

pub fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r");
}

// ---------------------------------------------------------------- test helpers

const testing = std.testing;

pub fn tmpPath(tmp: *testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(testing.io, &dir_buf);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir_buf[0..n], name });
}

pub fn readBack(tmp: *testing.TmpDir, name: []const u8) ![]u8 {
    return tmp.dir.readFileAlloc(testing.io, name, testing.allocator, .limited(max_file));
}
