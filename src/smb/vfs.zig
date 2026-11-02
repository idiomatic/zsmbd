//! POSIX file system access for SMB: path resolution confined to a share root,
//! stat → SMB attribute mapping, directory listing, and errno → NTSTATUS.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const Allocator = std.mem.Allocator;
const proto = @import("proto.zig");
const Status = proto.Status;

const is_linux = builtin.os.tag == .linux;
const is_darwin = builtin.os.tag.isDarwin();

extern "c" fn close(fd: c_int) c_int;
extern "c" fn dup(fd: c_int) c_int;
extern "c" fn fsync(fd: c_int) c_int;

pub const Fd = c_int;

pub const Error = error{
    NotFound,
    PathNotFound,
    Exists,
    AccessDenied,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpace,
    NameTooLong,
    ReadOnlyFs,
    Invalid,
    TooManyFiles,
    Io,
    OutOfMemory,
};

pub fn mapErrno(e: c.E) Error {
    return switch (e) {
        .NOENT => error.NotFound,
        .EXIST => error.Exists,
        .ACCES, .PERM => error.AccessDenied,
        .NOTDIR => error.NotDir,
        .ISDIR => error.IsDir,
        .NOTEMPTY => error.NotEmpty,
        .NOSPC, .DQUOT => error.NoSpace,
        .NAMETOOLONG => error.NameTooLong,
        .ROFS => error.ReadOnlyFs,
        .LOOP => error.AccessDenied,
        .MFILE, .NFILE => error.TooManyFiles,
        .INVAL => error.Invalid,
        .NOMEM => error.OutOfMemory,
        else => error.Io,
    };
}

pub fn status(err: anyerror) u32 {
    return switch (err) {
        error.NotFound => Status.object_name_not_found,
        error.PathNotFound => Status.object_path_not_found,
        error.Exists => Status.object_name_collision,
        error.AccessDenied => Status.access_denied,
        error.NotDir => Status.not_a_directory,
        error.IsDir => Status.file_is_a_directory,
        error.NotEmpty => Status.directory_not_empty,
        error.NoSpace => Status.disk_full,
        error.NameTooLong => Status.name_too_long,
        error.ReadOnlyFs => Status.media_write_protected,
        error.Invalid => Status.invalid_parameter,
        error.TooManyFiles => Status.too_many_opened_files,
        error.OutOfMemory => Status.insufficient_resources,
        error.Malformed => Status.invalid_parameter,
        else => Status.unexpected_io_error,
    };
}

inline fn check(rc: c_int) Error!void {
    if (rc == -1) return mapErrno(c.errno(rc));
}

pub const Kind = enum { file, dir, symlink, other };

pub const Info = struct {
    dev: u64,
    ino: u64,
    kind: Kind,
    mode: u32,
    nlink: u32,
    size: u64,
    alloc: u64,
    /// NT times (100ns since 1601).
    atime: u64,
    mtime: u64,
    ctime: u64,
    btime: u64,

    pub fn isDir(i: Info) bool {
        return i.kind == .dir;
    }

    /// DOS attributes for an entry (name is the final path component).
    pub fn attributes(i: Info, name: []const u8) u32 {
        var a: u32 = 0;
        if (i.kind == .dir) a |= proto.Attr.directory else a |= proto.Attr.archive;
        if (i.kind != .dir and i.mode & 0o222 == 0) a |= proto.Attr.readonly;
        if (name.len > 1 and name[0] == '.' and !std.mem.eql(u8, name, "..")) a |= proto.Attr.hidden;
        return a;
    }

    pub fn fileId(i: Info) u64 {
        return i.ino;
    }
};

fn ts(sec: anytype, nsec: anytype) u64 {
    return proto.unixToNt(@intCast(sec), @intCast(nsec));
}

fn kindOf(mode: u32) Kind {
    return switch (mode & 0o170000) {
        0o040000 => .dir,
        0o100000 => .file,
        0o120000 => .symlink,
        else => .other,
    };
}

fn fromStat(st: *const c.Stat) Info {
    const mode: u32 = @intCast(st.mode);
    const mt = st.mtime();
    const bt = if (@hasDecl(c.Stat, "birthtime")) st.birthtime() else mt;
    return .{
        .dev = @bitCast(@as(i64, st.dev)),
        .ino = @intCast(st.ino),
        .kind = kindOf(mode),
        .mode = mode,
        .nlink = @intCast(st.nlink),
        .size = @intCast(@max(st.size, 0)),
        .alloc = @as(u64, @intCast(@max(st.blocks, 0))) * 512,
        .atime = ts(st.atime().sec, st.atime().nsec),
        .mtime = ts(mt.sec, mt.nsec),
        .ctime = ts(st.ctime().sec, st.ctime().nsec),
        .btime = ts(bt.sec, bt.nsec),
    };
}

fn fromStatx(st: *const std.os.linux.Statx) Info {
    const mode: u32 = st.mode;
    const bt = if (st.mask.BTIME) st.btime else if (st.ctime.sec < st.mtime.sec) st.ctime else st.mtime;
    return .{
        .dev = (@as(u64, st.dev_major) << 32) | st.dev_minor,
        .ino = st.ino,
        .kind = kindOf(mode),
        .mode = mode,
        .nlink = st.nlink,
        .size = st.size,
        .alloc = st.blocks * 512,
        .atime = ts(st.atime.sec, st.atime.nsec),
        .mtime = ts(st.mtime.sec, st.mtime.nsec),
        .ctime = ts(st.ctime.sec, st.ctime.nsec),
        .btime = ts(bt.sec, bt.nsec),
    };
}

const AT_EMPTY_PATH = 0x1000;

fn statxMask() std.os.linux.STATX {
    return .{ .TYPE = true, .MODE = true, .NLINK = true, .UID = true, .GID = true, .ATIME = true, .MTIME = true, .CTIME = true, .INO = true, .SIZE = true, .BLOCKS = true, .BTIME = true };
}

pub fn statFd(fd: Fd) Error!Info {
    if (is_linux) {
        var st: std.os.linux.Statx = undefined;
        try check(c.statx(fd, "", AT_EMPTY_PATH, statxMask(), &st));
        return fromStatx(&st);
    } else {
        var st: c.Stat = undefined;
        try check(c.fstat(fd, &st));
        return fromStat(&st);
    }
}

pub fn statAt(dirfd: Fd, name: [*:0]const u8, follow: bool) Error!Info {
    const flags: u32 = if (follow) 0 else c.AT.SYMLINK_NOFOLLOW;
    if (is_linux) {
        var st: std.os.linux.Statx = undefined;
        try check(c.statx(dirfd, name, flags, statxMask(), &st));
        return fromStatx(&st);
    } else {
        var st: c.Stat = undefined;
        try check(c.fstatat(dirfd, name, &st, @intCast(flags)));
        return fromStat(&st);
    }
}

pub fn lstatPath(path: [:0]const u8) Error!Info {
    return statAt(c.AT.FDCWD, path.ptr, false);
}

pub fn statPath(path: [:0]const u8) Error!Info {
    return statAt(c.AT.FDCWD, path.ptr, true);
}

pub const OpenMode = enum { read, write, rdwr };

pub fn openFile(path: [:0]const u8, mode: OpenMode, create: bool, excl: bool, trunc: bool) Error!Fd {
    var o: c.O = .{ .CLOEXEC = true, .NOFOLLOW = true };
    o.ACCMODE = switch (mode) {
        .read => .RDONLY,
        .write => .WRONLY,
        .rdwr => .RDWR,
    };
    o.CREAT = create;
    o.EXCL = excl;
    o.TRUNC = trunc;
    while (true) {
        const fd = c.openat(c.AT.FDCWD, path.ptr, o, @as(c_uint, 0o666));
        if (fd >= 0) return fd;
        const e = c.errno(fd);
        if (e == .INTR) continue;
        return mapErrno(e);
    }
}

pub fn openDir(path: [:0]const u8) Error!Fd {
    const o: c.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true };
    const fd = c.openat(c.AT.FDCWD, path.ptr, o, @as(c_uint, 0));
    if (fd < 0) return mapErrno(c.errno(fd));
    return fd;
}

pub fn closeFd(fd: Fd) void {
    _ = close(fd);
}

pub fn mkdir(path: [:0]const u8) Error!void {
    try check(c.mkdirat(c.AT.FDCWD, path.ptr, 0o777));
}

pub fn unlink(path: [:0]const u8, is_dir: bool) Error!void {
    try check(c.unlinkat(c.AT.FDCWD, path.ptr, if (is_dir) c.AT.REMOVEDIR else 0));
}

pub fn rename(old: [:0]const u8, new: [:0]const u8) Error!void {
    try check(c.renameat(c.AT.FDCWD, old.ptr, c.AT.FDCWD, new.ptr));
}

/// Offsets and sizes come from clients; POSIX takes a signed 64-bit off_t.
fn checkRange(off: u64, len: usize) Error!void {
    const max: u64 = std.math.maxInt(i64);
    if (off > max or len > max - off) return error.Invalid;
}

pub fn pread(fd: Fd, buf: []u8, off: u64) Error!usize {
    try checkRange(off, buf.len);
    while (true) {
        const n = c.pread(fd, buf.ptr, buf.len, @intCast(off));
        if (n >= 0) return @intCast(n);
        const e = c.errno(n);
        if (e == .INTR) continue;
        return mapErrno(e);
    }
}

pub fn pwriteAll(fd: Fd, buf: []const u8, off: u64) Error!void {
    try checkRange(off, buf.len);
    var done: usize = 0;
    while (done < buf.len) {
        const n = c.pwrite(fd, buf[done..].ptr, buf.len - done, @intCast(off + done));
        if (n < 0) {
            const e = c.errno(n);
            if (e == .INTR) continue;
            return mapErrno(e);
        }
        done += @intCast(n);
    }
}

pub fn truncate(fd: Fd, size: u64) Error!void {
    try checkRange(size, 0);
    try check(c.ftruncate(fd, @intCast(size)));
}

pub fn sync(fd: Fd) Error!void {
    try check(fsync(fd));
}

pub fn chmod(fd: Fd, mode: u32) Error!void {
    try check(c.fchmod(fd, @intCast(mode & 0o7777)));
}

/// Never follows a symlink. musl implements the flag through /proc and
/// reports it unsupported without it, as glibc does on a link; then the
/// entry is checked by hand.
pub fn chmodPath(path: [:0]const u8, mode: u32) Error!void {
    const m: c.mode_t = @intCast(mode & 0o7777);
    const rc = c.fchmodat(c.AT.FDCWD, path.ptr, m, c.AT.SYMLINK_NOFOLLOW);
    if (rc != -1) return;
    const e = c.errno(rc);
    if (!isNotSupported(e)) return mapErrno(e);
    if ((try lstatPath(path)).kind == .symlink) return error.AccessDenied;
    try check(c.fchmodat(c.AT.FDCWD, path.ptr, m, 0));
}

fn isNotSupported(e: c.E) bool {
    const op = if (@hasField(c.E, "OPNOTSUPP")) e == .OPNOTSUPP else false;
    const ns = if (@hasField(c.E, "NOTSUP")) e == .NOTSUP else false;
    return op or ns;
}

fn timespecs(atime_nt: ?u64, mtime_nt: ?u64) [2]c.timespec {
    var t: [2]c.timespec = .{ c.UTIME.OMIT, c.UTIME.OMIT };
    if (atime_nt) |v| {
        const u = proto.ntToUnix(v);
        t[0] = .{ .sec = @intCast(u.sec), .nsec = @intCast(u.nsec) };
    }
    if (mtime_nt) |v| {
        const u = proto.ntToUnix(v);
        t[1] = .{ .sec = @intCast(u.sec), .nsec = @intCast(u.nsec) };
    }
    return t;
}

/// Set access/modify times; null leaves a time unchanged.
pub fn setTimes(fd: Fd, atime_nt: ?u64, mtime_nt: ?u64) Error!void {
    const t = timespecs(atime_nt, mtime_nt);
    try check(c.futimens(fd, &t));
}

pub fn setTimesPath(path: [:0]const u8, atime_nt: ?u64, mtime_nt: ?u64) Error!void {
    const t = timespecs(atime_nt, mtime_nt);
    try check(c.utimensat(c.AT.FDCWD, path.ptr, &t, c.AT.SYMLINK_NOFOLLOW));
}

/// realpath(3) into an allocated string.
pub fn realpath(gpa: Allocator, path: [:0]const u8) Error![:0]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const r = c.realpath(path.ptr, &buf) orelse return mapErrno(c.errno(@as(c_int, -1)));
    return try gpa.dupeSentinel(u8, std.mem.sliceTo(r, 0), 0);
}

// ---------------------------------------------------------------- directory listing

pub fn listDir(gpa: Allocator, dirfd: Fd) Error![][]u8 {
    const o: c.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const fd = c.openat(dirfd, ".", o, @as(c_uint, 0));
    if (fd < 0) return mapErrno(c.errno(fd));
    const d = c.fdopendir(fd) orelse {
        _ = close(fd);
        return error.Io;
    };
    defer _ = c.closedir(d);
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |n| gpa.free(n);
        out.deinit(gpa);
    }
    while (c.readdir(d)) |ent| {
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        try out.append(gpa, try gpa.dupe(u8, name));
    }
    return out.toOwnedSlice(gpa);
}

pub fn freeList(gpa: Allocator, names: [][]u8) void {
    for (names) |n| gpa.free(n);
    gpa.free(names);
}

// ---------------------------------------------------------------- volume info

pub const VolInfo = struct { block_size: u64, total: u64, free: u64, avail: u64 };

const StatvfsLinux = extern struct {
    f_bsize: c_ulong,
    f_frsize: c_ulong,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: c_ulong,
    f_flag: c_ulong,
    f_namemax: c_ulong,
    __spare: [6]c_int,
};

const StatfsDarwin = extern struct {
    f_bsize: u32,
    f_iosize: i32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_owner: u32,
    f_type: u32,
    f_flags: u32,
    f_fssubtype: u32,
    f_fstypename: [16]u8,
    f_mntonname: [1024]u8,
    f_mntfromname: [1024]u8,
    f_flags_ext: u32,
    f_reserved: [7]u32,
};

const sys = struct {
    extern "c" fn fstatvfs(fd: c_int, buf: *StatvfsLinux) c_int;
    extern "c" fn fstatfs(fd: c_int, buf: *StatfsDarwin) c_int;
};

pub fn volInfo(fd: Fd) Error!VolInfo {
    if (is_darwin) {
        var s: StatfsDarwin = undefined;
        try check(sys.fstatfs(fd, &s));
        return .{ .block_size = s.f_bsize, .total = s.f_blocks, .free = s.f_bfree, .avail = s.f_bavail };
    } else {
        var s: StatvfsLinux = undefined;
        try check(sys.fstatvfs(fd, &s));
        const bs: u64 = if (s.f_frsize != 0) s.f_frsize else s.f_bsize;
        return .{ .block_size = bs, .total = s.f_blocks, .free = s.f_bfree, .avail = s.f_bavail };
    }
}

// ---------------------------------------------------------------- path handling

pub const PathError = error{ Invalid, OutOfMemory };

/// Convert an SMB path (UTF-8 already, backslash separated, relative to the share)
/// into a normalized '/'-separated relative path. Rejects "..", stream names and
/// characters that are illegal in Windows names. Empty result = share root.
pub fn normalize(gpa: Allocator, smb_path: []const u8) PathError![]u8 {
    var p = smb_path;
    // The default data stream suffix refers to the file itself.
    if (std.ascii.endsWithIgnoreCase(p, "::$DATA")) p = p[0 .. p.len - 7];
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var it = std.mem.splitScalar(u8, p, '\\');
    while (it.next()) |comp| {
        if (comp.len == 0) continue;
        if (std.mem.eql(u8, comp, ".")) continue;
        if (std.mem.eql(u8, comp, "..")) return error.Invalid;
        for (comp) |ch| {
            if (ch < 0x20) return error.Invalid;
            switch (ch) {
                '/', ':', '*', '?', '"', '<', '>', '|' => return error.Invalid,
                else => {},
            }
        }
        if (out.items.len > 0) try out.append(gpa, '/');
        try out.appendSlice(gpa, comp);
    }
    return out.toOwnedSlice(gpa);
}

pub const Resolved = struct {
    /// Absolute host path (symlinks inside the share resolved).
    path: [:0]u8,
    info: ?Info,
};

fn underRoot(root: []const u8, p: []const u8) bool {
    if (std.mem.eql(u8, root, "/")) return true;
    if (!std.mem.startsWith(u8, p, root)) return false;
    return p.len == root.len or p[root.len] == '/';
}

fn joinZ(gpa: Allocator, a: []const u8, b: []const u8) ![:0]u8 {
    if (a.len > 0 and a[a.len - 1] == '/') return std.fmt.allocPrintSentinel(gpa, "{s}{s}", .{ a, b }, 0);
    return std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ a, b }, 0);
}

/// Case-insensitive match of a single component within `dir`.
fn findCaseless(gpa: Allocator, dir: [:0]const u8, name: []const u8) Error!?[]u8 {
    const fd = openDir(dir) catch return null;
    defer closeFd(fd);
    const names = try listDir(gpa, fd);
    defer freeList(gpa, names);
    for (names) |n| {
        if (eqlFold(n, name)) return try gpa.dupe(u8, n);
    }
    return null;
}

pub fn eqlFold(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Resolve a normalized relative path inside `root` (an absolute realpath).
/// Missing final components yield `info == null`; missing intermediate
/// components yield error.PathNotFound. Symlinks are followed only when their
/// target stays inside the share.
pub fn resolve(gpa: Allocator, root: []const u8, rel: []const u8) Error!Resolved {
    var cur: [:0]u8 = try gpa.dupeSentinel(u8, root, 0);
    errdefer gpa.free(cur);
    if (rel.len == 0) {
        return .{ .path = cur, .info = try statPath(cur) };
    }
    var it = std.mem.splitScalar(u8, rel, '/');
    var info: ?Info = null;
    while (it.next()) |comp| {
        const last = it.peek() == null;
        var cand = try joinZ(gpa, cur, comp);
        var st = lstatPath(cand) catch |e| switch (e) {
            error.NotFound => blk: {
                if (try findCaseless(gpa, cur, comp)) |real| {
                    defer gpa.free(real);
                    gpa.free(cand);
                    cand = try joinZ(gpa, cur, real);
                    break :blk lstatPath(cand) catch null;
                }
                break :blk null;
            },
            error.NotDir => {
                gpa.free(cand);
                return error.PathNotFound;
            },
            else => |x| {
                gpa.free(cand);
                return x;
            },
        };
        if (st) |s| if (s.kind == .symlink) {
            const rp = realpath(gpa, cand) catch {
                gpa.free(cand);
                // Dangling or looping link: treat as absent (it cannot be opened).
                if (last) return error.NotFound;
                return error.PathNotFound;
            };
            if (!underRoot(root, rp)) {
                gpa.free(rp);
                gpa.free(cand);
                return error.AccessDenied;
            }
            gpa.free(cand);
            cand = rp;
            st = try statPath(cand);
        };
        gpa.free(cur);
        cur = cand;
        if (st == null) {
            if (!last) return error.PathNotFound;
            info = null;
            break;
        }
        if (!last and st.?.kind != .dir) return error.PathNotFound;
        info = st;
    }
    return .{ .path = cur, .info = info };
}

pub fn basename(p: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, p, '/') orelse return p;
    return p[i + 1 ..];
}

pub fn dirname(p: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, p, '/') orelse return ".";
    if (i == 0) return "/";
    return p[0..i];
}

// ---------------------------------------------------------------- wildcard matching

fn lower(ch: u8) u8 {
    return std.ascii.toLower(ch);
}

/// Longest pattern or name `wildcardMatch` considers; longer ones never
/// match. A component is at most 255 UTF-16 units, so 1024 UTF-8 bytes.
pub const max_match_len = 1024;

/// Windows-style wildcard match (case-insensitive), including DOS wildcards
/// `<` (DOS_STAR), `>` (DOS_QM) and `"` (DOS_DOT).
///
/// The pattern comes from the client, so this runs in O(pattern × name) time
/// with a table, never backtracking (a recursive matcher is exponential on
/// patterns like `*a*a*a*a*b`).
pub fn wildcardMatch(pat: []const u8, name: []const u8) bool {
    if (pat.len == 0 or std.mem.eql(u8, pat, "*") or std.mem.eql(u8, pat, "*.*")) return true;
    if (pat.len > max_match_len or name.len > max_match_len) return false;
    const n = name.len;
    const last_dot = std.mem.lastIndexOfScalar(u8, name, '.');
    // next[j]: pat[i+1..] matches name[j..]; cur[j]: pat[i..] matches name[j..].
    var a: [max_match_len + 1]bool = undefined;
    var b: [max_match_len + 1]bool = undefined;
    var next = a[0 .. n + 1];
    var cur = b[0 .. n + 1];
    @memset(next, false);
    next[n] = true; // the empty pattern matches only the empty name
    var i = pat.len;
    while (i > 0) {
        i -= 1;
        switch (pat[i]) {
            '*' => {
                var acc = false;
                var j = n + 1;
                while (j > 0) {
                    j -= 1;
                    acc = acc or next[j];
                    cur[j] = acc;
                }
            },
            '<' => {
                // Zero or more characters, up to and including the final '.'.
                var acc = false;
                var j = n + 1;
                while (j > 0) {
                    j -= 1;
                    if (last_dot) |l| if (j == l) {
                        acc = false;
                    };
                    acc = acc or next[j];
                    cur[j] = acc;
                }
            },
            '?' => for (cur, 0..) |*m, j| {
                m.* = j < n and next[j + 1];
            },
            '>' => for (cur, 0..) |*m, j| {
                m.* = if (j == n or name[j] == '.') next[j] else next[j + 1];
            },
            '"' => for (cur, 0..) |*m, j| {
                m.* = if (j == n) next[j] else name[j] == '.' and next[j + 1];
            },
            else => |ch| for (cur, 0..) |*m, j| {
                m.* = j < n and lower(ch) == lower(name[j]) and next[j + 1];
            },
        }
        std.mem.swap([]bool, &next, &cur);
    }
    return next[0];
}

test "wildcards" {
    try std.testing.expect(wildcardMatch("*", "abc"));
    try std.testing.expect(wildcardMatch("*.TXT", "notes.txt"));
    try std.testing.expect(!wildcardMatch("*.txt", "notes.doc"));
    try std.testing.expect(wildcardMatch("a?c", "abc"));
    try std.testing.expect(wildcardMatch("<.txt", "x.y.txt"));
    try std.testing.expect(wildcardMatch("Foo", "foo"));
}

test "normalize" {
    const gpa = std.testing.allocator;
    const a = try normalize(gpa, "\\dir\\sub\\file.txt");
    defer gpa.free(a);
    try std.testing.expectEqualStrings("dir/sub/file.txt", a);
    try std.testing.expectError(error.Invalid, normalize(gpa, "a\\..\\b"));
    try std.testing.expectError(error.Invalid, normalize(gpa, "file:stream"));
    const b = try normalize(gpa, "file::$DATA");
    defer gpa.free(b);
    try std.testing.expectEqualStrings("file", b);
}

/// The original recursive matcher, kept as a reference for the fuzz test.
fn matchSlow(pat: []const u8, name: []const u8) bool {
    if (pat.len == 0) return name.len == 0;
    switch (pat[0]) {
        '*' => {
            var i: usize = 0;
            while (i <= name.len) : (i += 1) if (matchSlow(pat[1..], name[i..])) return true;
            return false;
        },
        '<' => {
            var i: usize = 0;
            while (i <= name.len) : (i += 1) {
                if (matchSlow(pat[1..], name[i..])) return true;
                if (i < name.len and name[i] == '.' and std.mem.indexOfScalar(u8, name[i + 1 ..], '.') == null) {
                    return matchSlow(pat[1..], name[i..]);
                }
            }
            return false;
        },
        '?' => return name.len > 0 and matchSlow(pat[1..], name[1..]),
        '>' => {
            if (name.len == 0 or name[0] == '.') return matchSlow(pat[1..], name);
            return matchSlow(pat[1..], name[1..]);
        },
        '"' => {
            if (name.len == 0) return matchSlow(pat[1..], name);
            return name[0] == '.' and matchSlow(pat[1..], name[1..]);
        },
        else => return name.len > 0 and lower(pat[0]) == lower(name[0]) and matchSlow(pat[1..], name[1..]),
    }
}

const fuzz = @import("../shared/fuzz.zig");

test "fuzz: wildcardMatch agrees with the reference matcher" {
    try fuzz.run({}, struct {
        fn one(_: void, in: []const u8) !void {
            // "pattern\x00name", both short enough for the slow matcher.
            const z = std.mem.indexOfScalar(u8, in, 0) orelse in.len;
            const pat = in[0..@min(z, 12)];
            const name = if (z < in.len) in[z + 1 .. @min(in.len, z + 1 + 16)] else "";
            const fast = wildcardMatch(pat, name);
            const ref = pat.len == 0 or std.mem.eql(u8, pat, "*") or std.mem.eql(u8, pat, "*.*") or matchSlow(pat, name);
            try std.testing.expectEqual(ref, fast);
        }
    }.one, &.{ "*.txt\x00notes.txt", "<.txt\x00x.y.txt", "a?c\x00abc", "\"*>\x00a.b.c", "*a*a*\x00aaaa.a", "<\"<\x00.." });
}

test "wildcardMatch is fast on backtracking patterns" {
    const pat = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
    const name: [200]u8 = @splat('a');
    try std.testing.expect(!wildcardMatch(pat, &name));
    const dos: [1000]u8 = @splat('<');
    const long: [1000]u8 = @splat('x');
    try std.testing.expect(!wildcardMatch(&dos, &long ++ "."));
}

test "fuzz: normalize never yields a path that leaves the share" {
    try fuzz.run({}, struct {
        fn one(_: void, in: []const u8) !void {
            const p = normalize(std.testing.allocator, in) catch return;
            defer std.testing.allocator.free(p);
            if (p.len == 0) return; // the share root
            var it = std.mem.splitScalar(u8, p, '/');
            while (it.next()) |comp| {
                try std.testing.expect(comp.len > 0 and !std.mem.eql(u8, comp, "..") and !std.mem.eql(u8, comp, "."));
                try std.testing.expect(std.mem.indexOfAny(u8, comp, ":\\*?\"<>|") == null);
            }
        }
    }.one, &.{ "\\dir\\sub\\file.txt", "a\\..\\b", "file::$DATA", "\\\\.\\x", "a/b" });
}

test "client offsets beyond off_t are refused, not trapped" {
    try std.testing.expectError(error.Invalid, pread(-1, &.{}, std.math.maxInt(u64)));
    try std.testing.expectError(error.Invalid, pwriteAll(-1, "x", std.math.maxInt(i64)));
    try std.testing.expectError(error.Invalid, truncate(-1, 1 << 63));
}
