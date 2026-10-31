//! SMB2 file commands: CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL,
//! QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, and SET_INFO, on top of
//! vfs.zig and the server's node table (share modes, delete-pending, and
//! byte-range locks).
//!
//! The connection handler verifies the session, tree, and signature, then
//! calls `dispatch` with the whole message (header and body) and an output
//! buffer that already holds the 64-byte response header. `dispatch` appends
//! the response body (or an error body) and returns the status; the handler
//! fills in the header.

const std = @import("std");
const Allocator = std.mem.Allocator;
const proto = @import("proto.zig");
const Status = proto.Status;
const Access = proto.Access;
const ShareAccess = proto.ShareAccess;
const Disposition = proto.Disposition;
const CreateOptions = proto.CreateOptions;
const FileInfo = proto.FileInfo;
const FsInfo = proto.FsInfo;
const Fsctl = proto.Fsctl;
const wire = @import("../shared/wire.zig");
const Buf = wire.Buf;
const vfs = @import("vfs.zig");
const rpc = @import("rpc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;
const Session = conn_mod.Session;
const Tree = conn_mod.Tree;
const Open = conn_mod.Open;
const state = @import("server.zig");
const Server = state.Server;
const Node = state.Node;
const db_mod = @import("../store/store.zig");

const max_io_size = conn_mod.max_io_size;
const hdr = proto.header_size;

pub const FileId = struct {
    persistent: u64,
    volatile_: u64,

    pub const none: FileId = .{ .persistent = std.math.maxInt(u64), .volatile_ = std.math.maxInt(u64) };

    pub fn isNone(f: FileId) bool {
        return f.persistent == none.persistent and f.volatile_ == none.volatile_;
    }

    fn get(b: []const u8, off: usize) FileId {
        return .{ .persistent = wire.get64(b, off), .volatile_ = wire.get64(b, off + 8) };
    }

    fn put(f: FileId, out: *Buf) !void {
        try out.u64_(f.persistent);
        try out.u64_(f.volatile_);
    }
};

/// What NEGOTIATE settled, kept by the connection; VALIDATE_NEGOTIATE_INFO
/// compares the client's claim against it.
pub const Negotiated = struct {
    dialect: u16 = 0,
    cipher: u16 = proto.Cipher.aes128_ccm,
    server_caps: u32 = 0,
    server_security_mode: u16 = 0,
    server_guid: [16]u8 = @splat(0),
    client_caps: u32 = 0,
    client_security_mode: u16 = 0,
    client_guid: [16]u8 = @splat(0),
    client_dialects: [16]u16 = @splat(0),
    client_dialect_count: u8 = 0,
};

/// A connection's open handles, keyed by volatile file ID. Only the
/// connection's own thread changes it, under the server lock.
pub const Opens = struct {
    map: std.AutoHashMapUnmanaged(u64, *Open) = .empty,
};

pub const Ctx = struct {
    conn: *Conn,
    session: *Session,
    tree: *Tree,
    /// File ID from the previous request of a related compound.
    related: ?FileId = null,

    fn gpa(ctx: *const Ctx) Allocator {
        return ctx.conn.gpa;
    }
    fn srv(ctx: *const Ctx) *Server {
        return ctx.conn.srv;
    }
};

pub const Reply = struct {
    status: u32,
    /// File ID for the next related request (set by CREATE).
    fid: ?FileId = null,
    /// A CHANGE_NOTIFY to queue with `Conn.queueNotify` (status is PENDING).
    notify: ?conn_mod.Notify = null,
    /// Keep the body written for an error status (copy-chunk limits,
    /// security descriptor size).
    keep_body: bool = false,
    /// Drop the connection (failed VALIDATE_NEGOTIATE_INFO).
    disconnect: bool = false,
};

fn st(s: u32) Reply {
    return .{ .status = s };
}

fn isError(s: u32) bool {
    return s >= 0xC0000000;
}

pub fn handles(cmd: proto.Command) bool {
    return switch (cmd) {
        .create, .close, .flush, .read, .write, .lock, .ioctl, .query_directory, .change_notify, .query_info, .set_info => true,
        else => false,
    };
}

pub fn dispatch(ctx: *Ctx, cmd: proto.Command, msg: []const u8, out: *Buf) Reply {
    std.debug.assert(out.len() == hdr and msg.len >= hdr);
    var r = run(ctx, cmd, msg, out) catch |e| st(vfs.status(e));
    if (isError(r.status) and !r.keep_body) out.list.shrinkRetainingCapacity(hdr);
    if (r.status != Status.success and out.len() == hdr) errorBody(out) catch {
        r = st(Status.insufficient_resources);
    };
    return r;
}

/// The SMB2 ERROR response body (also the body of interim responses).
pub fn errorBody(out: *Buf) !void {
    try out.u16_(9);
    try out.u16_(0);
    try out.u32_(0);
    try out.u8_(0);
}

/// Body of a CHANGE_NOTIFY completion with no change records.
pub fn notifyBody(out: *Buf) !void {
    try out.u16_(9);
    try out.u16_(hdr + 8);
    try out.u32_(0);
    try out.u8_(0);
}

fn run(ctx: *Ctx, cmd: proto.Command, msg: []const u8, out: *Buf) !Reply {
    const b = msg[hdr..];
    return switch (cmd) {
        .create => create(ctx, msg, b, out),
        .close => close(ctx, b, out),
        .flush => flush(ctx, b, out),
        .read => read(ctx, b, out),
        .write => write(ctx, msg, b, out),
        .lock => lock(ctx, b, out),
        .ioctl => ioctl(ctx, msg, b, out),
        .query_directory => queryDirectory(ctx, msg, b, out),
        .change_notify => changeNotify(ctx, msg, b),
        .query_info => queryInfo(ctx, b, out),
        .set_info => setInfo(ctx, msg, b, out),
        else => st(Status.not_supported),
    };
}

fn need(b: []const u8, n: usize) !void {
    if (b.len < n) return error.Malformed;
}

fn lookup(ctx: *Ctx, b: []const u8, off: usize) ?*Open {
    var fid = FileId.get(b, off);
    if (fid.isNone()) fid = ctx.related orelse return null;
    const o = ctx.conn.opens.map.get(fid.volatile_) orelse return null;
    if (o.persistent_id != fid.persistent or o.session_id != ctx.session.id or o.tree != ctx.tree) return null;
    return o;
}

fn utf16Arg(gpa: Allocator, msg: []const u8, off: usize, len: usize) ![]u8 {
    if (len == 0) return gpa.alloc(u8, 0);
    return wire.utf16ToUtf8(gpa, try wire.slice(msg, off, len));
}

/// Share-relative path in Windows form: "dir\file", with a leading
/// backslash when `leading`.
fn winPath(gpa: Allocator, rel: []const u8, leading: bool) ![]u8 {
    const p = try gpa.alloc(u8, rel.len + @intFromBool(leading));
    if (leading) p[0] = '\\';
    for (rel, p[@intFromBool(leading)..]) |ch, *d| d.* = if (ch == '/') '\\' else ch;
    return p;
}

/// Copy of a node's host path, taken under the server lock (renames on
/// other connections rewrite it).
fn nodePath(srv: *Server, gpa: Allocator, n: *Node) ![:0]u8 {
    srv.lock();
    defer srv.unlock();
    return gpa.dupeSentinel(u8, n.path, 0);
}

fn statOpen(srv: *Server, gpa: Allocator, o: *Open) !vfs.Info {
    if (o.fd >= 0) return vfs.statFd(o.fd);
    const p = try nodePath(srv, gpa, o.node orelse return error.Invalid);
    defer gpa.free(p);
    return vfs.statPath(p);
}

const pipe_info: vfs.Info = .{ .dev = 0, .ino = 0, .kind = .file, .mode = 0o600, .nlink = 1, .size = 0, .alloc = 0, .atime = 0, .mtime = 0, .ctime = 0, .btime = 0 };

fn infoOf(ctx: *Ctx, o: *Open) !vfs.Info {
    if (o.kind == .pipe) return pipe_info;
    return statOpen(ctx.srv(), ctx.gpa(), o);
}

fn attrsOf(i: vfs.Info, o: *const Open) u32 {
    if (o.kind == .pipe) return proto.Attr.normal;
    return i.attributes(vfs.basename(o.rel_path));
}

/// End of file and allocation size as SMB reports them (zero for directories).
fn sizes(i: vfs.Info) struct { eof: u64, alloc: u64 } {
    if (i.isDir()) return .{ .eof = 0, .alloc = 0 };
    return .{ .eof = i.size, .alloc = i.alloc };
}

fn times(out: *Buf, i: vfs.Info) !void {
    try out.u64_(i.btime);
    try out.u64_(i.atime);
    try out.u64_(i.mtime);
    try out.u64_(i.ctime);
}

fn parentChanged(ctx: *Ctx, host_path: []const u8) void {
    ctx.srv().dirChanged(vfs.dirname(host_path), ctx.conn);
}

// ---------------------------------------------------------------- access

fn mapGeneric(a: u32) u32 {
    var r = a & ~(Access.generic_all | Access.generic_execute | Access.generic_write | Access.generic_read);
    if (a & Access.generic_all != 0) r |= Access.file_all;
    if (a & Access.generic_execute != 0) r |= Access.file_generic_execute;
    if (a & Access.generic_write != 0) r |= Access.file_generic_write;
    if (a & Access.generic_read != 0) r |= Access.file_generic_read;
    return r;
}

const read_rights = Access.read_data | Access.execute;
const write_rights = Access.write_data | Access.append_data;
const data_rights = read_rights | write_rights | Access.delete;

/// True when an open with `access`/`share` conflicts with the node's opens.
fn shareConflict(n: *const Node, access: u32, share: u32) bool {
    if (access & data_rights == 0) return false;
    for (n.opens.items) |e| {
        if (e.access & data_rights == 0) continue;
        if (access & read_rights != 0 and e.share_access & ShareAccess.read == 0) return true;
        if (access & write_rights != 0 and e.share_access & ShareAccess.write == 0) return true;
        if (access & Access.delete != 0 and e.share_access & ShareAccess.delete == 0) return true;
        if (e.access & read_rights != 0 and share & ShareAccess.read == 0) return true;
        if (e.access & write_rights != 0 and share & ShareAccess.write == 0) return true;
        if (e.access & Access.delete != 0 and share & ShareAccess.delete == 0) return true;
    }
    return false;
}

/// True when a READ (or WRITE) of the range conflicts with byte-range locks.
/// Exclusive locks of other opens block both; shared locks block writes,
/// including the owner's.
fn lockConflict(srv: *Server, o: *Open, off: u64, len: u64, is_write: bool) bool {
    if (len == 0) return false;
    srv.lock();
    defer srv.unlock();
    const n = o.node orelse return false;
    for (n.locks.items) |l| {
        if (!l.overlaps(off, len)) continue;
        if (l.owner == o) {
            if (is_write and !l.exclusive) return true;
        } else if (is_write or l.exclusive) return true;
    }
    return false;
}

// ---------------------------------------------------------------- CREATE

const CreateCtxs = struct { mxac: bool = false, qfid: bool = false };

fn parseCreateContexts(blob: []const u8) !CreateCtxs {
    var r: CreateCtxs = .{};
    var p: usize = 0;
    while (true) {
        const c = try wire.slice(blob, p, 16);
        const name = try wire.slice(blob, p + wire.get16(c, 4), wire.get16(c, 6));
        if (std.mem.eql(u8, name, "MxAc")) r.mxac = true;
        if (std.mem.eql(u8, name, "QFid")) r.qfid = true;
        const next = wire.get32(c, 0);
        if (next == 0) return r;
        if (next < 16) return error.Malformed;
        p += next;
    }
}

fn create(ctx: *Ctx, msg: []const u8, b: []const u8, out: *Buf) !Reply {
    const gpa = ctx.gpa();
    const srv = ctx.srv();
    try need(b, 56);
    const desired = wire.get32(b, 24);
    const attrs = wire.get32(b, 28);
    const share = wire.get32(b, 32) & 7;
    const disp = wire.get32(b, 36);
    const opts = wire.get32(b, 40);
    if (disp > Disposition.overwrite_if) return st(Status.invalid_parameter);
    if (opts & CreateOptions.directory_file != 0 and opts & CreateOptions.non_directory_file != 0) return st(Status.invalid_parameter);
    if (opts & CreateOptions.open_by_file_id != 0) return st(Status.not_supported);
    if (desired & Access.access_system_security != 0) return st(Status.privilege_not_held);

    const name = try utf16Arg(gpa, msg, wire.get16(b, 44), wire.get16(b, 46));
    defer gpa.free(name);
    const ctxs: CreateCtxs = if (wire.get32(b, 52) == 0) .{} else try parseCreateContexts(try wire.slice(msg, wire.get32(b, 48), wire.get32(b, 52)));

    if (ctx.tree.ipc) return createPipe(ctx, name, desired, share, opts, out);

    const rel = vfs.normalize(gpa, name) catch |e| switch (e) {
        error.Invalid => return st(Status.object_name_invalid),
        else => |x| return x,
    };
    defer gpa.free(rel);

    const res = vfs.resolve(gpa, ctx.tree.root, rel) catch |e| return st(vfs.status(e));
    defer gpa.free(res.path);
    const path = res.path;
    const old = res.info;
    if (old) |i| if (i.kind == .other or i.kind == .symlink) return st(Status.access_denied);

    // Disposition.
    var action: u32 = proto.CreateAction.opened;
    var trunc = false;
    const make = old == null;
    if (old) |i| {
        if (opts & CreateOptions.directory_file != 0 and !i.isDir()) return st(Status.not_a_directory);
        if (opts & CreateOptions.non_directory_file != 0 and i.isDir()) return st(Status.file_is_a_directory);
        switch (disp) {
            Disposition.create => return st(Status.object_name_collision),
            Disposition.supersede => {
                action = proto.CreateAction.superseded;
                trunc = true;
            },
            Disposition.overwrite, Disposition.overwrite_if => {
                action = proto.CreateAction.overwritten;
                trunc = true;
            },
            else => {},
        }
        if (trunc and i.isDir()) return st(Status.invalid_parameter);
    } else {
        if (disp == Disposition.open or disp == Disposition.overwrite) return st(Status.object_name_not_found);
        action = proto.CreateAction.created;
    }
    const is_dir = if (old) |i| i.isDir() else opts & CreateOptions.directory_file != 0;
    if (make and is_dir and disp != Disposition.create and disp != Disposition.open_if) return st(Status.invalid_parameter);

    // Access.
    const max = ctx.tree.maxAccess();
    const ro_attr = if (old) |i| !i.isDir() and i.mode & 0o222 == 0 else false;
    var access = mapGeneric(desired);
    if (access & Access.maximum_allowed != 0) {
        access = (access & ~Access.maximum_allowed) | max;
        if (ro_attr) access &= ~(write_rights | Access.delete);
    }
    if (access & ~max != 0) return st(Status.access_denied);
    if (ro_attr and access & write_rights != 0) return st(Status.access_denied);
    if ((make or trunc) and ctx.tree.read_only) return st(Status.access_denied);
    if (access == 0) access = Access.read_attributes;
    if (opts & CreateOptions.delete_on_close != 0) {
        if (access & Access.delete == 0) return st(Status.access_denied);
        if (ro_attr) return st(Status.cannot_delete);
        if (rel.len == 0) return st(Status.access_denied);
    }

    // Open or create.
    var fd: vfs.Fd = -1;
    errdefer if (fd >= 0) vfs.closeFd(fd);
    if (is_dir) {
        if (make) try vfs.mkdir(path);
        fd = vfs.openDir(path) catch |e| switch (e) {
            error.AccessDenied => if (access & data_rights == 0 and !make) -1 else return e,
            else => return e,
        };
    } else {
        const mode: vfs.OpenMode = if (access & write_rights != 0 or trunc) .rdwr else .read;
        fd = vfs.openFile(path, mode, make, make, false) catch |e| switch (e) {
            error.AccessDenied => if (access & data_rights == 0 and !make) -1 else return e,
            else => return e,
        };
    }
    var info = if (fd >= 0) try vfs.statFd(fd) else try vfs.statPath(path);

    const o = try gpa.create(Open);
    errdefer gpa.destroy(o);
    const id = srv.newId();
    o.* = .{
        .volatile_id = id,
        .persistent_id = id,
        .conn = ctx.conn,
        .session_id = ctx.session.id,
        .tree = ctx.tree,
        .kind = if (is_dir) .dir else .file,
        .fd = fd,
        .rel_path = try gpa.dupe(u8, rel),
        .access = access,
        .share_access = share,
        .create_options = opts,
        .delete_on_close = opts & CreateOptions.delete_on_close != 0,
        .opened_ms = srv.nowMs(),
    };
    errdefer gpa.free(o.rel_path);
    if (try register(ctx, o, path, info)) |s| {
        if (fd >= 0) vfs.closeFd(fd);
        fd = -1;
        gpa.free(o.rel_path);
        gpa.destroy(o);
        return st(s);
    }
    fd = -1; // owned by the open now

    if (trunc) {
        vfs.truncate(o.fd, 0) catch |e| {
            closeOpen(ctx.conn, o);
            return st(vfs.status(e));
        };
    }
    if ((make or trunc) and attrs & proto.Attr.readonly != 0 and !is_dir and o.fd >= 0) {
        vfs.chmod(o.fd, info.mode & ~@as(u32, 0o222)) catch {};
    }
    if (make or trunc) info = statOpen(srv, gpa, o) catch info;
    if (make) parentChanged(ctx, path);

    const fid: FileId = .{ .persistent = o.persistent_id, .volatile_ = o.volatile_id };
    try createResponse(out, action, info, attrsOf(info, o), fid);
    if (ctxs.mxac or ctxs.qfid) {
        const max_access = if (info.isDir() or info.mode & 0o222 != 0) max else max & ~(write_rights | Access.delete);
        try createContexts(out, ctxs, max_access, info);
    }
    return .{ .status = Status.success, .fid = fid };
}

/// Add `o` to its node and the connection's table. Returns a failure status
/// (sharing violation, delete pending) or null.
fn register(ctx: *Ctx, o: *Open, path: []const u8, info: vfs.Info) !?u32 {
    const srv = ctx.srv();
    srv.lock();
    defer srv.unlock();
    const n = try srv.getNode(.{ .dev = info.dev, .ino = info.ino }, path, info.isDir());
    if (n.delete_pending or shareConflict(n, o.access, o.share_access)) {
        const s = if (n.delete_pending) Status.delete_pending else Status.sharing_violation;
        srv.dropNodeIfUnused(n);
        return s;
    }
    try n.opens.append(srv.gpa, o);
    errdefer _ = n.opens.pop();
    try ctx.conn.opens.map.put(ctx.gpa(), o.volatile_id, o);
    o.node = n;
    return null;
}

fn createResponse(out: *Buf, action: u32, info: vfs.Info, attrs: u32, fid: FileId) !void {
    const sz = sizes(info);
    try out.u16_(89);
    try out.u8_(0); // OplockLevel: none
    try out.u8_(0);
    try out.u32_(action);
    try times(out, info);
    try out.u64_(sz.alloc);
    try out.u64_(sz.eof);
    try out.u32_(attrs);
    try out.u32_(0);
    try fid.put(out);
    try out.u32_(0); // CreateContextsOffset (patched)
    try out.u32_(0); // CreateContextsLength (patched)
}

fn createContexts(out: *Buf, ctxs: CreateCtxs, max_access: u32, info: vfs.Info) !void {
    const start = out.len();
    var prev: ?usize = null;
    inline for (.{ "MxAc", "QFid" }) |tag| {
        const want = if (comptime std.mem.eql(u8, tag, "MxAc")) ctxs.mxac else ctxs.qfid;
        if (want) {
            try out.alignTo(8);
            const at = out.len();
            if (prev) |p| out.set32(p, @intCast(at - p));
            const data_len: u32 = if (comptime std.mem.eql(u8, tag, "MxAc")) 8 else 32;
            try out.u32_(0); // Next
            try out.u16_(16); // NameOffset
            try out.u16_(4);
            try out.u16_(0);
            try out.u16_(24); // DataOffset
            try out.u32_(data_len);
            try out.bytes(tag);
            try out.zeros(4);
            if (comptime std.mem.eql(u8, tag, "MxAc")) {
                try out.u32_(Status.success);
                try out.u32_(max_access);
            } else {
                try out.u64_(info.ino);
                try out.u64_(info.dev);
                try out.zeros(16); // VolumeId
            }
            prev = at;
        }
    }
    const first = std.mem.alignForward(usize, start, 8);
    out.set32(hdr + 80, @intCast(first));
    out.set32(hdr + 84, @intCast(out.len() - first));
}

fn createPipe(ctx: *Ctx, name: []const u8, desired: u32, share: u32, opts: u32, out: *Buf) !Reply {
    const gpa = ctx.gpa();
    const srv = ctx.srv();
    var n = name;
    while (n.len > 0 and n[0] == '\\') n = n[1..];
    if (std.ascii.startsWithIgnoreCase(n, "PIPE\\")) n = n[5..];
    if (!std.ascii.eqlIgnoreCase(n, "srvsvc")) return st(Status.object_name_not_found);
    const pipe = try gpa.create(rpc.Pipe);
    errdefer gpa.destroy(pipe);
    pipe.* = .init(gpa);
    errdefer pipe.deinit();
    const o = try gpa.create(Open);
    errdefer gpa.destroy(o);
    const id = srv.newId();
    o.* = .{
        .volatile_id = id,
        .persistent_id = id,
        .conn = ctx.conn,
        .session_id = ctx.session.id,
        .tree = ctx.tree,
        .kind = .pipe,
        .rel_path = try gpa.dupe(u8, "srvsvc"),
        .access = mapGeneric(desired) & ~Access.maximum_allowed,
        .share_access = share,
        .create_options = opts,
        .opened_ms = srv.nowMs(),
        .pipe = pipe,
    };
    errdefer gpa.free(o.rel_path);
    {
        srv.lock();
        defer srv.unlock();
        try ctx.conn.opens.map.put(gpa, id, o);
    }
    const fid: FileId = .{ .persistent = id, .volatile_ = id };
    try createResponse(out, proto.CreateAction.opened, pipe_info, proto.Attr.normal, fid);
    return .{ .status = Status.success, .fid = fid };
}

// ---------------------------------------------------------------- CLOSE

/// Close a handle: release its node entry and locks, perform a pending
/// delete on the last close, complete its CHANGE_NOTIFYs, and free it.
pub fn closeOpen(conn: *Conn, o: *Open) void {
    const gpa = conn.gpa;
    const srv = conn.srv;
    var gone: ?[:0]u8 = null;
    var gone_dir = false;
    var written: ?[:0]u8 = null;
    {
        srv.lock();
        defer srv.unlock();
        _ = conn.opens.map.remove(o.volatile_id);
        if (o.node) |n| {
            for (n.opens.items, 0..) |x, i| if (x == o) {
                _ = n.opens.swapRemove(i);
                break;
            };
            var i: usize = 0;
            while (i < n.locks.items.len) {
                if (n.locks.items[i].owner == o) _ = n.locks.swapRemove(i) else i += 1;
            }
            if (o.delete_on_close) n.delete_pending = true;
            if (n.opens.items.len == 0 and n.delete_pending) {
                gone = gpa.dupeSentinel(u8, n.path, 0) catch null;
                gone_dir = n.is_dir;
            } else if (o.bytes_written > 0) {
                written = gpa.dupeSentinel(u8, n.path, 0) catch null;
            }
            srv.dropNodeIfUnused(n);
        }
    }
    if (o.kind == .dir) conn.cleanupNotifies(o.volatile_id);
    if (o.fd >= 0) vfs.closeFd(o.fd);
    if (o.pipe) |p| {
        p.deinit();
        gpa.destroy(p);
    }
    if (gone) |p| {
        vfs.unlink(p, gone_dir) catch {};
        srv.dirChanged(vfs.dirname(p), conn);
        gpa.free(p);
    }
    if (written) |p| {
        srv.dirChanged(vfs.dirname(p), conn);
        gpa.free(p);
    }
    if (o.dir_names) |names| vfs.freeList(gpa, names);
    gpa.free(o.dir_pattern);
    gpa.free(o.rel_path);
    gpa.destroy(o);
}

/// Close every open of a session and/or tree (null matches any), for
/// TREE_DISCONNECT, LOGOFF, and connection teardown.
pub fn closeAll(conn: *Conn, session_id: ?u64, tree: ?*Tree) void {
    while (true) {
        var it = conn.opens.map.valueIterator();
        const victim = while (it.next()) |op| {
            const o = op.*;
            if (session_id) |s| if (o.session_id != s) continue;
            if (tree) |t| if (o.tree != t) continue;
            break o;
        } else return;
        closeOpen(conn, victim);
    }
}

fn close(ctx: *Ctx, b: []const u8, out: *Buf) !Reply {
    try need(b, 24);
    const flags = wire.get16(b, 2);
    const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
    const info: ?vfs.Info = if (flags & 1 != 0 and o.kind != .pipe) statOpen(ctx.srv(), ctx.gpa(), o) catch null else null;
    const attrs = if (info) |i| attrsOf(i, o) else 0;
    closeOpen(ctx.conn, o);
    try out.u16_(60);
    try out.u16_(if (info != null) 1 else 0);
    try out.u32_(0);
    if (info) |i| {
        const sz = sizes(i);
        try times(out, i);
        try out.u64_(sz.alloc);
        try out.u64_(sz.eof);
    } else try out.zeros(48);
    try out.u32_(attrs);
    return st(Status.success);
}

// ---------------------------------------------------------------- FLUSH

fn flush(ctx: *Ctx, b: []const u8, out: *Buf) !Reply {
    try need(b, 24);
    const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
    if (o.kind == .file) {
        if (o.access & write_rights == 0) return st(Status.access_denied);
        try vfs.sync(o.fd);
    }
    try out.u16_(4);
    try out.u16_(0);
    return st(Status.success);
}

// ---------------------------------------------------------------- READ / WRITE

fn read(ctx: *Ctx, b: []const u8, out: *Buf) !Reply {
    const gpa = ctx.gpa();
    try need(b, 48);
    const len = wire.get32(b, 4);
    const off = wire.get64(b, 8);
    const min = wire.get32(b, 32);
    const o = lookup(ctx, b, 16) orelse return st(Status.file_closed);
    if (len > max_io_size) return st(Status.invalid_parameter);
    try out.u16_(17);
    try out.u8_(hdr + 16); // DataOffset
    try out.u8_(0);
    try out.u32_(0); // DataLength (patched)
    try out.u32_(0); // DataRemaining
    try out.u32_(0);
    try out.list.ensureUnusedCapacity(gpa, len);
    const dest = out.list.unusedCapacitySlice()[0..len];
    var status = Status.success;
    var n: usize = 0;
    switch (o.kind) {
        .dir => return st(Status.invalid_device_request),
        .pipe => {
            n = o.pipe.?.read(dest);
            if (o.pipe.?.pending() > 0) status = Status.buffer_overflow;
        },
        .file => {
            if (o.access & read_rights == 0) return st(Status.access_denied);
            if (lockConflict(ctx.srv(), o, off, len, false)) return st(Status.file_lock_conflict);
            n = try vfs.pread(o.fd, dest, off);
            if ((n == 0 and len > 0) or n < min) return st(Status.end_of_file);
            o.position = off + n;
            o.bytes_read += n;
            _ = ctx.srv().stats.data_read.fetchAdd(n, .monotonic);
        },
    }
    out.list.items.len += n;
    out.set32(hdr + 4, @intCast(n));
    return st(status);
}

/// srvsvc needs the share list for NetrShareEnum.
fn pipeWrite(ctx: *Ctx, pipe: *rpc.Pipe, data: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(ctx.gpa());
    defer arena.deinit();
    const a = arena.allocator();
    const shares = try ctx.srv().db.listShares(a);
    const entries = try a.alloc(rpc.ShareEntry, shares.len + 1);
    for (shares, entries[0..shares.len]) |s, *e| e.* = .{ .name = s.name, .comment = s.comment, .kind = rpc.stype_disktree };
    entries[shares.len] = .{ .name = "IPC$", .comment = "IPC Service", .kind = rpc.stype_ipc_special };
    try pipe.write(data, entries);
}

fn write(ctx: *Ctx, msg: []const u8, b: []const u8, out: *Buf) !Reply {
    try need(b, 48);
    const data_off = wire.get16(b, 2);
    const len = wire.get32(b, 4);
    var off = wire.get64(b, 8);
    const flags = wire.get32(b, 44);
    const o = lookup(ctx, b, 16) orelse return st(Status.file_closed);
    if (len > max_io_size) return st(Status.invalid_parameter);
    const data = try wire.slice(msg, data_off, len);
    switch (o.kind) {
        .dir => return st(Status.invalid_device_request),
        .pipe => try pipeWrite(ctx, o.pipe.?, data),
        .file => {
            if (o.access & write_rights == 0) return st(Status.access_denied);
            if (off == std.math.maxInt(u64)) off = (try vfs.statFd(o.fd)).size;
            if (lockConflict(ctx.srv(), o, off, len, true)) return st(Status.file_lock_conflict);
            try vfs.pwriteAll(o.fd, data, off);
            if (flags & 1 != 0 or o.create_options & CreateOptions.write_through != 0) try vfs.sync(o.fd);
            o.position = off + len;
            o.bytes_written += len;
            _ = ctx.srv().stats.data_written.fetchAdd(len, .monotonic);
        },
    }
    try out.u16_(17);
    try out.u16_(0);
    try out.u32_(len);
    try out.u32_(0);
    try out.u16_(0);
    try out.u16_(0);
    return st(Status.success);
}

// ---------------------------------------------------------------- LOCK

fn lock(ctx: *Ctx, b: []const u8, out: *Buf) !Reply {
    const srv = ctx.srv();
    try need(b, 24);
    const count = wire.get16(b, 2);
    const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
    if (count == 0) return st(Status.invalid_parameter);
    const elems = try wire.slice(b, 24, @as(usize, count) * 24);
    if (o.kind != .file) return st(Status.invalid_parameter);
    const unlocking = wire.get32(elems, 16) & proto.LockFlags.unlock != 0;

    srv.lock();
    defer srv.unlock();
    const n = o.node.?;
    const before = n.locks.items.len;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const e = elems[i * 24 ..][0..24];
        const off = wire.get64(e, 0);
        const len = wire.get64(e, 8);
        const f = wire.get32(e, 16);
        if (unlocking) {
            if (f != proto.LockFlags.unlock) return st(Status.invalid_parameter);
            const k = for (n.locks.items, 0..) |l, k| {
                if (l.owner == o and l.off == off and l.len == len) break k;
            } else return st(Status.range_not_locked);
            _ = n.locks.orderedRemove(k);
            continue;
        }
        const kind = f & ~proto.LockFlags.fail_immediately;
        const exclusive = kind == proto.LockFlags.exclusive;
        const bad = (kind != proto.LockFlags.shared and !exclusive) or (count > 1 and f & proto.LockFlags.fail_immediately == 0);
        const conflict = for (n.locks.items) |l| {
            if (l.overlaps(off, len) and (exclusive or l.exclusive)) break true;
        } else false;
        if (bad or conflict) {
            n.locks.shrinkRetainingCapacity(before);
            return st(if (bad) Status.invalid_parameter else Status.lock_not_granted);
        }
        n.locks.append(srv.gpa, .{ .off = off, .len = len, .exclusive = exclusive, .owner = o }) catch {
            n.locks.shrinkRetainingCapacity(before);
            return st(Status.insufficient_resources);
        };
    }
    try out.u16_(4);
    try out.u16_(0);
    return st(Status.success);
}

// ---------------------------------------------------------------- QUERY_DIRECTORY

fn dirEntryFixed(class: u8) ?usize {
    return switch (class) {
        FileInfo.directory => 64,
        FileInfo.full_directory => 68,
        FileInfo.both_directory => 94,
        FileInfo.id_both_directory => 104,
        FileInfo.id_full_directory => 80,
        FileInfo.names => 12,
        else => null,
    };
}

fn dirEntry(out: *Buf, class: u8, name: []const u8, i: vfs.Info) !void {
    const name_len: u32 = @intCast(wire.utf16Len(name));
    try out.u32_(0); // NextEntryOffset (patched)
    try out.u32_(0); // FileIndex
    if (class == FileInfo.names) {
        try out.u32_(name_len);
        _ = try out.utf16(name);
        return;
    }
    const sz = sizes(i);
    try times(out, i);
    try out.u64_(sz.eof);
    try out.u64_(sz.alloc);
    try out.u32_(i.attributes(name));
    try out.u32_(name_len);
    switch (class) {
        FileInfo.full_directory => try out.u32_(0),
        FileInfo.both_directory => {
            try out.u32_(0);
            try out.zeros(26); // ShortNameLength, Reserved, ShortName
        },
        FileInfo.id_both_directory => {
            try out.u32_(0);
            try out.zeros(28); // ShortNameLength, Reserved1, ShortName, Reserved2
            try out.u64_(i.fileId());
        },
        FileInfo.id_full_directory => {
            try out.u32_(0);
            try out.u32_(0);
            try out.u64_(i.fileId());
        },
        else => {},
    }
    _ = try out.utf16(name);
}

/// Metadata for a directory entry; null when it vanished or is a symlink
/// that leaves the share.
fn entryInfo(ctx: *Ctx, o: *Open, name: []const u8) !?vfs.Info {
    const gpa = ctx.gpa();
    if (std.mem.eql(u8, name, ".")) return try vfs.statFd(o.fd);
    if (std.mem.eql(u8, name, "..")) {
        if (o.rel_path.len == 0) return try vfs.statFd(o.fd);
        return vfs.statAt(o.fd, "..", true) catch null;
    }
    const z = try gpa.dupeSentinel(u8, name, 0);
    defer gpa.free(z);
    const i = vfs.statAt(o.fd, z, false) catch return null;
    if (i.kind != .symlink) return if (i.kind == .other) null else i;
    const rel = if (o.rel_path.len == 0) try gpa.dupe(u8, name) else try std.fmt.allocPrint(gpa, "{s}/{s}", .{ o.rel_path, name });
    defer gpa.free(rel);
    const r = vfs.resolve(gpa, ctx.tree.root, rel) catch return null;
    defer gpa.free(r.path);
    return r.info;
}

fn queryDirectory(ctx: *Ctx, msg: []const u8, b: []const u8, out: *Buf) !Reply {
    const gpa = ctx.gpa();
    try need(b, 32);
    const class = b[2];
    const flags = b[3];
    const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
    const out_len = @min(wire.get32(b, 28), max_io_size);
    if (o.kind != .dir or o.fd < 0) return st(Status.invalid_parameter);
    const fixed = dirEntryFixed(class) orelse return st(Status.invalid_info_class);

    const restart = flags & (proto.QueryDirFlags.restart_scans | proto.QueryDirFlags.reopen) != 0;
    if (restart or o.dir_names == null) {
        const pattern = try utf16Arg(gpa, msg, wire.get16(b, 24), wire.get16(b, 26));
        errdefer gpa.free(pattern);
        const listed = try vfs.listDir(gpa, o.fd);
        defer gpa.free(listed);
        var names = try gpa.alloc([]u8, listed.len + 2);
        errdefer gpa.free(names);
        names[0] = try gpa.dupe(u8, ".");
        names[1] = gpa.dupe(u8, "..") catch |e| {
            gpa.free(names[0]);
            for (listed) |x| gpa.free(x);
            return e;
        };
        @memcpy(names[2..], listed);
        if (o.dir_names) |old| vfs.freeList(gpa, old);
        gpa.free(o.dir_pattern);
        o.dir_names = names;
        o.dir_pattern = pattern;
        o.dir_pos = 0;
        o.dir_any = false;
    }
    const names = o.dir_names.?;

    try out.u16_(9);
    try out.u16_(hdr + 8);
    try out.u32_(0); // OutputBufferLength (patched)
    const base = out.len();
    var last: ?usize = null;
    while (o.dir_pos < names.len) {
        const name = names[o.dir_pos];
        if (!vfs.wildcardMatch(o.dir_pattern, name)) {
            o.dir_pos += 1;
            continue;
        }
        const info = try entryInfo(ctx, o, name) orelse {
            o.dir_pos += 1;
            continue;
        };
        const pad = if (last == null) 0 else (8 - (out.len() - base) % 8) % 8;
        const size = fixed + wire.utf16Len(name);
        if (out.len() - base + pad + size > out_len) {
            if (last == null) return st(Status.info_length_mismatch);
            break;
        }
        try out.zeros(pad);
        const at = out.len();
        if (last) |l| out.set32(l, @intCast(at - l));
        try dirEntry(out, class, name, info);
        last = at;
        o.dir_pos += 1;
        o.dir_any = true;
        if (flags & proto.QueryDirFlags.return_single_entry != 0) break;
    }
    if (last == null) {
        out.list.shrinkRetainingCapacity(hdr);
        return st(if (o.dir_any) Status.no_more_files else Status.no_such_file);
    }
    out.set32(hdr + 4, @intCast(out.len() - base));
    return st(Status.success);
}

// ---------------------------------------------------------------- CHANGE_NOTIFY

fn changeNotify(ctx: *Ctx, msg: []const u8, b: []const u8) !Reply {
    try need(b, 32);
    const flags = wire.get16(b, 2);
    const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
    if (o.kind != .dir) return st(Status.invalid_parameter);
    const s = ctx.session;
    return .{ .status = Status.pending, .notify = .{
        .async_id = 0,
        .msg_id = wire.get64(msg, 24),
        .session_id = s.id,
        .tree_id = ctx.tree.id,
        .volatile_id = o.volatile_id,
        .dir_path = try nodePath(ctx.srv(), ctx.gpa(), o.node.?),
        .watch_tree = flags & 1 != 0,
        .sign = s.sign,
        .signing_key = s.signing_key,
        .encrypt = s.encrypt,
        .enc_key = s.enc_key,
    } };
}

// ---------------------------------------------------------------- QUERY_INFO

fn queryInfo(ctx: *Ctx, b: []const u8, out: *Buf) !Reply {
    try need(b, 40);
    const info_type = b[2];
    const class = b[3];
    const out_len = wire.get32(b, 4);
    const addl = wire.get32(b, 16);
    const o = lookup(ctx, b, 24) orelse return st(Status.file_closed);
    try out.u16_(9);
    try out.u16_(hdr + 8);
    try out.u32_(0); // OutputBufferLength (patched)
    const base = out.len();
    var variable = false;
    switch (info_type) {
        proto.InfoType.file => {
            variable = class == FileInfo.all or class == FileInfo.stream or class == FileInfo.normalized_name or class == FileInfo.name;
            if (try queryFile(ctx, o, class, out)) |s| return st(s);
        },
        proto.InfoType.filesystem => {
            variable = class == FsInfo.volume or class == FsInfo.attribute;
            if (try queryFs(ctx, o, class, out)) |s| return st(s);
        },
        proto.InfoType.security => {
            try securityDescriptor(out, addl, ctx.tree.maxAccess(), o.kind == .dir);
            const n = out.len() - base;
            if (n > out_len) {
                out.list.shrinkRetainingCapacity(hdr);
                try out.u16_(9);
                try out.u16_(0);
                try out.u32_(4); // ByteCount
                try out.u32_(@intCast(n)); // required size
                return .{ .status = Status.buffer_too_small, .keep_body = true };
            }
        },
        else => return st(Status.invalid_parameter),
    }
    var n = out.len() - base;
    var status = Status.success;
    if (n > out_len) {
        if (!variable) return st(Status.info_length_mismatch);
        out.list.shrinkRetainingCapacity(base + out_len);
        n = out_len;
        status = Status.buffer_overflow;
    }
    out.set32(hdr + 4, @intCast(n));
    return st(status);
}

fn queryFile(ctx: *Ctx, o: *Open, class: u8, out: *Buf) !?u32 {
    const gpa = ctx.gpa();
    const srv = ctx.srv();
    const i = try infoOf(ctx, o);
    const attrs = attrsOf(i, o);
    const sz = sizes(i);
    const pending = blk: {
        const n = o.node orelse break :blk false;
        srv.lock();
        defer srv.unlock();
        break :blk n.delete_pending;
    };
    switch (class) {
        FileInfo.basic => {
            try times(out, i);
            try out.u32_(attrs);
            try out.u32_(0);
        },
        FileInfo.standard => try standardInfo(out, i, pending),
        FileInfo.internal => try out.u64_(i.fileId()),
        FileInfo.ea, FileInfo.alignment => try out.u32_(0),
        FileInfo.access => try out.u32_(o.access),
        FileInfo.position => try out.u64_(o.position),
        FileInfo.mode => try out.u32_(o.create_options & 0x3E),
        FileInfo.all => {
            try times(out, i);
            try out.u32_(attrs);
            try out.u32_(0);
            try standardInfo(out, i, pending);
            try out.u64_(i.fileId());
            try out.u32_(0); // EaSize
            try out.u32_(o.access);
            try out.u64_(o.position);
            try out.u32_(o.create_options & 0x3E);
            try out.u32_(0); // AlignmentRequirement
            try nameInfo(gpa, out, o.rel_path, true);
        },
        FileInfo.network_open => {
            try times(out, i);
            try out.u64_(sz.alloc);
            try out.u64_(sz.eof);
            try out.u32_(attrs);
            try out.u32_(0);
        },
        FileInfo.attribute_tag => {
            try out.u32_(attrs);
            try out.u32_(0);
        },
        FileInfo.stream => if (!i.isDir()) {
            try out.u32_(0);
            try out.u32_(@intCast(wire.utf16Len("::$DATA")));
            try out.u64_(sz.eof);
            try out.u64_(sz.alloc);
            _ = try out.utf16("::$DATA");
        },
        FileInfo.normalized_name => try nameInfo(gpa, out, o.rel_path, false),
        FileInfo.name => try nameInfo(gpa, out, o.rel_path, true),
        else => return Status.invalid_info_class,
    }
    return null;
}

fn standardInfo(out: *Buf, i: vfs.Info, pending: bool) !void {
    const sz = sizes(i);
    try out.u64_(sz.alloc);
    try out.u64_(sz.eof);
    try out.u32_(i.nlink);
    try out.u8_(@intFromBool(pending));
    try out.u8_(@intFromBool(i.isDir()));
    try out.u16_(0);
}

fn nameInfo(gpa: Allocator, out: *Buf, rel: []const u8, leading: bool) !void {
    const p = try winPath(gpa, rel, leading);
    defer gpa.free(p);
    try out.u32_(@intCast(wire.utf16Len(p)));
    _ = try out.utf16(p);
}

fn queryFs(ctx: *Ctx, o: *Open, class: u8, out: *Buf) !?u32 {
    if (o.kind == .pipe) return Status.invalid_parameter;
    const fd = if (o.fd >= 0) o.fd else try vfs.openDir(ctx.tree.root);
    defer if (fd != o.fd) vfs.closeFd(fd);
    const bps: u32 = 512;
    switch (class) {
        FsInfo.volume => {
            try out.u64_(0); // VolumeCreationTime
            try out.u32_(std.hash.Crc32.hash(ctx.tree.share));
            try out.u32_(@intCast(wire.utf16Len(ctx.tree.share)));
            try out.u8_(0);
            try out.u8_(0);
            _ = try out.utf16(ctx.tree.share);
        },
        FsInfo.size, FsInfo.full_size => {
            const v = try vfs.volInfo(fd);
            const spu: u32 = @intCast(@max(1, v.block_size / bps));
            try out.u64_(v.total);
            try out.u64_(v.avail);
            if (class == FsInfo.full_size) try out.u64_(v.free);
            try out.u32_(spu);
            try out.u32_(bps);
        },
        FsInfo.device => {
            try out.u32_(7); // FILE_DEVICE_DISK
            try out.u32_(0);
        },
        FsInfo.attribute => {
            // FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK
            try out.u32_(0x2 | 0x4);
            try out.u32_(255);
            try out.u32_(@intCast(wire.utf16Len("NTFS")));
            _ = try out.utf16("NTFS");
        },
        FsInfo.sector_size => {
            for (0..4) |_| try out.u32_(bps);
            try out.u32_(0x3); // aligned device and partition
            try out.u32_(0);
            try out.u32_(0);
        },
        else => return Status.invalid_info_class,
    }
    return null;
}

/// Self-relative security descriptor: Everyone owns the object and is
/// granted `mask` (what the tree allows).
fn securityDescriptor(out: *Buf, addl: u32, mask: u32, inherit: bool) !void {
    const everyone = [_]u8{ 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
    const start = out.len();
    const dacl = addl & 4 != 0;
    try out.u8_(1); // Revision
    try out.u8_(0);
    try out.u16_(0x8000 | @as(u16, if (dacl) 0x0004 else 0)); // SELF_RELATIVE, DACL_PRESENT
    const offs = try out.reserve(16); // Owner, Group, Sacl, Dacl
    if (addl & 1 != 0) {
        out.set32(offs, @intCast(out.len() - start));
        try out.bytes(&everyone);
    }
    if (addl & 2 != 0) {
        out.set32(offs + 4, @intCast(out.len() - start));
        try out.bytes(&everyone);
    }
    if (dacl) {
        out.set32(offs + 12, @intCast(out.len() - start));
        try out.u8_(2); // ACL revision
        try out.u8_(0);
        try out.u16_(8 + 8 + everyone.len);
        try out.u16_(1);
        try out.u16_(0);
        try out.u8_(0); // ACCESS_ALLOWED_ACE_TYPE
        try out.u8_(if (inherit) 0x3 else 0); // OBJECT_INHERIT | CONTAINER_INHERIT
        try out.u16_(8 + everyone.len);
        try out.u32_(mask);
        try out.bytes(&everyone);
    }
}

// ---------------------------------------------------------------- SET_INFO

fn setInfo(ctx: *Ctx, msg: []const u8, b: []const u8, out: *Buf) !Reply {
    try need(b, 32);
    const info_type = b[2];
    const class = b[3];
    const data = try wire.slice(msg, wire.get16(b, 8), wire.get32(b, 4));
    const o = lookup(ctx, b, 16) orelse return st(Status.file_closed);
    const s: ?u32 = switch (info_type) {
        // Security descriptors are synthesized; changes are accepted and ignored.
        proto.InfoType.security => null,
        proto.InfoType.file => if (o.kind == .pipe) Status.not_supported else try setFile(ctx, o, class, data),
        else => Status.not_supported,
    };
    if (s) |x| return st(x);
    try out.u16_(2);
    return st(Status.success);
}

fn ntTime(v: u64) ?u64 {
    // 0 leaves the time alone; -1 and -2 suspend and resume automatic updates.
    return if (v == 0 or v >= std.math.maxInt(u64) - 1) null else v;
}

fn setFile(ctx: *Ctx, o: *Open, class: u8, data: []const u8) !?u32 {
    const gpa = ctx.gpa();
    const srv = ctx.srv();
    switch (class) {
        FileInfo.basic => {
            if (data.len < 36) return Status.info_length_mismatch;
            if (o.access & Access.write_attributes == 0) return Status.access_denied;
            const at = ntTime(wire.get64(data, 8));
            const mt = ntTime(wire.get64(data, 16));
            const attrs = wire.get32(data, 32);
            const i = try statOpen(srv, gpa, o);
            if (at != null or mt != null) {
                if (o.fd >= 0) try vfs.setTimes(o.fd, at, mt) else {
                    const p = try nodePath(srv, gpa, o.node.?);
                    defer gpa.free(p);
                    try vfs.setTimesPath(p, at, mt);
                }
            }
            if (attrs != 0 and !i.isDir()) {
                const mode = if (attrs & proto.Attr.readonly != 0) i.mode & ~@as(u32, 0o222) else if (i.mode & 0o222 == 0) i.mode | 0o200 else i.mode;
                if (mode != i.mode) {
                    if (o.fd >= 0) try vfs.chmod(o.fd, mode) else {
                        const p = try nodePath(srv, gpa, o.node.?);
                        defer gpa.free(p);
                        try vfs.chmodPath(p, mode);
                    }
                }
            }
        },
        FileInfo.end_of_file, FileInfo.allocation => {
            if (data.len < 8) return Status.info_length_mismatch;
            if (o.access & Access.write_data == 0) return Status.access_denied;
            if (o.kind != .file) return Status.invalid_parameter;
            const v = wire.get64(data, 0);
            if (class == FileInfo.allocation and v >= (try vfs.statFd(o.fd)).size) return null;
            try vfs.truncate(o.fd, v);
            o.bytes_written += 1; // notify the directory on close
        },
        FileInfo.disposition => {
            if (data.len < 1) return Status.info_length_mismatch;
            return setDelete(ctx, o, data[0] != 0);
        },
        FileInfo.disposition_ex => {
            if (data.len < 4) return Status.info_length_mismatch;
            return setDelete(ctx, o, wire.get32(data, 0) & 1 != 0);
        },
        FileInfo.rename => return rename(ctx, o, data),
        FileInfo.position => {
            if (data.len < 8) return Status.info_length_mismatch;
            o.position = wire.get64(data, 0);
        },
        FileInfo.mode => {},
        FileInfo.link => return Status.not_supported,
        FileInfo.full_ea => return Status.eas_not_supported,
        else => return Status.invalid_info_class,
    }
    return null;
}

fn setDelete(ctx: *Ctx, o: *Open, value: bool) !?u32 {
    const srv = ctx.srv();
    if (o.access & Access.delete == 0) return Status.access_denied;
    if (o.rel_path.len == 0) return Status.access_denied;
    if (value) {
        const i = try statOpen(srv, ctx.gpa(), o);
        if (!i.isDir() and i.mode & 0o222 == 0) return Status.cannot_delete;
        if (i.isDir() and o.fd >= 0) {
            const names = try vfs.listDir(ctx.gpa(), o.fd);
            defer vfs.freeList(ctx.gpa(), names);
            if (names.len > 0) return Status.directory_not_empty;
        }
    } else o.delete_on_close = false;
    srv.lock();
    defer srv.unlock();
    o.node.?.delete_pending = value;
    return null;
}

fn rename(ctx: *Ctx, o: *Open, data: []const u8) !?u32 {
    const gpa = ctx.gpa();
    const srv = ctx.srv();
    if (data.len < 20) return Status.info_length_mismatch;
    const replace = data[0] != 0;
    if (o.access & Access.delete == 0) return Status.access_denied;
    if (o.rel_path.len == 0) return Status.access_denied;
    const name = try wire.utf16ToUtf8(gpa, try wire.slice(data, 20, wire.get32(data, 16)));
    defer gpa.free(name);
    const new_rel = vfs.normalize(gpa, name) catch |e| switch (e) {
        error.Invalid => return Status.object_name_invalid,
        else => |x| return x,
    };
    defer gpa.free(new_rel);
    if (new_rel.len == 0) return Status.object_name_invalid;

    const res = vfs.resolve(gpa, ctx.tree.root, new_rel) catch |e| return vfs.status(e);
    defer gpa.free(res.path);
    const old_path = try nodePath(srv, gpa, o.node.?);
    defer gpa.free(old_path);
    const self = o.node.?.key;
    var target: [:0]u8 = undefined;
    if (res.info) |ti| {
        if (ti.dev == self.dev and ti.ino == self.ino) {
            // The same file under another spelling: a case-only rename.
            target = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ vfs.dirname(res.path), vfs.basename(new_rel) }, 0);
            if (std.mem.eql(u8, target, old_path)) {
                gpa.free(target);
                return null;
            }
        } else {
            if (!replace) return Status.object_name_collision;
            if (ti.isDir()) return Status.access_denied;
            srv.lock();
            const busy = srv.nodes.contains(.{ .dev = ti.dev, .ino = ti.ino });
            srv.unlock();
            if (busy) return Status.access_denied;
            target = try gpa.dupeSentinel(u8, res.path, 0);
        }
    } else target = try gpa.dupeSentinel(u8, res.path, 0);
    defer gpa.free(target);

    {
        srv.lock();
        defer srv.unlock();
        // A directory can't be renamed while anything beneath it is open.
        var it = srv.nodes.valueIterator();
        while (it.next()) |np| {
            const p = np.*.path;
            if (p.len > old_path.len and std.mem.startsWith(u8, p, old_path) and p[old_path.len] == '/') return Status.access_denied;
        }
        try vfs.rename(old_path, target);
        srv.renameNodes(old_path, target);
    }
    const rel = try gpa.dupe(u8, new_rel);
    gpa.free(o.rel_path);
    o.rel_path = rel;
    parentChanged(ctx, old_path);
    if (!std.mem.eql(u8, vfs.dirname(old_path), vfs.dirname(target))) parentChanged(ctx, target);
    return null;
}

// ---------------------------------------------------------------- IOCTL

const max_chunks = 256;
const max_chunk_size = 1024 * 1024;
const max_copy_total = 16 * 1024 * 1024;

fn ioctl(ctx: *Ctx, msg: []const u8, b: []const u8, out: *Buf) !Reply {
    try need(b, 56);
    const code = wire.get32(b, 4);
    const input = try wire.slice(msg, wire.get32(b, 24), wire.get32(b, 28));
    const max_out = wire.get32(b, 44);
    if (wire.get32(b, 48) & 1 == 0) return st(Status.not_supported); // not an FSCTL
    try out.u16_(49);
    try out.u16_(0);
    try out.u32_(code);
    try out.bytes(b[8..24]); // FileId
    try out.u32_(hdr + 48); // InputOffset
    try out.u32_(0);
    try out.u32_(hdr + 48); // OutputOffset
    try out.u32_(0); // OutputCount (patched)
    try out.u32_(0);
    try out.u32_(0);
    const base = out.len();
    var r: Reply = st(Status.success);
    switch (code) {
        Fsctl.validate_negotiate_info => r = try validateNegotiate(ctx, input, max_out, out),
        Fsctl.pipe_transceive => {
            const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
            const pipe = o.pipe orelse return st(Status.invalid_device_request);
            try pipeWrite(ctx, pipe, input);
            const n = @min(max_out, pipe.pending());
            const dest = try out.list.addManyAsSlice(ctx.gpa(), n);
            _ = pipe.read(dest);
            if (pipe.pending() > 0) r = st(Status.buffer_overflow);
        },
        Fsctl.srv_request_resume_key => {
            const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
            if (max_out < 28) return st(Status.invalid_parameter);
            try out.u64_(o.persistent_id);
            try out.u64_(o.volatile_id);
            try out.zeros(8);
            try out.u32_(0); // ContextLength
        },
        Fsctl.srv_copychunk, Fsctl.srv_copychunk_write => {
            const o = lookup(ctx, b, 8) orelse return st(Status.file_closed);
            if (max_out < 12) return st(Status.invalid_parameter);
            r = try copyChunk(ctx, o, input, code == Fsctl.srv_copychunk, out);
        },
        Fsctl.set_sparse => _ = lookup(ctx, b, 8) orelse return st(Status.file_closed),
        Fsctl.dfs_get_referrals, Fsctl.dfs_get_referrals_ex => return st(Status.fs_driver_required),
        else => return st(Status.not_supported),
    }
    out.set32(hdr + 36, @intCast(out.len() - base));
    return r;
}

fn validateNegotiate(ctx: *Ctx, input: []const u8, max_out: u32, out: *Buf) !Reply {
    const neg = &ctx.conn.neg;
    if (neg.dialect == proto.Dialect.smb311) return .{ .status = Status.access_denied, .disconnect = true };
    if (input.len < 24 or max_out < 24) return st(Status.invalid_parameter);
    const count = wire.get16(input, 22);
    const dialects = try wire.slice(input, 24, @as(usize, count) * 2);
    var ok = wire.get32(input, 0) == neg.client_caps and
        std.mem.eql(u8, input[4..20], &neg.client_guid) and
        wire.get16(input, 20) == neg.client_security_mode and
        count == neg.client_dialect_count;
    if (ok) for (neg.client_dialects[0..neg.client_dialect_count], 0..) |d, i| {
        if (wire.get16(dialects, i * 2) != d) ok = false;
    };
    if (!ok) return .{ .status = Status.access_denied, .disconnect = true };
    try out.u32_(neg.server_caps);
    try out.bytes(&neg.server_guid);
    try out.u16_(neg.server_security_mode);
    try out.u16_(neg.dialect);
    return st(Status.success);
}

fn copyChunk(ctx: *Ctx, dst: *Open, input: []const u8, need_read: bool, out: *Buf) !Reply {
    const gpa = ctx.gpa();
    const srv = ctx.srv();
    if (input.len < 32) return st(Status.invalid_parameter);
    const count = wire.get32(input, 24);
    const chunks = wire.slice(input, 32, @as(usize, count) * 24) catch return st(Status.invalid_parameter);
    var total: u64 = 0;
    var too_big = count > max_chunks;
    if (!too_big) for (0..count) |i| {
        const len = wire.get32(chunks, i * 24 + 16);
        total += len;
        if (len == 0 or len > max_chunk_size) too_big = true;
    };
    if (too_big or total > max_copy_total) {
        try out.u32_(max_chunks);
        try out.u32_(max_chunk_size);
        try out.u32_(max_copy_total);
        return .{ .status = Status.invalid_parameter, .keep_body = true };
    }
    const src = ctx.conn.opens.map.get(wire.get64(input, 8)) orelse return st(Status.object_name_not_found);
    if (src.persistent_id != wire.get64(input, 0) or src.session_id != ctx.session.id) return st(Status.object_name_not_found);
    if (src.kind != .file or dst.kind != .file) return st(Status.invalid_device_request);
    if (src.access & Access.read_data == 0) return st(Status.access_denied);
    if (dst.access & Access.write_data == 0 or (need_read and dst.access & Access.read_data == 0)) return st(Status.access_denied);

    const buf = try gpa.alloc(u8, max_chunk_size);
    defer gpa.free(buf);
    var written: u32 = 0;
    var done: u32 = 0;
    for (0..count) |i| {
        const c = chunks[i * 24 ..][0..24];
        const s_off = wire.get64(c, 0);
        const d_off = wire.get64(c, 8);
        const len = wire.get32(c, 16);
        if (lockConflict(srv, src, s_off, len, false) or lockConflict(srv, dst, d_off, len, true)) return st(Status.file_lock_conflict);
        var got: usize = 0;
        while (got < len) {
            const n = try vfs.pread(src.fd, buf[got..len], s_off + got);
            if (n == 0) break;
            got += n;
        }
        try vfs.pwriteAll(dst.fd, buf[0..got], d_off);
        written += @intCast(got);
        done += 1;
        if (got < len) break;
    }
    dst.bytes_written += written;
    _ = srv.stats.data_written.fetchAdd(written, .monotonic);
    try out.u32_(done);
    try out.u32_(0);
    try out.u32_(written);
    return st(Status.success);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Db = db_mod.Db;

const Fixture = struct {
    tmp: testing.TmpDir,
    db: Db,
    srv: Server,
    conn: *Conn,
    session: Session,
    tree: Tree,
    ctx: Ctx,
    out: Buf,

    fn init(f: *Fixture) !void {
        const gpa = testing.allocator;
        f.tmp = testing.tmpDir(.{});
        errdefer f.tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try f.tmp.dir.realPath(testing.io, &buf);
        f.db = try Db.open(testing.io, ":memory:");
        f.srv = .{
            .gpa = gpa,
            .io = testing.io,
            .db = &f.db,
            .guid = @splat(0),
            .start_ms = 0,
            .smb_port = 445,
            .cfg = .{ .server_name = &.{}, .workgroup = &.{}, .signing_required = true, .encrypt = false },
        };
        f.conn = try gpa.create(Conn);
        f.conn.* = .{ .gpa = gpa, .srv = &f.srv, .id = 1, .stream = undefined };
        f.session = .{ .id = 7, .state = .valid, .created_ms = 0 };
        f.tree = .{
            .id = 3,
            .session_id = 7,
            .share = @constCast("data"),
            .root = try gpa.dupeSentinel(u8, buf[0..n], 0),
            .ipc = false,
            .read_only = false,
            .connected_ms = 0,
        };
        f.ctx = .{ .conn = f.conn, .session = &f.session, .tree = &f.tree };
        f.out = .init(gpa);
    }

    fn deinit(f: *Fixture) void {
        const gpa = testing.allocator;
        closeAll(f.conn, null, null);
        f.conn.opens.map.deinit(gpa);
        f.conn.notifies.deinit(gpa);
        gpa.destroy(f.conn);
        f.srv.nodes.deinit(gpa);
        f.db.close();
        gpa.free(f.tree.root);
        f.out.deinit();
        f.tmp.cleanup();
    }

    /// Send one request (body only; the header is zero) and return the status.
    fn call(f: *Fixture, cmd: proto.Command, req: []const u8) !u32 {
        const gpa = testing.allocator;
        const msg = try gpa.alloc(u8, hdr + req.len);
        defer gpa.free(msg);
        @memset(msg[0..hdr], 0);
        @memcpy(msg[hdr..], req);
        f.out.clear();
        try f.out.zeros(hdr);
        const r = dispatch(&f.ctx, cmd, msg, &f.out);
        if (r.notify) |n| gpa.free(n.dir_path);
        if (r.fid) |fid| f.ctx.related = fid;
        return r.status;
    }

    fn body(f: *Fixture) []u8 {
        return f.out.items()[hdr..];
    }

    fn create(f: *Fixture, name: []const u8, access: u32, share: u32, disp: u32, opts: u32) !struct { status: u32, fid: FileId } {
        const gpa = testing.allocator;
        var b = Buf.init(gpa);
        defer b.deinit();
        try b.u16_(57);
        try b.zeros(22);
        try b.u32_(access);
        try b.u32_(0);
        try b.u32_(share);
        try b.u32_(disp);
        try b.u32_(opts);
        try b.u16_(hdr + 56);
        try b.u16_(@intCast(wire.utf16Len(name)));
        try b.u32_(0);
        try b.u32_(0);
        _ = try b.utf16(name);
        if (name.len == 0) try b.u8_(0);
        const s = try f.call(.create, b.items());
        if (s != Status.success) return .{ .status = s, .fid = .none };
        return .{ .status = s, .fid = FileId.get(f.body(), 64) };
    }

    fn withFid(f: *Fixture, comptime n: usize, prefix: []const u8, fid: FileId, at: usize) ![n]u8 {
        _ = f;
        var b: [n]u8 = @splat(0);
        @memcpy(b[0..prefix.len], prefix);
        wire.put64(&b, at, fid.persistent);
        wire.put64(&b, at + 8, fid.volatile_);
        return b;
    }

    fn close(f: *Fixture, fid: FileId) !u32 {
        const b = try f.withFid(24, &.{ 24, 0 }, fid, 8);
        return f.call(.close, &b);
    }

    fn write(f: *Fixture, fid: FileId, off: u64, data: []const u8) !u32 {
        const gpa = testing.allocator;
        const b = try gpa.alloc(u8, 48 + data.len);
        defer gpa.free(b);
        @memset(b[0..48], 0);
        wire.put16(b, 0, 49);
        wire.put16(b, 2, hdr + 48);
        wire.put32(b, 4, @intCast(data.len));
        wire.put64(b, 8, off);
        wire.put64(b, 16, fid.persistent);
        wire.put64(b, 24, fid.volatile_);
        @memcpy(b[48..], data);
        return f.call(.write, b);
    }

    fn read(f: *Fixture, fid: FileId, off: u64, len: u32) !u32 {
        var b = try f.withFid(49, &.{ 49, 0 }, fid, 16);
        wire.put32(&b, 4, len);
        wire.put64(&b, 8, off);
        return f.call(.read, &b);
    }

    fn list(f: *Fixture, fid: FileId, flags: u8, pattern: []const u8, names: *std.ArrayList([]u8)) !u32 {
        const gpa = testing.allocator;
        var b = Buf.init(gpa);
        defer b.deinit();
        try b.u16_(33);
        try b.u8_(FileInfo.names);
        try b.u8_(flags);
        try b.u32_(0);
        try fid.put(&b);
        try b.u16_(hdr + 32);
        try b.u16_(@intCast(wire.utf16Len(pattern)));
        try b.u32_(65536);
        _ = try b.utf16(pattern);
        if (pattern.len == 0) try b.u8_(0);
        const s = try f.call(.query_directory, b.items());
        if (s != Status.success) return s;
        const data = f.body()[8..];
        var p: usize = 0;
        while (true) {
            const len = wire.get32(data, p + 8);
            try names.append(gpa, try wire.utf16ToUtf8(gpa, data[p + 12 ..][0..len]));
            const next = wire.get32(data, p);
            if (next == 0) break;
            p += next;
        }
        return s;
    }

    fn setInfo(f: *Fixture, fid: FileId, class: u8, data: []const u8) !u32 {
        const gpa = testing.allocator;
        const b = try gpa.alloc(u8, 32 + data.len);
        defer gpa.free(b);
        @memset(b[0..32], 0);
        wire.put16(b, 0, 33);
        b[2] = proto.InfoType.file;
        b[3] = class;
        wire.put32(b, 4, @intCast(data.len));
        wire.put16(b, 8, hdr + 32);
        wire.put64(b, 16, fid.persistent);
        wire.put64(b, 24, fid.volatile_);
        @memcpy(b[32..], data);
        return f.call(.set_info, b);
    }

    fn queryInfo(f: *Fixture, fid: FileId, info_type: u8, class: u8, out_len: u32) !u32 {
        var b = try f.withFid(40, &.{ 41, 0, info_type, class }, fid, 24);
        wire.put32(&b, 4, out_len);
        return f.call(.query_info, &b);
    }

    fn lockRange(f: *Fixture, fid: FileId, off: u64, len: u64, flags: u32) !u32 {
        var b = try f.withFid(48, &.{ 48, 0, 1, 0 }, fid, 8);
        wire.put64(&b, 24, off);
        wire.put64(&b, 32, len);
        wire.put32(&b, 40, flags);
        return f.call(.lock, &b);
    }

    fn exists(f: *Fixture, name: []const u8) bool {
        f.tmp.dir.access(testing.io, name, .{}) catch return false;
        return true;
    }
};

fn freeNames(names: *std.ArrayList([]u8)) void {
    for (names.items) |n| testing.allocator.free(n);
    names.deinit(testing.allocator);
}

const rw = Access.read_data | Access.write_data;
const share_all = ShareAccess.read | ShareAccess.write | ShareAccess.delete;

test "create, write, read, and list" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();

    const c = try f.create("notes.txt", rw, share_all, Disposition.create, CreateOptions.non_directory_file);
    try testing.expectEqual(Status.success, c.status);
    try testing.expectEqual(proto.CreateAction.created, wire.get32(f.body(), 4));
    try testing.expectEqual(Status.success, try f.write(c.fid, 0, "hello, hal"));
    try testing.expectEqual(Status.success, try f.read(c.fid, 7, 100));
    try testing.expectEqualStrings("hal", f.body()[16..]);
    try testing.expectEqual(Status.end_of_file, try f.read(c.fid, 50, 10));
    try testing.expectEqual(Status.object_name_collision, (try f.create("NOTES.TXT", rw, share_all, Disposition.create, 0)).status);
    try testing.expectEqual(Status.success, try f.close(c.fid));
    try testing.expectEqual(Status.file_closed, try f.close(c.fid));

    // A case-insensitive open finds it and overwrite truncates it.
    const o = try f.create("Notes.TXT", rw, share_all, Disposition.overwrite_if, 0);
    try testing.expectEqual(Status.success, o.status);
    try testing.expectEqual(proto.CreateAction.overwritten, wire.get32(f.body(), 4));
    try testing.expectEqual(@as(u64, 0), wire.get64(f.body(), 48));
    try testing.expectEqual(Status.success, try f.close(o.fid));

    const d = try f.create("", Access.read_data, share_all, Disposition.open, CreateOptions.directory_file);
    try testing.expectEqual(Status.success, d.status);
    var names: std.ArrayList([]u8) = .empty;
    defer freeNames(&names);
    try testing.expectEqual(Status.success, try f.list(d.fid, 0, "*", &names));
    try testing.expectEqual(@as(usize, 3), names.items.len);
    try testing.expectEqualStrings(".", names.items[0]);
    try testing.expectEqualStrings("..", names.items[1]);
    try testing.expectEqualStrings("notes.txt", names.items[2]);
    try testing.expectEqual(Status.no_more_files, try f.list(d.fid, 0, "*", &names));
    try testing.expectEqual(Status.no_such_file, try f.list(d.fid, proto.QueryDirFlags.restart_scans, "*.doc", &names));
}

test "names that leave the share are refused" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    try testing.expectEqual(Status.object_name_invalid, (try f.create("..\\etc\\passwd", Access.read_data, share_all, Disposition.open, 0)).status);
    try testing.expectEqual(Status.object_name_invalid, (try f.create("a:stream", Access.read_data, share_all, Disposition.open, 0)).status);
    try f.tmp.dir.symLink(testing.io, "/etc", "out", .{});
    try testing.expectEqual(Status.access_denied, (try f.create("out\\hosts", Access.read_data, share_all, Disposition.open, 0)).status);
    try testing.expectEqual(Status.object_path_not_found, (try f.create("missing\\x", Access.read_data, share_all, Disposition.open, 0)).status);
}

test "share modes and delete on close" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const a = try f.create("skynet.bin", rw | Access.delete, ShareAccess.read, Disposition.create, 0);
    try testing.expectEqual(Status.success, a.status);
    try testing.expectEqual(Status.sharing_violation, (try f.create("skynet.bin", Access.write_data, share_all, Disposition.open, 0)).status);
    const b = try f.create("skynet.bin", Access.read_data, share_all, Disposition.open, 0);
    try testing.expectEqual(Status.success, b.status);
    // Attribute-only opens never conflict.
    const c = try f.create("skynet.bin", Access.read_attributes, 0, Disposition.open, 0);
    try testing.expectEqual(Status.success, c.status);

    try testing.expectEqual(Status.success, try f.setInfo(a.fid, FileInfo.disposition, &.{1}));
    try testing.expectEqual(Status.delete_pending, (try f.create("skynet.bin", Access.read_attributes, share_all, Disposition.open, 0)).status);
    try testing.expectEqual(Status.success, try f.close(a.fid));
    try testing.expect(f.exists("skynet.bin"));
    try testing.expectEqual(Status.success, try f.close(b.fid));
    try testing.expectEqual(Status.success, try f.close(c.fid));
    try testing.expect(!f.exists("skynet.bin"));

    const d = try f.create("gone.txt", Access.delete, share_all, Disposition.create, CreateOptions.delete_on_close);
    try testing.expectEqual(Status.success, d.status);
    try testing.expectEqual(Status.success, try f.close(d.fid));
    try testing.expect(!f.exists("gone.txt"));
    try testing.expectEqual(@as(u32, 0), f.srv.nodes.count());
}

test "directories, rename, and non-empty delete" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const d = try f.create("perihelion", Access.read_data | Access.delete, share_all, Disposition.create, CreateOptions.directory_file);
    try testing.expectEqual(Status.success, d.status);
    const x = try f.create("perihelion\\art.txt", rw | Access.delete, share_all, Disposition.create, 0);
    try testing.expectEqual(Status.success, x.status);
    try testing.expectEqual(Status.directory_not_empty, try f.setInfo(d.fid, FileInfo.disposition, &.{1}));

    const gpa = testing.allocator;
    var b = Buf.init(gpa);
    defer b.deinit();
    try b.u8_(0);
    try b.zeros(15);
    try b.u32_(@intCast(wire.utf16Len("perihelion\\renamed.txt")));
    _ = try b.utf16("perihelion\\renamed.txt");
    try testing.expectEqual(Status.success, try f.setInfo(x.fid, FileInfo.rename, b.items()));
    try testing.expect(f.exists("perihelion/renamed.txt"));
    try testing.expectEqual(Status.success, try f.queryInfo(x.fid, proto.InfoType.file, FileInfo.normalized_name, 1024));
    const nm = try wire.utf16ToUtf8(gpa, f.body()[8 + 4 ..]);
    defer gpa.free(nm);
    try testing.expectEqualStrings("perihelion\\renamed.txt", nm);

    // The directory can't be renamed while a file inside is open.
    b.clear();
    try b.u8_(0);
    try b.zeros(15);
    try b.u32_(@intCast(wire.utf16Len("other")));
    _ = try b.utf16("other");
    try testing.expectEqual(Status.access_denied, try f.setInfo(d.fid, FileInfo.rename, b.items()));

    // Collisions need ReplaceIfExists.
    const y = try f.create("perihelion\\y.txt", rw | Access.delete, share_all, Disposition.create, 0);
    try testing.expectEqual(Status.success, try f.close(y.fid));
    b.clear();
    try b.u8_(0);
    try b.zeros(15);
    try b.u32_(@intCast(wire.utf16Len("perihelion\\y.txt")));
    _ = try b.utf16("perihelion\\y.txt");
    try testing.expectEqual(Status.object_name_collision, try f.setInfo(x.fid, FileInfo.rename, b.items()));
    b.items()[0] = 1;
    try testing.expectEqual(Status.success, try f.setInfo(x.fid, FileInfo.rename, b.items()));
    try testing.expect(!f.exists("perihelion/renamed.txt"));
    try testing.expectEqual(Status.success, try f.close(x.fid));
}

test "byte-range locks" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const a = try f.create("locked", rw, share_all, Disposition.create, 0);
    try testing.expectEqual(Status.success, try f.write(a.fid, 0, "0123456789"));
    const b = try f.create("locked", rw, share_all, Disposition.open, 0);
    try testing.expectEqual(Status.success, b.status);
    const ex = proto.LockFlags.exclusive | proto.LockFlags.fail_immediately;
    try testing.expectEqual(Status.success, try f.lockRange(a.fid, 2, 4, ex));
    try testing.expectEqual(Status.file_lock_conflict, try f.read(b.fid, 0, 4));
    try testing.expectEqual(Status.success, try f.read(b.fid, 6, 4));
    try testing.expectEqual(Status.lock_not_granted, try f.lockRange(b.fid, 5, 1, proto.LockFlags.shared));
    try testing.expectEqual(Status.range_not_locked, try f.lockRange(b.fid, 2, 4, proto.LockFlags.unlock));
    try testing.expectEqual(Status.success, try f.lockRange(a.fid, 2, 4, proto.LockFlags.unlock));
    try testing.expectEqual(Status.success, try f.read(b.fid, 0, 4));
    // Closing a handle releases its locks.
    try testing.expectEqual(Status.success, try f.lockRange(a.fid, 0, 10, proto.LockFlags.shared));
    try testing.expectEqual(Status.file_lock_conflict, try f.write(b.fid, 0, "x"));
    try testing.expectEqual(Status.success, try f.close(a.fid));
    try testing.expectEqual(Status.success, try f.write(b.fid, 0, "x"));
}

test "query info sizes and read-only shares" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const a = try f.create("hal9000.txt", rw, share_all, Disposition.create, 0);
    try testing.expectEqual(Status.success, try f.write(a.fid, 0, "I'm sorry, Dave."));
    try testing.expectEqual(Status.success, try f.queryInfo(a.fid, proto.InfoType.file, FileInfo.standard, 24));
    try testing.expectEqual(@as(u64, 16), wire.get64(f.body(), 8 + 8));
    try testing.expectEqual(Status.info_length_mismatch, try f.queryInfo(a.fid, proto.InfoType.file, FileInfo.basic, 8));
    try testing.expectEqual(Status.buffer_overflow, try f.queryInfo(a.fid, proto.InfoType.file, FileInfo.all, 100));
    try testing.expectEqual(Status.success, try f.queryInfo(a.fid, proto.InfoType.filesystem, FsInfo.full_size, 32));
    try testing.expect(wire.get64(f.body(), 8) > 0);
    try testing.expectEqual(Status.success, try f.queryInfo(a.fid, proto.InfoType.security, 0, 4096));
    try testing.expectEqual(Status.invalid_info_class, try f.queryInfo(a.fid, proto.InfoType.file, 99, 4096));
    try testing.expectEqual(Status.success, try f.setInfo(a.fid, FileInfo.end_of_file, &.{ 3, 0, 0, 0, 0, 0, 0, 0 }));
    try testing.expectEqual(Status.success, try f.read(a.fid, 0, 100));
    try testing.expectEqualStrings("I'm", f.body()[16..]);
    try testing.expectEqual(Status.success, try f.close(a.fid));

    f.tree.read_only = true;
    try testing.expectEqual(Status.access_denied, (try f.create("hal9000.txt", Access.write_data, share_all, Disposition.open, 0)).status);
    try testing.expectEqual(Status.access_denied, (try f.create("new.txt", Access.read_data, share_all, Disposition.create, 0)).status);
    const r = try f.create("hal9000.txt", Access.maximum_allowed, share_all, Disposition.open, 0);
    try testing.expectEqual(Status.success, r.status);
    try testing.expectEqual(Status.access_denied, try f.write(r.fid, 0, "x"));
}

test "server-side copy" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const src = try f.create("src", rw, share_all, Disposition.create, 0);
    try testing.expectEqual(Status.success, try f.write(src.fid, 0, "copy me, art"));
    const dst = try f.create("dst", rw, share_all, Disposition.create, 0);

    var b = try f.withFid(56, &.{ 57, 0 }, src.fid, 8);
    wire.put32(&b, 4, Fsctl.srv_request_resume_key);
    wire.put32(&b, 44, 32);
    wire.put32(&b, 48, 1);
    try testing.expectEqual(Status.success, try f.call(.ioctl, &b));
    const key = f.body()[48..][0..24].*;

    var req: [56 + 32 + 24]u8 = @splat(0);
    wire.put16(&req, 0, 57);
    wire.put32(&req, 4, Fsctl.srv_copychunk);
    wire.put64(&req, 8, dst.fid.persistent);
    wire.put64(&req, 16, dst.fid.volatile_);
    wire.put32(&req, 24, hdr + 56);
    wire.put32(&req, 28, 32 + 24);
    wire.put32(&req, 44, 12);
    wire.put32(&req, 48, 1);
    @memcpy(req[56..80], &key);
    wire.put32(&req, 80, 1);
    wire.put64(&req, 88 + 8, 4); // TargetOffset
    wire.put32(&req, 88 + 16, 12);
    try testing.expectEqual(Status.success, try f.call(.ioctl, &req));
    try testing.expectEqual(@as(u32, 12), wire.get32(f.body(), 48 + 8));
    try testing.expectEqual(Status.success, try f.read(dst.fid, 0, 100));
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00copy me, art", f.body()[16..]);

    wire.put32(&req, 88 + 16, 2 * 1024 * 1024);
    try testing.expectEqual(Status.invalid_parameter, try f.call(.ioctl, &req));
    try testing.expectEqual(@as(u32, max_chunks), wire.get32(f.body(), 48));
}

const fuzz_commands = [_]proto.Command{ .create, .close, .flush, .read, .write, .lock, .ioctl, .query_directory, .change_notify, .query_info, .set_info };

fn expectedSize(cmd: proto.Command) u16 {
    return switch (cmd) {
        .create => 89,
        .close => 60,
        .flush, .lock => 4,
        .read, .write => 17,
        .ioctl => 49,
        .query_directory, .query_info => 9,
        .set_info => 2,
        else => 9,
    };
}

/// One fuzz seed: the command's index, then its body with every FileId all
/// ones (so it refers to the related open, a file with data).
fn seed(gpa: Allocator, cmd: proto.Command, body: []const u8) ![]u8 {
    const s = try gpa.alloc(u8, 1 + body.len);
    s[0] = @intCast(std.mem.indexOfScalar(proto.Command, &fuzz_commands, cmd).?);
    @memcpy(s[1..], body);
    return s;
}

fn fuzzSeeds(gpa: Allocator) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |x| gpa.free(x);
        list.deinit(gpa);
    }
    const ones: [16]u8 = @splat(0xff);
    var b = Buf.init(gpa);
    defer b.deinit();
    // CREATE "perihelion\art.txt" with MxAc and QFid contexts.
    try b.u16_(57);
    try b.zeros(22);
    try b.u32_(Access.maximum_allowed);
    try b.u32_(0);
    try b.u32_(7);
    try b.u32_(Disposition.open_if);
    try b.u32_(0);
    const name = "perihelion\\art.txt";
    try b.u16_(hdr + 56);
    try b.u16_(@intCast(wire.utf16Len(name)));
    try b.u32_(@intCast(hdr + 56 + 40));
    try b.u32_(48);
    _ = try b.utf16(name);
    try b.alignFrom(0, 8);
    while (b.len() < 56 + 40) try b.u8_(0);
    for ([_][]const u8{ "MxAc", "QFid" }, 0..) |tag, i| {
        try b.u32_(if (i == 0) 24 else 0);
        try b.u16_(16);
        try b.u16_(4);
        try b.u16_(0);
        try b.u16_(0);
        try b.u32_(0);
        try b.bytes(tag);
        try b.zeros(4);
    }
    try list.append(gpa, try seed(gpa, .create, b.items()));
    // CLOSE, FLUSH, CHANGE_NOTIFY: fixed bodies around a FileId.
    b.clear();
    try b.u16_(24);
    try b.u16_(1);
    try b.u32_(0);
    try b.bytes(&ones);
    try list.append(gpa, try seed(gpa, .close, b.items()));
    try list.append(gpa, try seed(gpa, .flush, b.items()));
    b.clear();
    try b.u16_(32);
    try b.u16_(1);
    try b.u32_(4096);
    try b.bytes(&ones);
    try b.u32_(0x17);
    try b.u32_(0);
    try list.append(gpa, try seed(gpa, .change_notify, b.items()));
    // READ 16 bytes at 2.
    b.clear();
    try b.u16_(49);
    try b.u16_(0);
    try b.u32_(16);
    try b.u64_(2);
    try b.bytes(&ones);
    try b.zeros(17);
    try list.append(gpa, try seed(gpa, .read, b.items()));
    // WRITE "dave" at 4.
    b.clear();
    try b.u16_(49);
    try b.u16_(hdr + 48);
    try b.u32_(4);
    try b.u64_(4);
    try b.bytes(&ones);
    try b.zeros(16);
    try b.bytes("dave");
    try list.append(gpa, try seed(gpa, .write, b.items()));
    // LOCK one exclusive range.
    b.clear();
    try b.u16_(48);
    try b.u16_(1);
    try b.u32_(0);
    try b.bytes(&ones);
    try b.u64_(0);
    try b.u64_(8);
    try b.u32_(proto.LockFlags.exclusive | proto.LockFlags.fail_immediately);
    try b.u32_(0);
    try list.append(gpa, try seed(gpa, .lock, b.items()));
    // IOCTL: request a resume key, then a copy chunk from the same file.
    for ([_]u32{ Fsctl.srv_request_resume_key, Fsctl.srv_copychunk_write, Fsctl.set_sparse }) |code| {
        b.clear();
        try b.u16_(57);
        try b.u16_(0);
        try b.u32_(code);
        try b.bytes(&ones);
        const in_len: u32 = if (code == Fsctl.srv_copychunk_write) 32 + 24 else 0;
        try b.u32_(hdr + 56);
        try b.u32_(in_len);
        try b.u32_(0);
        try b.u32_(0);
        try b.u32_(0);
        try b.u32_(64);
        try b.u32_(1);
        try b.u32_(0);
        if (in_len > 0) {
            try b.zeros(24); // resume key (fuzzing fills it in)
            try b.u32_(1);
            try b.u32_(0);
            try b.u64_(0);
            try b.u64_(8);
            try b.u32_(4);
            try b.u32_(0);
        }
        try list.append(gpa, try seed(gpa, .ioctl, b.items()));
    }
    // QUERY_DIRECTORY with a DOS-wildcard pattern.
    b.clear();
    try b.u16_(33);
    try b.u8_(FileInfo.id_both_directory);
    try b.u8_(proto.QueryDirFlags.restart_scans);
    try b.u32_(0);
    try b.bytes(&ones);
    try b.u16_(hdr + 32);
    try b.u16_(@intCast(wire.utf16Len("<.t*")));
    try b.u32_(4096);
    _ = try b.utf16("<.t*");
    try list.append(gpa, try seed(gpa, .query_directory, b.items()));
    // QUERY_INFO: all, file system full size, security.
    for ([_][2]u8{ .{ proto.InfoType.file, FileInfo.all }, .{ proto.InfoType.filesystem, FsInfo.full_size }, .{ proto.InfoType.security, 0 } }) |q| {
        b.clear();
        try b.u16_(41);
        try b.u8_(q[0]);
        try b.u8_(q[1]);
        try b.u32_(4096);
        try b.zeros(8);
        try b.u32_(7);
        try b.u32_(0);
        try b.bytes(&ones);
        try list.append(gpa, try seed(gpa, .query_info, b.items()));
    }
    // SET_INFO: rename, end of file, basic.
    const target = "perihelion\\moved.txt";
    for ([_]u8{ FileInfo.rename, FileInfo.end_of_file, FileInfo.basic }) |class| {
        var data = Buf.init(gpa);
        defer data.deinit();
        switch (class) {
            FileInfo.rename => {
                try data.u8_(1);
                try data.zeros(15);
                try data.u32_(@intCast(wire.utf16Len(target)));
                _ = try data.utf16(target);
            },
            FileInfo.end_of_file => try data.u64_(3),
            else => {
                try data.zeros(8);
                try data.u64_(proto.unixToNt(1_000_000_000, 0));
                try data.u64_(proto.unixToNt(1_000_000_000, 0));
                try data.zeros(8);
                try data.u32_(proto.Attr.readonly);
                try data.u32_(0);
            },
        }
        b.clear();
        try b.u16_(33);
        try b.u8_(proto.InfoType.file);
        try b.u8_(class);
        try b.u32_(@intCast(data.len()));
        try b.u16_(hdr + 32);
        try b.u16_(0);
        try b.u32_(0);
        try b.bytes(&ones);
        try b.bytes(data.items());
        try list.append(gpa, try seed(gpa, .set_info, b.items()));
    }
    return list.toOwnedSlice(gpa);
}

test "fuzz: file commands against a temporary share" {
    const gpa = testing.allocator;
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const seeds = try fuzzSeeds(gpa);
    defer {
        for (seeds) |x| gpa.free(x);
        gpa.free(seeds);
    }
    try @import("../shared/fuzz.zig").run(&f, struct {
        fn one(fx: *Fixture, in: []const u8) !void {
            if (in.len == 0) return;
            // Each input starts from the same state: one open file with data.
            closeAll(fx.conn, null, null);
            fx.ctx.related = null;
            const dir = try fx.create("perihelion", Access.read_data, share_all, Disposition.open_if, CreateOptions.directory_file);
            const base = try fx.create("perihelion\\art.txt", rw | Access.delete | Access.write_attributes, share_all, Disposition.overwrite_if, 0);
            if (base.status != Status.success) return;
            _ = try fx.write(base.fid, 0, "I'm sorry, Dave.");
            fx.ctx.related = base.fid;
            // Keep the tree writable for each input.
            vfs.chmodPath(fx.tree.root, 0o755) catch {};

            const cmd = fuzz_commands[in[0] % fuzz_commands.len];
            if (cmd == .query_directory or cmd == .change_notify) fx.ctx.related = dir.fid;
            const status = try fx.call(cmd, in[1..]);
            const out = fx.out.items();
            try testing.expect(out.len >= hdr + 2);
            const size = wire.get16(out, hdr);
            if (status == Status.success) {
                try testing.expectEqual(expectedSize(cmd), size);
            } else if (out.len == hdr + 9) {
                try testing.expectEqual(@as(u16, 9), size);
            }
            if (cmd == .read and status == Status.success) {
                try testing.expectEqual(out.len, hdr + 16 + wire.get32(out, hdr + 4));
            }
            // The node table only holds files with open handles.
            closeAll(fx.conn, null, null);
            try testing.expectEqual(@as(u32, 0), fx.srv.nodes.count());
            // `--fuzz` checks each input for leaks: drop retained capacity.
            fx.srv.nodes.clearAndFree(testing.allocator);
            fx.conn.opens.map.clearAndFree(testing.allocator);
            fx.out.list.clearAndFree(testing.allocator);
            fx.ctx.related = null;
        }
    }.one, seeds);
}
