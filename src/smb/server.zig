//! Process-wide server state shared by SMB connection threads and the admin
//! web server: configuration snapshot, live connection registry, the table of
//! open file nodes (share modes, delete-pending, byte-range locks) and an
//! activity log ring.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Db = @import("../store/store.zig").Db;
const auth = @import("../policy/auth.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;
const Open = conn_mod.Open;

pub const Config = struct {
    server_name: []u8,
    workgroup: []u8,
    signing_required: bool,
    encrypt: bool,

    pub fn free(cfg: Config, gpa: Allocator) void {
        gpa.free(cfg.server_name);
        gpa.free(cfg.workgroup);
    }
};

pub const NodeKey = struct { dev: u64, ino: u64 };

pub const Lock = struct {
    off: u64,
    len: u64,
    exclusive: bool,
    owner: *Open,

    pub fn overlaps(l: Lock, off: u64, len: u64) bool {
        if (len == 0 or l.len == 0) return false;
        const a_end = l.off +| l.len;
        const b_end = off +| len;
        return l.off < b_end and off < a_end;
    }
};

/// A file system object that has at least one open handle.
pub const Node = struct {
    key: NodeKey,
    path: [:0]u8,
    is_dir: bool,
    opens: std.ArrayList(*Open) = .empty,
    locks: std.ArrayList(Lock) = .empty,
    delete_pending: bool = false,
};

pub const Event = struct {
    time_ms: i64,
    conn_id: u64,
    kind: [12]u8,
    kind_len: u8,
    msg: [200]u8,
    msg_len: u8,

    pub fn kindStr(e: *const Event) []const u8 {
        return e.kind[0..e.kind_len];
    }
    pub fn msgStr(e: *const Event) []const u8 {
        return e.msg[0..e.msg_len];
    }
};

pub const Stats = struct {
    connections_total: std.atomic.Value(u64) = .init(0),
    bytes_in: std.atomic.Value(u64) = .init(0),
    bytes_out: std.atomic.Value(u64) = .init(0),
    data_read: std.atomic.Value(u64) = .init(0),
    data_written: std.atomic.Value(u64) = .init(0),
    requests: std.atomic.Value(u64) = .init(0),
    logon_failures: std.atomic.Value(u64) = .init(0),
};

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    db: *Db,
    guid: [16]u8,
    start_ms: i64,
    smb_port: u16,

    /// Protects everything below.
    mutex: Io.Mutex = .init,
    cfg: Config,
    conns: std.ArrayList(*Conn) = .empty,
    nodes: std.AutoHashMapUnmanaged(NodeKey, *Node) = .empty,
    events: [512]Event = undefined,
    event_head: usize = 0,
    event_count: usize = 0,

    stats: Stats = .{},
    next_id: std.atomic.Value(u64) = .init(1),

    pub fn nowMs(srv: *Server) i64 {
        return Io.Clock.real.now(srv.io).toMilliseconds();
    }

    pub fn newId(srv: *Server) u64 {
        return srv.next_id.fetchAdd(1, .monotonic);
    }

    pub fn lock(srv: *Server) void {
        srv.mutex.lockUncancelable(srv.io);
    }
    pub fn unlock(srv: *Server) void {
        srv.mutex.unlock(srv.io);
    }

    /// Re-read configuration from the database.
    pub fn loadConfig(srv: *Server) !void {
        const gpa = srv.gpa;
        const name = (try srv.db.getSetting(gpa, "server_name")) orelse try defaultServerName(gpa);
        errdefer gpa.free(name);
        for (name) |*ch| ch.* = std.ascii.toUpper(ch.*);
        const wg = (try srv.db.getSetting(gpa, "workgroup")) orelse try gpa.dupe(u8, "WORKGROUP");
        errdefer gpa.free(wg);
        const sr = try srv.boolSetting("signing_required", true);
        const enc = try srv.boolSetting("encrypt", false);
        srv.lock();
        defer srv.unlock();
        if (srv.cfg.server_name.len != 0) srv.cfg.free(gpa);
        srv.cfg = .{ .server_name = name, .workgroup = wg, .signing_required = sr, .encrypt = enc };
    }

    fn boolSetting(srv: *Server, key: []const u8, default: bool) !bool {
        const v = (try srv.db.getSetting(srv.gpa, key)) orelse return default;
        defer srv.gpa.free(v);
        // Hand-edited text files skip the CLI and web checks.
        const n = auth.normalizeSetting(key, v) catch {
            std.log.err("setting {s} = {s}: expected yes or no", .{ key, v });
            return error.InvalidSetting;
        };
        return n[0] == 't';
    }

    /// Copy of the current configuration; caller frees with Config.free.
    pub fn configCopy(srv: *Server, gpa: Allocator) !Config {
        srv.lock();
        defer srv.unlock();
        const n = try gpa.dupe(u8, srv.cfg.server_name);
        errdefer gpa.free(n);
        return .{ .server_name = n, .workgroup = try gpa.dupe(u8, srv.cfg.workgroup), .signing_required = srv.cfg.signing_required, .encrypt = srv.cfg.encrypt };
    }

    pub fn log(srv: *Server, conn_id: u64, kind: []const u8, comptime fmt: []const u8, args: anytype) void {
        var e: Event = undefined;
        e.time_ms = srv.nowMs();
        e.conn_id = conn_id;
        e.kind_len = @intCast(@min(kind.len, e.kind.len));
        @memcpy(e.kind[0..e.kind_len], kind[0..e.kind_len]);
        const m = std.fmt.bufPrint(&e.msg, fmt, args) catch e.msg[0..];
        e.msg_len = @intCast(m.len);
        std.log.info("[{d}] {s}: {s}", .{ conn_id, kind, m });
        srv.lock();
        defer srv.unlock();
        srv.events[srv.event_head] = e;
        srv.event_head = (srv.event_head + 1) % srv.events.len;
        if (srv.event_count < srv.events.len) srv.event_count += 1;
    }

    /// Accept SMB clients on `listener` until it fails, one thread per
    /// connection. Each `Conn` releases itself when its client leaves.
    pub fn acceptLoop(srv: *Server, listener: *Io.net.Server) void {
        while (true) {
            const stream = listener.accept(srv.io) catch |e| {
                std.log.warn("smb accept: {s}", .{@errorName(e)});
                continue;
            };
            srv.startConn(stream) catch |e| {
                std.log.warn("smb connection not started: {s}", .{@errorName(e)});
                stream.close(srv.io);
            };
        }
    }

    fn startConn(srv: *Server, stream: Io.net.Stream) !void {
        const c = try srv.gpa.create(Conn);
        c.* = .{ .gpa = srv.gpa, .srv = srv, .id = srv.newId(), .stream = stream };
        srv.addConn(c) catch |e| {
            srv.gpa.destroy(c);
            return e;
        };
        const t = std.Thread.spawn(.{}, conn_mod.serve, .{c}) catch |e| {
            srv.removeConn(c);
            srv.gpa.destroy(c);
            return e;
        };
        t.detach();
    }

    pub fn addConn(srv: *Server, c: *Conn) !void {
        srv.lock();
        defer srv.unlock();
        try srv.conns.append(srv.gpa, c);
        _ = srv.stats.connections_total.fetchAdd(1, .monotonic);
    }

    pub fn removeConn(srv: *Server, c: *Conn) void {
        srv.lock();
        defer srv.unlock();
        for (srv.conns.items, 0..) |x, i| if (x == c) {
            _ = srv.conns.swapRemove(i);
            break;
        };
    }

    /// Request that a connection be dropped (from the admin UI).
    pub fn kick(srv: *Server, conn_id: u64) bool {
        srv.lock();
        defer srv.unlock();
        for (srv.conns.items) |c| if (c.id == conn_id) {
            c.stream.shutdown(srv.io, .both) catch {};
            return true;
        };
        return false;
    }

    // ------------------------------------------------------------ nodes (caller holds lock)

    pub fn getNode(srv: *Server, key: NodeKey, path: []const u8, is_dir: bool) !*Node {
        const gop = try srv.nodes.getOrPut(srv.gpa, key);
        if (gop.found_existing) {
            const n = gop.value_ptr.*;
            if (!std.mem.eql(u8, n.path, path)) {
                const np = try srv.gpa.dupeSentinel(u8, path, 0);
                srv.gpa.free(n.path);
                n.path = np;
            }
            return n;
        }
        errdefer srv.nodes.removeByPtr(gop.key_ptr);
        const n = try srv.gpa.create(Node);
        errdefer srv.gpa.destroy(n);
        n.* = .{ .key = key, .path = try srv.gpa.dupeSentinel(u8, path, 0), .is_dir = is_dir };
        gop.value_ptr.* = n;
        return n;
    }

    pub fn dropNodeIfUnused(srv: *Server, n: *Node) void {
        if (n.opens.items.len != 0) return;
        _ = srv.nodes.remove(n.key);
        n.opens.deinit(srv.gpa);
        n.locks.deinit(srv.gpa);
        srv.gpa.free(n.path);
        srv.gpa.destroy(n);
    }

    /// After a rename, update paths of the node and of nodes beneath it.
    pub fn renameNodes(srv: *Server, old: []const u8, new: []const u8) void {
        var it = srv.nodes.valueIterator();
        while (it.next()) |np| {
            const n = np.*;
            if (std.mem.eql(u8, n.path, old) or (std.mem.startsWith(u8, n.path, old) and n.path.len > old.len and n.path[old.len] == '/')) {
                const updated = std.fmt.allocPrintSentinel(srv.gpa, "{s}{s}", .{ new, n.path[old.len..] }, 0) catch continue;
                srv.gpa.free(n.path);
                n.path = updated;
            }
        }
    }

    /// Notify connections with CHANGE_NOTIFY requests pending on `dir_path`
    /// (an absolute host path) that its contents changed.
    pub fn dirChanged(srv: *Server, dir_path: []const u8, origin: *Conn) void {
        srv.lock();
        const conns = srv.gpa.dupe(*Conn, srv.conns.items) catch {
            srv.unlock();
            return;
        };
        for (conns) |c| c.ref();
        srv.unlock();
        defer {
            for (conns) |c| c.unref();
            srv.gpa.free(conns);
        }
        for (conns) |c| c.completeNotifies(dir_path, origin);
    }
};

fn defaultServerName(gpa: Allocator) ![]u8 {
    var buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const h = std.posix.gethostname(&buf) catch return gpa.dupe(u8, "ZSMBD");
    const short = h[0 .. std.mem.indexOfScalar(u8, h, '.') orelse h.len];
    return gpa.dupe(u8, short[0..@min(short.len, 15)]);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "loadConfig reads yes and no as hand-edited text files write them" {
    var t: conn_mod.TestConn = undefined;
    try t.init();
    defer t.deinit();
    try t.db.setSetting("encrypt", "yes");
    try t.db.setSetting("signing_required", "No");
    try t.srv.loadConfig();
    defer t.srv.cfg.free(testing.allocator);
    try testing.expect(t.srv.cfg.encrypt and !t.srv.cfg.signing_required);
}
