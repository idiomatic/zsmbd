//! The server, shared by SMB connection tasks and the host: its lifecycle
//! (`start`, `adopt`, `stop`), configuration snapshot, live connection
//! registry, the table of open file nodes (share modes, delete-pending,
//! byte-range locks), an activity log ring, and the view of who is signed in
//! to what (`writeActivity`).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const host_mod = @import("host.zig");
const Host = host_mod.Host;
const Share = host_mod.Share;
const Kick = host_mod.Kick;
const Level = host_mod.Level;
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;
const Open = conn_mod.Open;

/// The settings a host chooses. `setConfig` copies them.
pub const Config = struct {
    /// NetBIOS name shown to clients (upper-cased; at most 15 characters).
    server_name: []const u8,
    workgroup: []const u8 = "WORKGROUP",
    signing_required: bool = true,
    /// Every session must encrypt.
    encrypt: bool = false,

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

/// One row of the activity view: a valid session (`tree_id` 0, `name` the
/// user, empty for anonymous) or one of its trees (`name` the share). The
/// rows mirror `Conn.sessions`, which only the connection's thread may read.
const Watch = struct {
    conn_id: u64,
    session_id: u64,
    tree_id: u32,
    name: []u8,
    /// Tree rows: the share's path as configured when the client connected.
    path: []u8,
    read_only: bool,
    since_ms: i64,
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
    host: Host,
    guid: [16]u8,
    start_ms: i64,
    /// The port `start` listens on, for the activity view; 0 before.
    smb_port: u16 = 0,
    /// The accept loop and one task per connection.
    group: Io.Group = .init,
    /// Set when `stop` has finished.
    stopped: Io.Event = .unset,

    /// Protects everything below.
    mutex: Io.Mutex = .init,
    cfg: Config,
    /// No connection starts once set.
    stopping: bool = false,
    conns: std.ArrayList(*Conn) = .empty,
    nodes: std.AutoHashMapUnmanaged(NodeKey, *Node) = .empty,
    events: [512]Event = undefined,
    event_head: usize = 0,
    event_count: usize = 0,
    watch: std.ArrayList(Watch) = .empty,

    stats: Stats = .{},
    next_id: std.atomic.Value(u64) = .init(1),

    /// A server that serves nothing until `start` or `adopt`. It must not
    /// move after that.
    pub fn init(gpa: Allocator, io: Io, host: Host, cfg: Config) Allocator.Error!Server {
        var srv: Server = .{
            .gpa = gpa,
            .io = io,
            .host = host,
            .guid = undefined,
            .start_ms = Io.Clock.real.now(io).toMilliseconds(),
            .cfg = .{ .server_name = &.{}, .workgroup = &.{} },
        };
        io.random(&srv.guid);
        try srv.setConfig(cfg);
        return srv;
    }

    /// Frees the server; after `stop`, if it was started.
    pub fn deinit(srv: *Server) void {
        srv.cfg.free(srv.gpa);
        srv.conns.deinit(srv.gpa);
        srv.nodes.deinit(srv.gpa);
        srv.deinitMonitor();
    }

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

    /// Replaces the settings. NEGOTIATE uses them from then on; a session
    /// keeps the signing rule its NEGOTIATE promised.
    pub fn setConfig(srv: *Server, cfg: Config) Allocator.Error!void {
        const name = try srv.gpa.dupe(u8, cfg.server_name);
        errdefer srv.gpa.free(name);
        for (name) |*ch| ch.* = std.ascii.toUpper(ch.*);
        const wg = try srv.gpa.dupe(u8, cfg.workgroup);
        srv.lock();
        const old = srv.cfg;
        srv.cfg = .{ .server_name = name, .workgroup = wg, .signing_required = cfg.signing_required, .encrypt = cfg.encrypt };
        srv.unlock();
        old.free(srv.gpa);
    }

    /// Copy of the current configuration; caller frees with Config.free.
    pub fn configCopy(srv: *Server, gpa: Allocator) !Config {
        srv.lock();
        defer srv.unlock();
        const n = try gpa.dupe(u8, srv.cfg.server_name);
        errdefer gpa.free(n);
        return .{ .server_name = n, .workgroup = try gpa.dupe(u8, srv.cfg.workgroup), .signing_required = srv.cfg.signing_required, .encrypt = srv.cfg.encrypt };
    }

    pub fn signingRequired(srv: *Server) bool {
        srv.lock();
        defer srv.unlock();
        return srv.cfg.signing_required;
    }

    /// Records an event for the activity view and passes it to the host.
    pub fn log(srv: *Server, conn_id: u64, kind: []const u8, comptime fmt: []const u8, args: anytype) void {
        srv.logAt(.info, conn_id, kind, fmt, args);
    }

    pub fn logAt(srv: *Server, level: Level, conn_id: u64, kind: []const u8, comptime fmt: []const u8, args: anytype) void {
        var e: Event = undefined;
        e.time_ms = srv.nowMs();
        e.conn_id = conn_id;
        e.kind_len = @intCast(@min(kind.len, e.kind.len));
        @memcpy(e.kind[0..e.kind_len], kind[0..e.kind_len]);
        const m = std.fmt.bufPrint(&e.msg, fmt, args) catch e.msg[0..];
        e.msg_len = @intCast(m.len);
        srv.host.log(level, conn_id, kind, m);
        srv.lock();
        defer srv.unlock();
        srv.events[srv.event_head] = e;
        srv.event_head = (srv.event_head + 1) % srv.events.len;
        if (srv.event_count < srv.events.len) srv.event_count += 1;
    }

    // ------------------------------------------------------------ lifecycle

    /// Serves the clients that connect to `listener` until `stop`, which the
    /// host calls before closing `listener`.
    pub fn start(srv: *Server, listener: *Io.net.Server) Io.ConcurrentError!void {
        srv.smb_port = listener.socket.address.getPort();
        try srv.group.concurrent(srv.io, acceptLoop, .{ srv, listener });
    }

    fn acceptLoop(srv: *Server, listener: *Io.net.Server) void {
        while (true) {
            const stream = listener.accept(srv.io) catch |e| switch (e) {
                error.Canceled, error.SocketNotListening => return,
                else => {
                    srv.logAt(.warn, 0, "smb", "accept: {s}", .{@errorName(e)});
                    continue;
                },
            };
            srv.adopt(stream) catch |e| {
                srv.logAt(.warn, 0, "smb", "connection not started: {s}", .{@errorName(e)});
                stream.close(srv.io);
            };
        }
    }

    /// Serves one client the host accepted; the server closes `stream`
    /// when the client leaves. On error the host still owns `stream`.
    pub fn adopt(srv: *Server, stream: Io.net.Stream) (Allocator.Error || Io.ConcurrentError || error{Stopped})!void {
        const c = try srv.gpa.create(Conn);
        c.* = .{ .gpa = srv.gpa, .srv = srv, .id = srv.newId(), .stream = stream };
        c.connected_ms = srv.nowMs();
        const peer = std.fmt.bufPrint(&c.peer, "{f}", .{stream.socket.address}) catch c.peer[0..0];
        c.peer_len = @intCast(peer.len);
        srv.addConn(c) catch |e| {
            srv.gpa.destroy(c);
            return e;
        };
        srv.group.concurrent(srv.io, conn_mod.serve, .{c}) catch |e| {
            srv.removeConn(c);
            srv.gpa.destroy(c);
            return e;
        };
    }

    /// Stops accepting, drops every client, and returns once their tasks
    /// have finished (their opens closed). Call once, not from a callback.
    pub fn stop(srv: *Server) void {
        srv.lock();
        srv.stopping = true;
        for (srv.conns.items) |c| c.stream.shutdown(srv.io, .both) catch {};
        srv.unlock();
        srv.group.cancel(srv.io);
        srv.stopped.set(srv.io);
    }

    /// Blocks until `stop` has finished.
    pub fn wait(srv: *Server) Io.Cancelable!void {
        return srv.stopped.wait(srv.io);
    }

    pub fn addConn(srv: *Server, c: *Conn) (Allocator.Error || error{Stopped})!void {
        srv.lock();
        defer srv.unlock();
        if (srv.stopping) return error.Stopped;
        try srv.conns.append(srv.gpa, c);
        _ = srv.stats.connections_total.fetchAdd(1, .monotonic);
    }

    pub fn removeConn(srv: *Server, c: *Conn) void {
        srv.lock();
        defer srv.unlock();
        srv.dropWatch(c.id, null, null);
        for (srv.conns.items, 0..) |x, i| if (x == c) {
            _ = srv.conns.swapRemove(i);
            break;
        };
    }

    // ------------------------------------------------------------ activity view

    /// Records a signed-in session (`user` empty for anonymous). Best effort:
    /// the view is for the admin console only.
    pub fn watchSession(srv: *Server, conn_id: u64, session_id: u64, user: []const u8) void {
        srv.addWatch(.{ .conn_id = conn_id, .session_id = session_id, .tree_id = 0, .name = user, .path = "", .read_only = false });
    }

    pub fn watchTree(srv: *Server, conn_id: u64, session_id: u64, tree_id: u32, share: []const u8, path: []const u8, read_only: bool) void {
        srv.addWatch(.{ .conn_id = conn_id, .session_id = session_id, .tree_id = tree_id, .name = share, .path = path, .read_only = read_only });
    }

    pub fn unwatchSession(srv: *Server, conn_id: u64, session_id: u64) void {
        srv.lock();
        defer srv.unlock();
        srv.dropWatch(conn_id, session_id, null);
    }

    pub fn unwatchTree(srv: *Server, conn_id: u64, session_id: u64, tree_id: u32) void {
        srv.lock();
        defer srv.unlock();
        srv.dropWatch(conn_id, session_id, tree_id);
    }

    pub fn deinitMonitor(srv: *Server) void {
        for (srv.watch.items) |w| {
            srv.gpa.free(w.name);
            srv.gpa.free(w.path);
        }
        srv.watch.deinit(srv.gpa);
        srv.watch = .empty;
    }

    const NewWatch = struct { conn_id: u64, session_id: u64, tree_id: u32, name: []const u8, path: []const u8, read_only: bool };

    fn addWatch(srv: *Server, n: NewWatch) void {
        const name = srv.gpa.dupe(u8, n.name) catch return;
        const path = srv.gpa.dupe(u8, n.path) catch {
            srv.gpa.free(name);
            return;
        };
        const since = srv.nowMs();
        srv.lock();
        defer srv.unlock();
        srv.watch.append(srv.gpa, .{ .conn_id = n.conn_id, .session_id = n.session_id, .tree_id = n.tree_id, .name = name, .path = path, .read_only = n.read_only, .since_ms = since }) catch {
            srv.gpa.free(name);
            srv.gpa.free(path);
        };
    }

    /// Removes the rows of a connection, of one of its sessions (with its
    /// trees), or of one tree. Caller holds the lock.
    fn dropWatch(srv: *Server, conn_id: u64, session_id: ?u64, tree_id: ?u32) void {
        var i: usize = 0;
        while (i < srv.watch.items.len) {
            const w = srv.watch.items[i];
            const hit = w.conn_id == conn_id and
                (session_id == null or w.session_id == session_id.?) and
                (tree_id == null or w.tree_id == tree_id.?);
            if (hit) {
                srv.gpa.free(w.name);
                srv.gpa.free(w.path);
                _ = srv.watch.orderedRemove(i);
            } else i += 1;
        }
    }

    /// Writes the activity view as JSON for the admin console: the server,
    /// its connections with their sessions and trees, the event log (oldest
    /// first), and the counters. The caller's `gpa` is scratch space.
    pub fn writeActivity(srv: *Server, gpa: Allocator, w: *Io.Writer) !void {
        const now = srv.nowMs();
        srv.lock();
        defer srv.unlock();
        var open_counts: std.AutoHashMapUnmanaged(u64, u32) = .empty;
        defer open_counts.deinit(gpa);
        var nodes = srv.nodes.valueIterator();
        while (nodes.next()) |n| for (n.*.opens.items) |o| {
            const gop = try open_counts.getOrPut(gpa, o.conn.id);
            gop.value_ptr.* = if (gop.found_existing) gop.value_ptr.* + 1 else 1;
        };

        var j: std.json.Stringify = .{ .writer = w };
        try j.beginObject();
        try j.objectField("smb_running");
        try j.write(true);
        try j.objectField("server");
        try j.write(.{ .name = srv.cfg.server_name, .port = srv.smb_port, .start_ms = srv.start_ms, .now_ms = now });

        try j.objectField("connections");
        try j.beginArray();
        for (srv.conns.items) |c| {
            try j.beginObject();
            try j.objectField("id");
            try j.write(c.id);
            try j.objectField("peer");
            try j.write(c.peer[0..c.peer_len]);
            try j.objectField("connected_ms");
            try j.write(c.connected_ms);
            try j.objectField("opens");
            try j.write(open_counts.get(c.id) orelse 0);
            try j.objectField("sessions");
            try j.beginArray();
            for (srv.watch.items) |s| {
                if (s.conn_id != c.id or s.tree_id != 0) continue;
                try j.beginObject();
                try j.objectField("id");
                try j.write(s.session_id);
                try j.objectField("user");
                try j.write(s.name);
                try j.objectField("anonymous");
                try j.write(s.name.len == 0);
                try j.objectField("since_ms");
                try j.write(s.since_ms);
                try j.objectField("trees");
                try j.beginArray();
                for (srv.watch.items) |t| {
                    if (t.conn_id != c.id or t.session_id != s.session_id or t.tree_id == 0) continue;
                    try j.write(.{ .id = t.tree_id, .share = t.name, .read_only = t.read_only, .since_ms = t.since_ms });
                }
                try j.endArray();
                try j.endObject();
            }
            try j.endArray();
            try j.endObject();
        }
        try j.endArray();

        try j.objectField("events");
        try j.beginArray();
        const first = (srv.event_head + srv.events.len - srv.event_count) % srv.events.len;
        for (0..srv.event_count) |k| {
            const e = &srv.events[(first + k) % srv.events.len];
            try j.write(.{ .time_ms = e.time_ms, .conn_id = e.conn_id, .kind = e.kindStr(), .msg = e.msgStr() });
        }
        try j.endArray();

        try j.objectField("stats");
        try j.write(.{
            .connections_now = srv.conns.items.len,
            .connections_total = srv.stats.connections_total.load(.monotonic),
            .bytes_in = srv.stats.bytes_in.load(.monotonic),
            .bytes_out = srv.stats.bytes_out.load(.monotonic),
            .data_read = srv.stats.data_read.load(.monotonic),
            .data_written = srv.stats.data_written.load(.monotonic),
            .requests = srv.stats.requests.load(.monotonic),
            .logon_failures = srv.stats.logon_failures.load(.monotonic),
        });
        try j.endObject();
    }

    /// IDs of the connections whose rights on `share` the share as it is now
    /// (`cur`; null when it is gone) no longer allows: a tree opened writable
    /// on a share now read-only, a tree on a share that moved, or an
    /// anonymous session on a share without guests. Relaxing a share makes
    /// none stale, unless `relax` asks for them: `.writable` adds the trees
    /// opened read-only on a share now writable, `.guests` the connections
    /// with an anonymous session on a share now open to guests. Caller frees
    /// the slice.
    pub fn staleOnShare(srv: *Server, gpa: Allocator, share: []const u8, cur: ?Share, relax: Kick) ![]u64 {
        srv.lock();
        defer srv.unlock();
        var ids: std.ArrayList(u64) = .empty;
        errdefer ids.deinit(gpa);
        for (srv.watch.items) |t| {
            if (t.tree_id == 0 or !std.ascii.eqlIgnoreCase(t.name, share)) continue;
            const stale = if (cur) |c|
                (!t.read_only and c.read_only) or !std.mem.eql(u8, t.path, c.path) or
                    (!c.guest_ok and srv.sessionIsAnonymous(t.conn_id, t.session_id)) or
                    (relax == .writable and t.read_only and !c.read_only)
            else
                true;
            if (stale and std.mem.indexOfScalar(u64, ids.items, t.conn_id) == null) try ids.append(gpa, t.conn_id);
        }
        // A refused anonymous session has no tree, so it is found by name.
        if (relax == .guests) if (cur) |c| if (c.guest_ok) for (srv.watch.items) |s| {
            if (s.tree_id == 0 and s.name.len == 0 and std.mem.indexOfScalar(u64, ids.items, s.conn_id) == null) try ids.append(gpa, s.conn_id);
        };
        return ids.toOwnedSlice(gpa);
    }

    /// Caller holds the lock.
    fn sessionIsAnonymous(srv: *Server, conn_id: u64, session_id: u64) bool {
        for (srv.watch.items) |s| {
            if (s.tree_id == 0 and s.conn_id == conn_id and s.session_id == session_id) return s.name.len == 0;
        }
        return false;
    }

    /// Call after the host changed (or deleted) share `name`: drops the
    /// connections whose access it now tightens, so each client reconnects
    /// under the new rules (`relax`: see staleOnShare). Returns how many
    /// were dropped.
    pub fn reconcileShare(srv: *Server, name: []const u8, relax: Kick) usize {
        const shares = srv.host.listShares(srv.gpa) catch return 0;
        defer host_mod.freeShares(srv.gpa, shares);
        const cur: ?Share = for (shares) |sh| {
            if (std.ascii.eqlIgnoreCase(sh.name, name)) break sh;
        } else null;
        const ids = srv.staleOnShare(srv.gpa, name, cur, relax) catch return 0;
        defer srv.gpa.free(ids);
        const n = srv.kickAll(ids);
        if (n > 0) srv.log(0, "share", "{s} changed: {d} connection(s) dropped", .{ name, n });
        return n;
    }

    /// IDs of the connections with a session of user `name` (any case).
    /// Caller frees the slice.
    pub fn connectionsOfUser(srv: *Server, gpa: Allocator, name: []const u8) ![]u64 {
        srv.lock();
        defer srv.unlock();
        var ids: std.ArrayList(u64) = .empty;
        errdefer ids.deinit(gpa);
        for (srv.watch.items) |w| {
            if (w.tree_id != 0 or w.name.len == 0 or !std.ascii.eqlIgnoreCase(w.name, name)) continue;
            if (std.mem.indexOfScalar(u64, ids.items, w.conn_id) == null) try ids.append(gpa, w.conn_id);
        }
        return ids.toOwnedSlice(gpa);
    }

    /// Call after the host changed user `name`: drops their connections if
    /// they no longer have an SMB password (or no longer exist). A new
    /// password alone keeps sessions, as on any SMB server.
    pub fn reconcileUser(srv: *Server, name: []const u8) usize {
        const nt = srv.host.ntHash(name) catch return 0;
        if (nt != null) return 0;
        const ids = srv.connectionsOfUser(srv.gpa, name) catch return 0;
        defer srv.gpa.free(ids);
        const n = srv.kickAll(ids);
        if (n > 0) srv.log(0, "user", "{s} lost SMB access: {d} connection(s) dropped", .{ name, n });
        return n;
    }

    fn kickAll(srv: *Server, ids: []const u64) usize {
        var n: usize = 0;
        for (ids) |id| if (srv.kick(id)) {
            n += 1;
        };
        return n;
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

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "stop drops the clients and ends their tasks" {
    const gpa = testing.allocator;
    const io = testing.io;
    var th: host_mod.TestHost = .{ .gpa = gpa };
    defer th.deinit();
    var srv: Server = try .init(gpa, io, th.host(), .{ .server_name = "hal9000" });
    defer srv.deinit();
    try testing.expectEqualStrings("HAL9000", srv.cfg.server_name);
    const addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{});
    defer listener.deinit(io);
    try srv.start(&listener);
    try testing.expect(srv.smb_port != 0);

    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    // Until the server has registered the client.
    for (0..1000) |_| {
        srv.lock();
        const n = srv.conns.items.len;
        srv.unlock();
        if (n == 1) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    } else return error.TestUnexpectedResult;

    srv.stop();
    try srv.wait();
    try testing.expectEqual(@as(usize, 0), srv.conns.items.len);
    var buf: [1]u8 = undefined;
    var r = client.reader(io, &buf);
    try testing.expectError(error.EndOfStream, r.interface.takeByte());
    try testing.expectError(error.Stopped, srv.adopt(client));
}

test "the activity view lists connections, sessions, trees, and events" {
    var t: conn_mod.TestConn = undefined;
    try t.init();
    defer t.deinit();
    const c = t.conn;
    c.connected_ms = 5;
    const peer = "127.0.0.1:50000";
    @memcpy(c.peer[0..peer.len], peer);
    c.peer_len = peer.len;
    try t.srv.conns.append(testing.allocator, c);
    t.srv.watchSession(c.id, 7, "hal");
    t.srv.watchTree(c.id, 7, 3, "data", "/srv/data", true);
    t.srv.watchSession(c.id, 8, "");
    t.srv.log(c.id, "auth", "hal logged on from {s}", .{"HAL9000"});

    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try t.srv.writeActivity(testing.allocator, &aw.writer);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expect(root.get("smb_running").?.bool);
    const conn = root.get("connections").?.array.items[0].object;
    try testing.expectEqualStrings(peer, conn.get("peer").?.string);
    try testing.expectEqual(@as(i64, 5), conn.get("connected_ms").?.integer);
    const sessions = conn.get("sessions").?.array.items;
    try testing.expectEqual(@as(usize, 2), sessions.len);
    try testing.expectEqualStrings("hal", sessions[0].object.get("user").?.string);
    try testing.expect(!sessions[0].object.get("anonymous").?.bool and sessions[1].object.get("anonymous").?.bool);
    const tree = sessions[0].object.get("trees").?.array.items[0].object;
    try testing.expectEqualStrings("data", tree.get("share").?.string);
    try testing.expect(tree.get("read_only").?.bool);
    try testing.expectEqual(@as(usize, 0), sessions[1].object.get("trees").?.array.items.len);
    const event = root.get("events").?.array.items[0].object;
    try testing.expectEqualStrings("auth", event.get("kind").?.string);
    try testing.expectEqualStrings("hal logged on from HAL9000", event.get("msg").?.string);
    try testing.expectEqual(@as(i64, 1), root.get("stats").?.object.get("connections_now").?.integer);

    // Trees, sessions, and finally the connection drop their rows.
    t.srv.unwatchTree(c.id, 7, 3);
    t.srv.unwatchSession(c.id, 8);
    try testing.expectEqual(@as(usize, 1), t.srv.watch.items.len);
    t.srv.removeConn(c);
    try testing.expectEqual(@as(usize, 0), t.srv.watch.items.len);
}

test "the event log is written oldest first after it wraps" {
    var t: conn_mod.TestConn = undefined;
    try t.init();
    defer t.deinit();
    for (0..t.srv.events.len + 3) |i| t.srv.log(1, "n", "event {d}", .{i});
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try t.srv.writeActivity(testing.allocator, &aw.writer);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const events = parsed.value.object.get("events").?.array.items;
    try testing.expectEqual(t.srv.events.len, events.len);
    try testing.expectEqualStrings("event 3", events[0].object.get("msg").?.string);
    try testing.expectEqualStrings("event 514", events[events.len - 1].object.get("msg").?.string);
}

test "which connections a changed share leaves stale" {
    var t: conn_mod.TestConn = undefined;
    try t.init();
    defer t.deinit();
    const srv = &t.srv;
    const gpa = testing.allocator;
    // Connection 1: hal and a guest on Data; 2: art on data, read-only;
    // 3: art on another share.
    srv.watchSession(1, 7, "hal");
    srv.watchTree(1, 7, 3, "Data", "/srv/data", false);
    srv.watchSession(1, 8, "");
    srv.watchTree(1, 8, 4, "Data", "/srv/data", false);
    srv.watchSession(2, 9, "art");
    srv.watchTree(2, 9, 5, "data", "/srv/data", true);
    srv.watchSession(3, 10, "art");
    srv.watchTree(3, 10, 6, "other", "/srv/other", false);

    const open: Share = .{ .name = "data", .path = "/srv/data", .guest_ok = true };
    // Unchanged, or relaxed, leaves nobody stale.
    const same = try srv.staleOnShare(gpa, "DATA", open, .none);
    defer gpa.free(same);
    try testing.expectEqual(@as(usize, 0), same.len);
    // Read-only turned on: the writable trees (connection 1 only).
    var cur = open;
    cur.read_only = true;
    const ro = try srv.staleOnShare(gpa, "data", cur, .none);
    defer gpa.free(ro);
    try testing.expectEqualSlices(u64, &.{1}, ro);
    // Guests turned off: only the guest session's connection.
    cur = open;
    cur.guest_ok = false;
    const noguest = try srv.staleOnShare(gpa, "data", cur, .none);
    defer gpa.free(noguest);
    try testing.expectEqualSlices(u64, &.{1}, noguest);
    // Moved, or deleted: every connection using it.
    cur = open;
    cur.path = "/srv/elsewhere";
    const moved = try srv.staleOnShare(gpa, "data", cur, .none);
    defer gpa.free(moved);
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, moved);
    const gone = try srv.staleOnShare(gpa, "data", null, .none);
    defer gpa.free(gone);
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, gone);
    // Kicking after a relaxing change: connection 2 holds a read-only tree
    // (found once the share is writable); connections with an anonymous
    // session (1) are found once the share admits guests. Each kick finds
    // only its own kind, and none at all while the share is unchanged.
    const rw = try srv.staleOnShare(gpa, "data", open, .writable);
    defer gpa.free(rw);
    try testing.expectEqualSlices(u64, &.{2}, rw);
    var tight = open;
    tight.read_only = true;
    const rw_tight = try srv.staleOnShare(gpa, "data", tight, .writable);
    defer gpa.free(rw_tight);
    try testing.expectEqualSlices(u64, &.{1}, rw_tight);
    const guests = try srv.staleOnShare(gpa, "data", open, .guests);
    defer gpa.free(guests);
    try testing.expectEqualSlices(u64, &.{1}, guests);
    var closed = open;
    closed.guest_ok = false;
    const guests_closed = try srv.staleOnShare(gpa, "data", closed, .guests);
    defer gpa.free(guests_closed);
    try testing.expectEqualSlices(u64, &.{1}, guests_closed); // the usual noguest rule
    // Nothing is registered as a live connection, so nothing is dropped.
    try testing.expectEqual(@as(usize, 0), srv.reconcileShare("data", .none));

    const art = try srv.connectionsOfUser(gpa, "ART");
    defer gpa.free(art);
    try testing.expectEqualSlices(u64, &.{ 2, 3 }, art);
    const anon = try srv.connectionsOfUser(gpa, "");
    defer gpa.free(anon);
    try testing.expectEqual(@as(usize, 0), anon.len);
}
