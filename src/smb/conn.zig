//! One SMB2/3 client connection: framing, compounding, signing/encryption,
//! NEGOTIATE, SESSION_SETUP, TREE_CONNECT and request dispatch.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const proto = @import("proto.zig");
const Status = proto.Status;
const Command = proto.Command;
const wire = @import("../shared/wire.zig");
const Buf = wire.Buf;
const crypto = @import("../shared/crypto.zig");
const ntlm = @import("auth/ntlm.zig");
const spnego = @import("auth/spnego.zig");
const files = @import("files.zig");
const rpc = @import("rpc.zig");
const vfs = @import("vfs.zig");
const state = @import("server.zig");
const Server = state.Server;
const db_mod = @import("../store/store.zig");

pub const max_io_size: u32 = 4 * 1024 * 1024;
const max_frame: usize = max_io_size + 64 * 1024;

pub const Session = struct {
    id: u64,
    state: enum { in_progress, valid } = .in_progress,
    auth: ?ntlm.Server = null,
    mech_types: []u8 = &.{},
    user: []u8 = &.{},
    domain: []u8 = &.{},
    workstation: []u8 = &.{},
    anonymous: bool = false,
    session_key: [16]u8 = @splat(0),
    signing_key: [16]u8 = @splat(0),
    dec_key: [16]u8 = @splat(0),
    enc_key: [16]u8 = @splat(0),
    sign: bool = false,
    encrypt: bool = false,
    preauth: [64]u8 = @splat(0),
    trees: std.AutoHashMapUnmanaged(u32, *Tree) = .empty,
    created_ms: i64,

    pub fn hasKey(s: *const Session) bool {
        return s.state == .valid and !s.anonymous;
    }
};

pub const Tree = struct {
    id: u32,
    session_id: u64,
    share: []u8,
    root: [:0]u8,
    ipc: bool,
    read_only: bool,
    connected_ms: i64,

    pub fn maxAccess(t: *const Tree) u32 {
        return if (t.read_only or t.ipc) proto.Access.read_only_max else proto.Access.file_all;
    }
};

pub const OpenKind = enum { file, dir, pipe };

pub const Open = struct {
    volatile_id: u64,
    persistent_id: u64,
    conn: *Conn,
    session_id: u64,
    tree: *Tree,
    kind: OpenKind,
    fd: vfs.Fd = -1,
    node: ?*state.Node = null,
    /// Share-relative path using '/' separators ("" for the root).
    rel_path: []u8,
    access: u32,
    share_access: u32,
    create_options: u32,
    delete_on_close: bool = false,
    position: u64 = 0,
    opened_ms: i64,
    // Directory enumeration state.
    dir_names: ?[][]u8 = null,
    dir_pos: usize = 0,
    dir_pattern: []u8 = &.{},
    /// Whether any entry matched since the last restart.
    dir_any: bool = false,
    // Named pipe.
    pipe: ?*rpc.Pipe = null,
    // Activity counters (monitor).
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,

    pub fn fileIdMatches(o: *const Open, persistent: u64) bool {
        return o.persistent_id == persistent;
    }
};

/// A pending CHANGE_NOTIFY request; everything needed to send the completion
/// from any thread is copied here.
pub const Notify = struct {
    async_id: u64,
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    volatile_id: u64,
    dir_path: [:0]u8,
    watch_tree: bool,
    /// Copied from the session so another thread can sign or seal.
    sign: bool,
    signing_key: [16]u8,
    encrypt: bool,
    enc_key: [16]u8,
};

/// The connection core that `state.zig` and `files.zig` rely on: identity,
/// reference counting, the open-handle table, pending CHANGE_NOTIFYs, and the
/// framed, signed or sealed write path. The request loop, NEGOTIATE,
/// SESSION_SETUP, and TREE_CONNECT are still to be written (ARCHITECTURE.md
/// section 7.2).
pub const Conn = struct {
    gpa: Allocator,
    srv: *Server,
    id: u64,
    stream: net.Stream,
    refs: std.atomic.Value(u32) = .init(1),
    closed: std.atomic.Value(bool) = .init(false),
    neg: files.Negotiated = .{},
    sessions: std.AutoHashMapUnmanaged(u64, *Session) = .empty,
    opens: files.Opens = .{},
    /// Serializes socket writes (this thread and notify completions).
    write_mutex: Io.Mutex = .init,
    /// Protects `notifies` and `next_async`.
    notify_mutex: Io.Mutex = .init,
    notifies: std.ArrayList(Notify) = .empty,
    next_async: u64 = 1,

    pub fn ref(c: *Conn) void {
        _ = c.refs.fetchAdd(1, .monotonic);
    }

    pub fn unref(c: *Conn) void {
        if (c.refs.fetchSub(1, .acq_rel) != 1) return;
        const io = c.srv.io;
        c.stream.close(io);
        for (c.notifies.items) |n| c.gpa.free(n.dir_path);
        c.notifies.deinit(c.gpa);
        c.gpa.destroy(c);
    }

    /// Queue a CHANGE_NOTIFY that files.zig answered with STATUS_PENDING;
    /// returns its async ID for the interim response. Takes ownership of
    /// `n.dir_path`.
    pub fn queueNotify(c: *Conn, n: Notify) !u64 {
        c.notify_mutex.lockUncancelable(c.srv.io);
        defer c.notify_mutex.unlock(c.srv.io);
        var q = n;
        q.async_id = c.next_async;
        try c.notifies.append(c.gpa, q);
        c.next_async += 1;
        return q.async_id;
    }

    /// Complete pending notifies on `dir_path` (or above it, for watch-tree
    /// requests). Called from any thread.
    pub fn completeNotifies(c: *Conn, dir_path: []const u8, origin: *Conn) void {
        _ = origin;
        if (c.closed.load(.acquire)) return;
        c.finishNotifies(.{ .path = dir_path }, Status.notify_enum_dir);
    }

    /// Complete the notifies on a closed handle with STATUS_NOTIFY_CLEANUP.
    pub fn cleanupNotifies(c: *Conn, volatile_id: u64) void {
        c.finishNotifies(.{ .handle = volatile_id }, Status.notify_cleanup);
    }

    const Match = union(enum) { path: []const u8, handle: u64 };

    fn finishNotifies(c: *Conn, m: Match, status: u32) void {
        var done: std.ArrayList(Notify) = .empty;
        defer {
            for (done.items) |n| c.gpa.free(n.dir_path);
            done.deinit(c.gpa);
        }
        {
            c.notify_mutex.lockUncancelable(c.srv.io);
            defer c.notify_mutex.unlock(c.srv.io);
            var i: usize = 0;
            while (i < c.notifies.items.len) {
                const n = c.notifies.items[i];
                const hit = switch (m) {
                    .handle => |v| n.volatile_id == v,
                    .path => |p| std.mem.eql(u8, n.dir_path, p) or (n.watch_tree and std.mem.startsWith(u8, p, n.dir_path) and p.len > n.dir_path.len and p[n.dir_path.len] == '/'),
                };
                if (hit) {
                    done.append(c.gpa, n) catch break;
                    _ = c.notifies.swapRemove(i);
                } else i += 1;
            }
        }
        for (done.items) |n| c.sendAsync(n, status) catch {};
    }

    /// Send the final response of an asynchronous CHANGE_NOTIFY.
    fn sendAsync(c: *Conn, n: Notify, status: u32) !void {
        var b = Buf.init(c.gpa);
        defer b.deinit();
        try b.bytes(&proto.protocol_id);
        try b.u16_(64); // StructureSize
        try b.u16_(0); // CreditCharge
        try b.u32_(status);
        try b.u16_(@intFromEnum(Command.change_notify));
        try b.u16_(0); // CreditResponse: credits were granted with the interim
        try b.u32_(proto.Flags.server_to_redir | proto.Flags.async_command);
        try b.u32_(0); // NextCommand
        try b.u64_(n.msg_id);
        try b.u64_(n.async_id);
        try b.u64_(n.session_id);
        try b.zeros(16); // Signature
        try files.notifyBody(&b);
        try c.writeMessage(b.items(), n.session_id, n.sign and !n.encrypt, n.signing_key, if (n.encrypt) n.enc_key else null);
    }

    /// Sign `msg` in place (when `sign`), seal it (when `enc_key` is set),
    /// frame it, and write it to the socket.
    pub fn writeMessage(c: *Conn, msg: []u8, session_id: u64, sign: bool, signing_key: [16]u8, enc_key: ?[16]u8) !void {
        if (sign) {
            const f = wire.get32(msg, 16) | proto.Flags.signed;
            wire.put32(msg, 16, f);
            @memset(msg[48..64], 0);
            const sig = if (c.neg.dialect >= proto.Dialect.smb300)
                crypto.cmacSig(&signing_key, msg)
            else
                crypto.hmacSha256Sig(&signing_key, msg);
            @memcpy(msg[48..64], &sig);
        }
        const io = c.srv.io;
        var frame: [4]u8 = undefined;
        var th: [52]u8 = undefined;
        var sealed: []u8 = &.{};
        defer c.gpa.free(sealed);
        var body: []const u8 = msg;
        if (enc_key) |key| {
            sealed = try c.gpa.alloc(u8, msg.len);
            @memcpy(th[0..4], &proto.transform_id);
            @memset(th[20..36], 0);
            io.random(th[20..32]);
            const gcm = c.neg.cipher == proto.Cipher.aes128_gcm;
            if (!gcm) @memset(th[20 + crypto.ccm_nonce_len .. 32], 0);
            wire.put32(&th, 36, @intCast(msg.len));
            wire.put16(&th, 40, 0);
            wire.put16(&th, 42, 1); // Encrypted
            wire.put64(&th, 44, session_id);
            var tag: [16]u8 = undefined;
            if (gcm)
                Aes128Gcm.encrypt(sealed, &tag, msg, th[20..52], th[20..32].*, key)
            else
                crypto.ccmEncrypt(sealed, &tag, msg, th[20..52], th[20..][0..crypto.ccm_nonce_len], key);
            @memcpy(th[4..20], &tag);
            body = sealed;
        }
        const total = body.len + (if (enc_key != null) th.len else 0);
        if (total > 0xFFFFFF) return error.MessageTooLarge;
        std.mem.writeInt(u32, &frame, @intCast(total), .big);
        c.write_mutex.lockUncancelable(io);
        defer c.write_mutex.unlock(io);
        var wbuf: [4096]u8 = undefined;
        var w = c.stream.writer(io, &wbuf);
        try w.interface.writeAll(&frame);
        if (enc_key != null) try w.interface.writeAll(&th);
        try w.interface.writeAll(body);
        try w.interface.flush();
        _ = c.srv.stats.bytes_out.fetchAdd(total + 4, .monotonic);
    }
};
