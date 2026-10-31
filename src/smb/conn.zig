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
const handshake = @import("handshake.zig");
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
    next_tree_id: u32 = 1,
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
/// framed, signed or sealed write path. The request loop is `serve`;
/// NEGOTIATE and TREE_CONNECT are in handshake.zig; SESSION_SETUP, signature
/// checks, and decryption are still to be written (ARCHITECTURE.md 7.2).
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
    credits: Credits = .{},

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

    const Match = union(enum) {
        path: []const u8,
        handle: u64,
        /// CANCEL: by async ID, or by message ID for a request still synchronous.
        cancel: struct { session_id: u64, is_async: bool, id: u64 },
    };

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
                    .cancel => |k| n.session_id == k.session_id and k.id == if (k.is_async) n.async_id else n.msg_id,
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
        if (sign) signMessage(msg, signing_key);
        try c.writeFrame(msg, session_id, enc_key);
    }

    /// Seal `msg` (one message or a whole compound chain, already signed)
    /// when `enc_key` is set, frame it, and write it to the socket.
    pub fn writeFrame(c: *Conn, msg: []const u8, session_id: u64, enc_key: ?[16]u8) !void {
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

/// Sign one message in place with AES-CMAC and set the signed flag.
pub fn signMessage(msg: []u8, signing_key: [16]u8) void {
    wire.put32(msg, 16, wire.get32(msg, 16) | proto.Flags.signed);
    @memset(msg[48..64], 0);
    const sig = crypto.cmacSig(&signing_key, msg);
    @memcpy(msg[48..64], &sig);
}

// ---------------------------------------------------------------- framing

const hdr = proto.header_size;

/// Read one direct-TCP frame: a big-endian length whose top byte must be
/// zero, then the payload. The caller frees the result.
pub fn readFrame(r: *Io.Reader, gpa: Allocator) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try r.readSliceAll(&len_buf);
    const n = std.mem.readInt(u32, &len_buf, .big);
    if (n > max_frame) return error.FrameTooLarge;
    if (n < 4) return error.Malformed;
    const frame = try gpa.alloc(u8, n);
    errdefer gpa.free(frame);
    try r.readSliceAll(frame);
    return frame;
}

/// The message of a compound chain that starts at `off`, padding included,
/// or null at the end of the frame.
pub fn nextInChain(frame: []const u8, off: usize) !?[]const u8 {
    if (off == frame.len) return null;
    const rest = frame[off..];
    if (rest.len < hdr) return error.Malformed;
    if (!std.mem.eql(u8, rest[0..4], &proto.protocol_id) or wire.get16(rest, 4) != hdr) return error.Malformed;
    const next = wire.get32(rest, 20);
    if (next == 0) return rest;
    if (next % 8 != 0 or next < hdr or next >= rest.len) return error.Malformed;
    return rest[0..next];
}

/// Whether an SMB1 NEGOTIATE offers the `SMB 2.???` dialect string, so the
/// client can be upgraded with the wildcard dialect.
pub fn smb1OffersSmb2(frame: []const u8) bool {
    if (frame.len < 35 or !std.mem.eql(u8, frame[0..4], &proto.smb1_id)) return false;
    if (frame[4] != 0x72 or frame[32] != 0) return false; // NEGOTIATE, WordCount 0
    const count = wire.get16(frame, 33);
    var d = wire.slice(frame, 35, count) catch return false;
    while (d.len > 0) {
        if (d[0] != 0x02) return false; // BufferFormat: dialect
        const end = std.mem.indexOfScalar(u8, d[1..], 0) orelse return false;
        if (std.mem.eql(u8, d[1..][0..end], "SMB 2.???")) return true;
        d = d[end + 2 ..];
    }
    return false;
}

// ---------------------------------------------------------------- credits

/// The message-ID window (MS-SMB2 3.3.1.1): IDs below `low` are spent, IDs
/// from `high` on are not yet granted, and `used` marks spent IDs in between.
pub const Credits = struct {
    pub const window = 8192;
    low: u64 = 0,
    high: u64 = 1,
    used: [window / 64]u64 = @splat(0),

    fn isUsed(cr: *const Credits, id: u64) bool {
        const k = id % window;
        return cr.used[k / 64] & (@as(u64, 1) << @intCast(k % 64)) != 0;
    }

    fn setUsed(cr: *Credits, id: u64, on: bool) void {
        const k = id % window;
        const m = @as(u64, 1) << @intCast(k % 64);
        if (on) cr.used[k / 64] |= m else cr.used[k / 64] &= ~m;
    }

    /// Spend IDs `id` through `id + charge - 1` (a charge of 0 counts as 1).
    /// False when any is outside the window or already spent.
    pub fn consume(cr: *Credits, id: u64, charge: u16) bool {
        const n: u64 = @max(charge, 1);
        if (id < cr.low or id >= cr.high or n > cr.high - id) return false;
        var k = id;
        while (k < id + n) : (k += 1) if (cr.isUsed(k)) return false;
        k = id;
        while (k < id + n) : (k += 1) cr.setUsed(k, true);
        while (cr.low < cr.high and cr.isUsed(cr.low)) : (cr.low += 1) cr.setUsed(cr.low, false);
        return true;
    }

    /// Grant up to `requested` new IDs (at least one), keeping the window
    /// at most `window` wide. Returns the number granted.
    pub fn grant(cr: *Credits, requested: u16) u16 {
        const room = window - (cr.high - cr.low);
        const g = @min(@max(requested, 1), room);
        cr.high += g;
        return @intCast(g);
    }
};

/// The credit charge a request's payload needs (MS-SMB2 3.3.5.2.5): one per
/// 64 KiB.
pub fn requiredCharge(cmd: Command, b: []const u8) u64 {
    const g = struct {
        fn at(x: []const u8, off: usize) u64 {
            return if (x.len >= off + 4) wire.get32(x, off) else 0;
        }
    };
    const size: u64 = switch (cmd) {
        .read, .write, .change_notify => g.at(b, 4),
        .query_info => @max(g.at(b, 4), g.at(b, 12)),
        .query_directory => g.at(b, 28),
        .ioctl => @max(g.at(b, 28), g.at(b, 44)),
        else => 0,
    };
    return if (size == 0) 1 else (size - 1) / 65536 + 1;
}

// ---------------------------------------------------------------- request loop

/// Run the connection until the client leaves or breaks the protocol, then
/// release everything it holds, including the caller's reference.
pub fn serve(c: *Conn) void {
    defer shutdown(c);
    const io = c.srv.io;
    var rbuf: [16 * 1024]u8 = undefined;
    var r = c.stream.reader(io, &rbuf);
    var out = Buf.init(c.gpa);
    defer out.deinit();
    while (true) {
        const frame = readFrame(&r.interface, c.gpa) catch return;
        defer c.gpa.free(frame);
        _ = c.srv.stats.bytes_in.fetchAdd(frame.len + 4, .monotonic);
        out.clear();
        const keep = handleFrame(c, frame, &out) catch |e| {
            c.srv.log(c.id, "smb", "dropped: {s}", .{@errorName(e)});
            return;
        };
        if (out.len() > 0) c.writeFrame(out.items(), 0, null) catch return;
        if (!keep) return;
    }
}

/// Answer one frame into `out` (left empty when there is nothing to send).
/// Returns false when the connection must close after sending.
pub fn handleFrame(c: *Conn, frame: []const u8, out: *Buf) !bool {
    if (frame.len < 4) return error.Malformed;
    if (std.mem.eql(u8, frame[0..4], &proto.transform_id)) {
        // Decryption is not written yet, so encrypted traffic ends the connection.
        return error.EncryptionUnsupported;
    }
    if (std.mem.eql(u8, frame[0..4], &proto.smb1_id)) {
        // Only as the first frame, and only to upgrade to SMB2.
        if (c.neg.dialect != 0 or !smb1OffersSmb2(frame)) return error.Smb1;
        try handshake.wildcardResponse(c, out);
        return true;
    }
    return processChain(c, frame, out);
}

/// What a compound chain carries from one related request to the next.
const Chain = struct {
    first: bool = true,
    session: ?*Session = null,
    tree: ?*Tree = null,
    fid: ?files.FileId = null,
    status: u32 = Status.success,
};

/// A response in `out`, signed with `key` once the chain is complete.
const Span = struct { start: usize, len: usize, key: ?[16]u8 };

const Result = struct {
    status: u32,
    /// The session whose key signs the response.
    session: ?*Session = null,
    notify: ?Notify = null,
    disconnect: bool = false,
};

/// Walk a compound chain, answering each request into `out`. Returns false
/// when the connection must close after sending.
pub fn processChain(c: *Conn, frame: []const u8, out: *Buf) !bool {
    var spans: std.ArrayList(Span) = .empty;
    defer spans.deinit(c.gpa);
    var one = Buf.init(c.gpa);
    defer one.deinit();
    var chain: Chain = .{};
    var keep = true;
    var off: usize = 0;
    while (try nextInChain(frame, off)) |msg| : (off += msg.len) {
        _ = c.srv.stats.requests.fetchAdd(1, .monotonic);
        const cmd: Command = @enumFromInt(wire.get16(msg, 12));
        const flags = wire.get32(msg, 16);
        if (flags & proto.Flags.server_to_redir != 0) return error.Malformed;
        if (cmd == .cancel) {
            cancel(c, msg);
            continue;
        }
        // NEGOTIATE comes first, alone in its frame, and only once.
        const negotiated = c.neg.dialect == proto.Dialect.smb311;
        if (cmd == .negotiate) {
            if (negotiated) return error.Renegotiate;
            if (msg.len != frame.len) return error.Malformed;
        } else if (!negotiated) return error.NotNegotiated;
        if (!c.credits.consume(wire.get64(msg, 24), wire.get16(msg, 6))) return error.BadMessageId;
        const granted = c.credits.grant(wire.get16(msg, 18));

        one.clear();
        try responseHeader(&one, msg, granted);
        var res = if (cmd == .negotiate) blk: {
            const n = try handshake.negotiate(c, msg, &one);
            break :blk Result{ .status = n.status, .disconnect = n.disconnect };
        } else handle(c, cmd, msg, &chain, &one) catch |e| Result{ .status = vfs.status(e) };
        if (res.notify) |n| {
            if (c.queueNotify(n)) |async_id| {
                wire.put32(one.items(), 16, wire.get32(one.items(), 16) | proto.Flags.async_command);
                wire.put64(one.items(), 32, async_id);
            } else |_| {
                c.gpa.free(n.dir_path);
                res.status = Status.insufficient_resources;
                one.list.shrinkRetainingCapacity(hdr);
            }
        }
        if (res.status != Status.success and res.status != Status.pending and one.len() == hdr) try files.errorBody(&one);
        wire.put32(one.items(), 8, res.status);
        if (cmd == .negotiate and res.status == Status.success) handshake.hashResponse(c, one.items());
        chain.status = res.status;
        chain.first = false;
        if (res.disconnect) keep = false;

        try out.alignTo(8);
        const key: ?[16]u8 = if (res.session) |s| (if (s.sign) s.signing_key else null) else null;
        try spans.append(c.gpa, .{ .start = out.len(), .len = one.len(), .key = key });
        try out.bytes(one.items());
        if (!keep) break;
    }
    // Link the responses, padding each but the last to 8 bytes, then sign.
    const all = out.items();
    for (spans.items, 0..) |*sp, i| {
        if (i + 1 < spans.items.len) {
            sp.len = spans.items[i + 1].start - sp.start;
            wire.put32(all, sp.start + 20, @intCast(sp.len));
        }
    }
    for (spans.items) |sp| if (sp.key) |k| signMessage(all[sp.start..][0..sp.len], k);
    return keep;
}

/// A response header for `req`: same command, message ID, tree, and session.
fn responseHeader(out: *Buf, req: []const u8, credits: u16) !void {
    try out.bytes(&proto.protocol_id);
    try out.u16_(hdr);
    try out.u16_(wire.get16(req, 6)); // CreditCharge
    try out.u32_(Status.success); // patched
    try out.u16_(wire.get16(req, 12));
    try out.u16_(credits);
    const keep_flags = proto.Flags.related_operations | proto.Flags.priority_mask;
    try out.u32_(proto.Flags.server_to_redir | (wire.get32(req, 16) & keep_flags));
    try out.u32_(0); // NextCommand, patched
    try out.bytes(req[24..48]); // MessageId, Reserved, TreeId, SessionId
    try out.zeros(16); // Signature
}

/// Signature verification is not written yet, so it fails closed: requests
/// on signing sessions, and requests flagged signed, are refused.
fn signatureValid(s: *const Session, msg: []const u8) bool {
    _ = s;
    _ = msg;
    return false;
}

fn handle(c: *Conn, cmd: Command, msg: []const u8, chain: *Chain, out: *Buf) !Result {
    const related = wire.get32(msg, 16) & proto.Flags.related_operations != 0;
    if (related and chain.first) return .{ .status = Status.invalid_parameter };
    if (related and chain.status != Status.success) return .{ .status = chain.status };
    if (requiredCharge(cmd, msg[hdr..]) > @max(wire.get16(msg, 6), 1)) return .{ .status = Status.invalid_parameter };

    switch (cmd) {
        .echo => {
            try out.u16_(4);
            try out.u16_(0);
            return .{ .status = Status.success };
        },
        // SESSION_SETUP is not written yet.
        .session_setup => return .{ .status = Status.not_supported },
        else => {},
    }

    const s = if (related) chain.session orelse return .{ .status = Status.invalid_parameter } else c.sessions.get(wire.get64(msg, 40)) orelse
        return .{ .status = Status.user_session_deleted };
    chain.session = s;
    if (s.state != .valid) return .{ .status = Status.user_session_deleted };
    const flagged = wire.get32(msg, 16) & proto.Flags.signed != 0;
    if ((s.sign or flagged) and !signatureValid(s, msg)) return .{ .status = Status.access_denied };
    // A plain frame on an encrypting session (decryption is not written, so
    // every frame here is plain).
    if (s.encrypt) return .{ .status = Status.access_denied, .session = s };

    if (cmd == .logoff) {
        logoff(c, s);
        chain.session = null;
        try out.u16_(4);
        try out.u16_(0);
        return .{ .status = Status.success };
    }

    if (cmd == .tree_connect) {
        const r = try handshake.treeConnect(c, s, msg, out);
        if (r.tree) |t| chain.tree = t;
        return .{ .status = r.status, .session = s };
    }

    const t = if (related) chain.tree orelse return .{ .status = Status.invalid_parameter, .session = s } else s.trees.get(wire.get32(msg, 36)) orelse
        return .{ .status = Status.network_name_deleted, .session = s };
    chain.tree = t;

    if (cmd == .tree_disconnect) {
        disconnectTree(c, s, t);
        chain.tree = null;
        try out.u16_(4);
        try out.u16_(0);
        return .{ .status = Status.success, .session = s };
    }
    if (!files.handles(cmd)) return .{ .status = Status.not_supported, .session = s };

    var ctx: files.Ctx = .{ .conn = c, .session = s, .tree = t, .related = if (related) chain.fid else null };
    const r = files.dispatch(&ctx, cmd, msg, out);
    if (r.fid) |f| chain.fid = f;
    return .{ .status = r.status, .session = s, .notify = r.notify, .disconnect = r.disconnect };
}

/// CANCEL: complete the matching pending CHANGE_NOTIFY with STATUS_CANCELLED.
/// CANCEL has no response of its own, so anything unmatched is ignored.
fn cancel(c: *Conn, msg: []const u8) void {
    const sid = wire.get64(msg, 40);
    const s = c.sessions.get(sid) orelse return;
    const flagged = wire.get32(msg, 16) & proto.Flags.signed != 0;
    if ((s.sign or flagged) and !signatureValid(s, msg)) return;
    const is_async = wire.get32(msg, 16) & proto.Flags.async_command != 0;
    c.finishNotifies(.{ .cancel = .{
        .session_id = sid,
        .is_async = is_async,
        .id = if (is_async) wire.get64(msg, 32) else wire.get64(msg, 24),
    } }, Status.cancelled);
}

/// LOGOFF: close the session's handles and trees, then forget it.
pub fn logoff(c: *Conn, s: *Session) void {
    files.closeAll(c, s.id, null);
    _ = c.sessions.remove(s.id);
    freeSession(c.gpa, s);
}

/// TREE_DISCONNECT: close the tree's handles, then forget it.
pub fn disconnectTree(c: *Conn, s: *Session, t: *Tree) void {
    files.closeAll(c, s.id, t);
    _ = s.trees.remove(t.id);
    freeTree(c.gpa, t);
}

fn freeTree(gpa: Allocator, t: *Tree) void {
    gpa.free(t.share);
    gpa.free(t.root);
    gpa.destroy(t);
}

fn freeSession(gpa: Allocator, s: *Session) void {
    var it = s.trees.valueIterator();
    while (it.next()) |t| freeTree(gpa, t.*);
    s.trees.deinit(gpa);
    if (s.auth) |*a| a.deinit();
    gpa.free(s.mech_types);
    gpa.free(s.user);
    gpa.free(s.domain);
    gpa.free(s.workstation);
    std.crypto.secureZero(u8, &s.session_key);
    std.crypto.secureZero(u8, &s.signing_key);
    std.crypto.secureZero(u8, &s.dec_key);
    std.crypto.secureZero(u8, &s.enc_key);
    gpa.destroy(s);
}

/// Release everything the connection holds and drop the loop's reference.
fn shutdown(c: *Conn) void {
    c.closed.store(true, .release);
    files.closeAll(c, null, null);
    var it = c.sessions.valueIterator();
    while (it.next()) |s| freeSession(c.gpa, s.*);
    c.sessions.deinit(c.gpa);
    c.opens.map.deinit(c.gpa);
    c.srv.removeConn(c);
    c.unref();
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "credits: window, reuse, and multi-credit charges" {
    var cr: Credits = .{};
    try testing.expect(!cr.consume(1, 1)); // not granted yet
    try testing.expect(cr.consume(0, 0));
    try testing.expect(!cr.consume(0, 1)); // reused
    try testing.expectEqual(@as(u16, 10), cr.grant(10));
    try testing.expect(cr.consume(3, 4)); // 3..6, out of order
    try testing.expect(!cr.consume(5, 1));
    try testing.expectEqual(@as(u64, 1), cr.low);
    try testing.expect(cr.consume(1, 2));
    try testing.expectEqual(@as(u64, 7), cr.low);
    try testing.expect(!cr.consume(9, 3)); // past high (11)
    try testing.expect(cr.consume(7, 4));
    try testing.expectEqual(@as(u16, 1), cr.grant(0));
    // The window never exceeds its width.
    try testing.expectEqual(@as(u16, Credits.window - 1), cr.grant(65535));
    try testing.expectEqual(@as(u16, 0), cr.grant(1));
}

test "requiredCharge counts 64 KiB units" {
    var b: [48]u8 = @splat(0);
    try testing.expectEqual(@as(u64, 1), requiredCharge(.read, &b));
    wire.put32(&b, 4, 65536);
    try testing.expectEqual(@as(u64, 1), requiredCharge(.read, &b));
    wire.put32(&b, 4, 65537);
    try testing.expectEqual(@as(u64, 2), requiredCharge(.write, &b));
    wire.put32(&b, 44, 1 << 20);
    try testing.expectEqual(@as(u64, 16), requiredCharge(.ioctl, &b));
    try testing.expectEqual(@as(u64, 1), requiredCharge(.echo, b[0..2]));
}

test "readFrame enforces the length limit" {
    var ok = [_]u8{ 0, 0, 0, 4, 'a', 'b', 'c', 'd' };
    var r: Io.Reader = .fixed(&ok);
    const f = try readFrame(&r, testing.allocator);
    defer testing.allocator.free(f);
    try testing.expectEqualStrings("abcd", f);
    var big = [_]u8{ 1, 0, 0, 0 };
    r = .fixed(&big);
    try testing.expectError(error.FrameTooLarge, readFrame(&r, testing.allocator));
    var short = [_]u8{ 0, 0, 0, 8, 1, 2 };
    r = .fixed(&short);
    try testing.expectError(error.EndOfStream, readFrame(&r, testing.allocator));
}

pub fn testHeader(b: []u8, cmd: Command, msg_id: u64, next: u32, flags: u32) void {
    @memset(b[0..hdr], 0);
    @memcpy(b[0..4], &proto.protocol_id);
    wire.put16(b, 4, hdr);
    wire.put16(b, 12, @intFromEnum(cmd));
    wire.put16(b, 18, 1);
    wire.put32(b, 16, flags);
    wire.put32(b, 20, next);
    wire.put64(b, 24, msg_id);
}

test "nextInChain walks and rejects bad chains" {
    var f: [72 + 68]u8 = @splat(0);
    testHeader(f[0..], .echo, 0, 72, 0);
    testHeader(f[72..], .echo, 1, 0, 0);
    const a = (try nextInChain(&f, 0)).?;
    try testing.expectEqual(@as(usize, 72), a.len);
    const b = (try nextInChain(&f, 72)).?;
    try testing.expectEqual(@as(usize, 68), b.len);
    try testing.expect(try nextInChain(&f, f.len) == null);
    wire.put32(&f, 20, 70); // misaligned
    try testing.expectError(error.Malformed, nextInChain(&f, 0));
    wire.put32(&f, 20, f.len); // points past the end
    try testing.expectError(error.Malformed, nextInChain(&f, 0));
    f[0] = 0xFD;
    try testing.expectError(error.Malformed, nextInChain(&f, 0));
}

test "smb1OffersSmb2" {
    var f: [35 + 23]u8 = @splat(0);
    @memcpy(f[0..4], &proto.smb1_id);
    f[4] = 0x72;
    const d = "\x02NT LM 0.12\x00\x02SMB 2.???\x00";
    wire.put16(&f, 33, d.len);
    @memcpy(f[35..], d);
    try testing.expect(smb1OffersSmb2(&f));
    f[35 + 13] = 'X';
    try testing.expect(!smb1OffersSmb2(&f));
    wire.put16(&f, 33, 200); // ByteCount past the end
    try testing.expect(!smb1OffersSmb2(&f));
}

pub const TestConn = struct {
    db: db_mod.Db,
    srv: Server,
    conn: *Conn,

    pub fn init(t: *TestConn) !void {
        const gpa = testing.allocator;
        t.db = try db_mod.Db.open(testing.io, ":memory:");
        t.srv = .{
            .gpa = gpa,
            .io = testing.io,
            .db = &t.db,
            .guid = @splat(0),
            .start_ms = 0,
            .smb_port = 445,
            .cfg = .{ .server_name = &.{}, .workgroup = &.{}, .signing_required = false, .encrypt = false },
        };
        t.conn = try gpa.create(Conn);
        t.conn.* = .{ .gpa = gpa, .srv = &t.srv, .id = 1, .stream = undefined };
        t.conn.neg.dialect = proto.Dialect.smb311;
    }

    pub fn deinit(t: *TestConn) void {
        const gpa = testing.allocator;
        const c = t.conn;
        files.closeAll(c, null, null);
        var it = c.sessions.valueIterator();
        while (it.next()) |s| freeSession(gpa, s.*);
        c.sessions.deinit(gpa);
        c.opens.map.deinit(gpa);
        for (c.notifies.items) |n| gpa.free(n.dir_path);
        c.notifies.deinit(gpa);
        gpa.destroy(c);
        t.srv.nodes.deinit(gpa);
        t.db.close();
    }

    /// A valid, unsigned session 7 with tree 3 on `IPC$`.
    pub fn addSession(t: *TestConn, sign: bool) !*Session {
        const gpa = testing.allocator;
        const s = try gpa.create(Session);
        s.* = .{ .id = 7, .state = .valid, .sign = sign, .created_ms = 0 };
        const tree = try gpa.create(Tree);
        tree.* = .{
            .id = 3,
            .session_id = 7,
            .share = try gpa.dupe(u8, "IPC$"),
            .root = try gpa.dupeSentinel(u8, "/", 0),
            .ipc = true,
            .read_only = true,
            .connected_ms = 0,
        };
        try s.trees.put(gpa, 3, tree);
        try t.conn.sessions.put(gpa, 7, s);
        return s;
    }
};

pub fn statusAt(out: *const Buf, off: usize) u32 {
    return wire.get32(out.items(), off + 8);
}

test "echo chain: credits, linking, and padding" {
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    var f: [72 + 68]u8 = @splat(0);
    testHeader(f[0..], .echo, 0, 72, 0);
    wire.put16(&f, 18, 5); // request 5 credits
    wire.put16(&f, hdr, 4);
    testHeader(f[72..], .echo, 1, 0, 0);
    wire.put16(&f, 72 + hdr, 4);
    var out = Buf.init(testing.allocator);
    defer out.deinit();
    try testing.expect(try processChain(t.conn, &f, &out));
    const o = out.items();
    try testing.expectEqual(@as(usize, 72 + 68), o.len);
    try testing.expectEqual(@as(u32, 72), wire.get32(o, 20));
    try testing.expectEqual(@as(u16, 5), wire.get16(o, 14));
    try testing.expectEqual(@as(u32, 0), wire.get32(o, 72 + 20));
    try testing.expectEqual(@as(u64, 1), wire.get64(o, 72 + 24));
    try testing.expect(wire.get32(o, 16) & proto.Flags.server_to_redir != 0);
    // Replaying message 0 breaks the connection.
    out.clear();
    wire.put32(&f, 20, 0);
    try testing.expectError(error.BadMessageId, processChain(t.conn, f[0..68], &out));
}

test "sessions, trees, logoff, and the fail-closed signature check" {
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    var out = Buf.init(testing.allocator);
    defer out.deinit();
    var m: [hdr + 4]u8 = @splat(0);

    // No session yet.
    testHeader(&m, .tree_disconnect, 0, 0, 0);
    wire.put64(&m, 40, 7);
    _ = try processChain(t.conn, &m, &out);
    try testing.expectEqual(Status.user_session_deleted, statusAt(&out, 0));

    // A signing session is refused until verification exists.
    const s = try t.addSession(true);
    out.clear();
    testHeader(&m, .tree_disconnect, 1, 0, 0);
    wire.put64(&m, 40, 7);
    wire.put32(&m, 36, 3);
    _ = try processChain(t.conn, &m, &out);
    try testing.expectEqual(Status.access_denied, statusAt(&out, 0));

    s.sign = false;
    out.clear();
    testHeader(&m, .tree_disconnect, 2, 0, 0);
    wire.put64(&m, 40, 7);
    wire.put32(&m, 36, 9);
    _ = try processChain(t.conn, &m, &out);
    try testing.expectEqual(Status.network_name_deleted, statusAt(&out, 0));

    out.clear();
    testHeader(&m, .tree_disconnect, 3, 0, 0);
    wire.put64(&m, 40, 7);
    wire.put32(&m, 36, 3);
    _ = try processChain(t.conn, &m, &out);
    try testing.expectEqual(Status.success, statusAt(&out, 0));
    try testing.expectEqual(@as(u32, 0), s.trees.count());

    out.clear();
    testHeader(&m, .logoff, 4, 0, 0);
    wire.put64(&m, 40, 7);
    _ = try processChain(t.conn, &m, &out);
    try testing.expectEqual(Status.success, statusAt(&out, 0));
    try testing.expectEqual(@as(u32, 0), t.conn.sessions.count());

    // SESSION_SETUP answers NOT_SUPPORTED for now.
    out.clear();
    testHeader(&m, .session_setup, 5, 0, 0);
    _ = try processChain(t.conn, &m, &out);
    try testing.expectEqual(Status.not_supported, statusAt(&out, 0));

    // A second NEGOTIATE ends the connection.
    out.clear();
    testHeader(&m, .negotiate, 6, 0, 0);
    try testing.expectError(error.Renegotiate, processChain(t.conn, &m, &out));
}

test "related requests inherit the session and stop after a failure" {
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    _ = try t.addSession(false);
    var out = Buf.init(testing.allocator);
    defer out.deinit();
    // A related first request is invalid.
    var m: [hdr + 4]u8 = @splat(0);
    testHeader(&m, .echo, 0, 0, proto.Flags.related_operations);
    _ = try processChain(t.conn, &m, &out);
    try testing.expectEqual(Status.invalid_parameter, statusAt(&out, 0));

    // A failed TREE_DISCONNECT (unknown tree) fails the related LOGOFF too.
    var f: [72 + 68]u8 = @splat(0);
    testHeader(f[0..], .tree_disconnect, 1, 72, 0);
    wire.put64(&f, 40, 7);
    wire.put32(&f, 36, 9);
    testHeader(f[72..], .logoff, 2, 0, proto.Flags.related_operations);
    wire.put16(&f, 18, 1);
    t.conn.credits.high = 3;
    out.clear();
    _ = try processChain(t.conn, &f, &out);
    try testing.expectEqual(Status.network_name_deleted, statusAt(&out, 0));
    const second = wire.get32(out.items(), 20); // the error body pads the first to 80
    try testing.expectEqual(@as(u32, 80), second);
    try testing.expectEqual(Status.network_name_deleted, statusAt(&out, second));
    try testing.expectEqual(@as(u32, 1), t.conn.sessions.count());
}

test "fuzz: frames, compound chains, and credits" {
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();

    var echo2: [72 + 68]u8 = @splat(0);
    testHeader(echo2[0..], .echo, 0, 72, 0);
    wire.put16(&echo2, hdr, 4);
    testHeader(echo2[72..], .echo, 1, 0, proto.Flags.related_operations);
    wire.put16(&echo2, 72 + hdr, 4);
    var td_logoff: [72 + 68]u8 = @splat(0);
    testHeader(td_logoff[0..], .tree_disconnect, 0, 72, 0);
    wire.put64(&td_logoff, 40, 7);
    wire.put32(&td_logoff, 36, 3);
    testHeader(td_logoff[72..], .logoff, 1, 0, proto.Flags.related_operations);
    var cancel_msg: [hdr + 4]u8 = @splat(0);
    testHeader(&cancel_msg, .cancel, 0, 0, proto.Flags.async_command);
    wire.put64(&cancel_msg, 40, 7);
    var smb1: [35 + 11]u8 = @splat(0);
    @memcpy(smb1[0..5], "\xFFSMB\x72");
    wire.put16(&smb1, 33, 11);
    @memcpy(smb1[35..], "\x02SMB 2.???\x00");
    const seeds = [_][]const u8{ &echo2, &td_logoff, &cancel_msg, &smb1 };

    try @import("../shared/fuzz.zig").run(&t, struct {
        fn one(tc: *TestConn, in: []const u8) !void {
            if (tc.conn.sessions.count() == 0) _ = try tc.addSession(false);
            tc.conn.credits = .{ .high = Credits.window };
            var out = Buf.init(testing.allocator);
            defer out.deinit();
            _ = handleFrame(tc.conn, in, &out) catch return;
        }
    }.one, &seeds);
}
