//! NEGOTIATE (SMB 3.1.1 only, plus the SMB1 upgrade) and TREE_CONNECT
//! (ARCHITECTURE.md sections 7.3 and 7.5). SESSION_SETUP is still to come.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha512 = std.crypto.hash.sha2.Sha512;

const proto = @import("proto.zig");
const Status = proto.Status;
const wire = @import("../shared/wire.zig");
const Buf = wire.Buf;
const spnego = @import("auth/spnego.zig");
const vfs = @import("vfs.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;
const Session = conn_mod.Session;
const Tree = conn_mod.Tree;

const hdr = proto.header_size;

/// SHA-512, the only preauthentication hash (MS-SMB2 2.2.3.1.1).
const sha512_id: u16 = 0x0001;
/// Trees one session may hold.
pub const max_trees = 256;
/// Longest share component of a TREE_CONNECT path (MS-SMB2 2.2.9).
const max_share_name = 80;

pub const Outcome = struct {
    status: u32,
    /// Close the connection after the reply.
    disconnect: bool = false,
};

/// Current time as a Windows FILETIME (100 ns units since 1601).
fn ntNow(c: *Conn) u64 {
    const ns = std.Io.Clock.real.now(c.srv.io).nanoseconds;
    return @intCast(@divTrunc(ns, 100) + 116444736000000000);
}

fn signingRequired(c: *Conn) bool {
    c.srv.lock();
    defer c.srv.unlock();
    return c.srv.cfg.signing_required;
}

fn encryptRequired(c: *Conn) bool {
    c.srv.lock();
    defer c.srv.unlock();
    return c.srv.cfg.encrypt;
}

/// The fixed NEGOTIATE response body and the SPNEGO NegTokenInit, after the
/// 64-byte header already in `out`. Returns the position of
/// NegotiateContextOffset, for the caller to patch.
fn negotiateBody(c: *Conn, out: *Buf, dialect: u16, ctx_count: u16) !usize {
    var mode: u16 = proto.SecurityMode.signing_enabled;
    if (signingRequired(c)) mode |= proto.SecurityMode.signing_required;
    try out.u16_(65);
    try out.u16_(mode);
    try out.u16_(dialect);
    try out.u16_(ctx_count);
    try out.bytes(&c.srv.guid);
    try out.u32_(proto.Cap.large_mtu);
    try out.u32_(conn_mod.max_io_size); // MaxTransactSize
    try out.u32_(conn_mod.max_io_size); // MaxReadSize
    try out.u32_(conn_mod.max_io_size); // MaxWriteSize
    try out.u64_(ntNow(c));
    try out.u64_(0); // ServerStartTime
    const token = try spnego.negTokenInit(c.gpa);
    defer c.gpa.free(token);
    try out.u16_(hdr + 64); // SecurityBufferOffset
    try out.u16_(@intCast(token.len));
    const ctx_pos = out.len();
    try out.u32_(0); // NegotiateContextOffset
    try out.bytes(token);
    return ctx_pos;
}

/// The SMB2 NEGOTIATE response, header included, that answers an SMB1
/// NEGOTIATE offering `SMB 2.???` (MS-SMB2 3.3.5.3.1). The client then sends
/// an SMB2 NEGOTIATE with message ID 1.
pub fn wildcardResponse(c: *Conn, out: *Buf) !void {
    _ = c.credits.consume(0, 1);
    const credits = c.credits.grant(1);
    try out.bytes(&proto.protocol_id);
    try out.u16_(hdr);
    try out.u16_(0); // CreditCharge
    try out.u32_(Status.success);
    try out.u16_(@intFromEnum(proto.Command.negotiate));
    try out.u16_(credits);
    try out.u32_(proto.Flags.server_to_redir);
    try out.zeros(4 + 8 + 4 + 4 + 8 + 16); // NextCommand through Signature
    _ = try negotiateBody(c, out, proto.Dialect.wildcard, 0);
    c.neg.dialect = proto.Dialect.wildcard;
}

fn putContext(out: *Buf, ctx_type: u16, data: []const u8) !void {
    try out.alignTo(8);
    try out.u16_(ctx_type);
    try out.u16_(@intCast(data.len));
    try out.u32_(0);
    try out.bytes(data);
}

fn hasId(list: []const u8, id: u16) bool {
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) if (wire.get16(list, i) == id) return true;
    return false;
}

/// SMB2 NEGOTIATE (MS-SMB2 3.3.5.4) for a request that is a whole frame.
/// On success the connection's dialect, cipher, and signing algorithm are
/// set, and its preauthentication hash covers the request; the caller hashes
/// the response with `hashResponse` once it is complete.
pub fn negotiate(c: *Conn, msg: []const u8, out: *Buf) !Outcome {
    const b = msg[hdr..];
    if (b.len < 36 or wire.get16(b, 0) != 36) return .{ .status = Status.invalid_parameter };
    const count = wire.get16(b, 2);
    if (count == 0) return .{ .status = Status.invalid_parameter };
    const dialects = wire.slice(b, 36, @as(usize, count) * 2) catch return .{ .status = Status.invalid_parameter };
    if (!hasId(dialects, proto.Dialect.smb311)) return .{ .status = Status.not_supported, .disconnect = true };

    var preauth_seen = false;
    var preauth_ok = false;
    var cipher: ?u16 = null;
    var signing: ?u16 = null;
    var compression_seen = false;
    var rdma_seen = false;
    var pos: usize = wire.get32(b, 28);
    for (0..wire.get16(b, 32)) |_| {
        pos = std.mem.alignForward(usize, pos, 8);
        const head = wire.slice(msg, pos, 8) catch return .{ .status = Status.invalid_parameter };
        const d = wire.slice(msg, pos + 8, wire.get16(head, 2)) catch return .{ .status = Status.invalid_parameter };
        pos += 8 + d.len;
        switch (wire.get16(head, 0)) {
            proto.NegCtx.preauth_integrity => {
                if (preauth_seen or d.len < 6) return .{ .status = Status.invalid_parameter };
                preauth_seen = true;
                const algs = wire.slice(d, 4, @as(usize, wire.get16(d, 0)) * 2) catch return .{ .status = Status.invalid_parameter };
                _ = wire.slice(d, 4 + algs.len, wire.get16(d, 2)) catch return .{ .status = Status.invalid_parameter }; // Salt
                preauth_ok = hasId(algs, sha512_id);
            },
            proto.NegCtx.encryption => {
                if (cipher != null or d.len < 4) return .{ .status = Status.invalid_parameter };
                const ids = wire.slice(d, 2, @as(usize, wire.get16(d, 0)) * 2) catch return .{ .status = Status.invalid_parameter };
                cipher = if (hasId(ids, proto.Cipher.aes128_gcm))
                    proto.Cipher.aes128_gcm
                else if (hasId(ids, proto.Cipher.aes128_ccm))
                    proto.Cipher.aes128_ccm
                else
                    0;
            },
            proto.NegCtx.signing => {
                if (signing != null or d.len < 4 or wire.get16(d, 0) == 0) return .{ .status = Status.invalid_parameter };
                _ = wire.slice(d, 2, @as(usize, wire.get16(d, 0)) * 2) catch return .{ .status = Status.invalid_parameter };
                // AES-CMAC is the only algorithm, and the default without overlap.
                signing = proto.SigningAlg.aes_cmac;
            },
            proto.NegCtx.compression => {
                if (compression_seen) return .{ .status = Status.invalid_parameter };
                compression_seen = true;
            },
            proto.NegCtx.rdma_transform => {
                if (rdma_seen) return .{ .status = Status.invalid_parameter };
                rdma_seen = true;
            },
            else => {},
        }
    }
    if (!preauth_seen) return .{ .status = Status.invalid_parameter };
    if (!preauth_ok) return .{ .status = Status.no_preauth_integrity_hash_overlap };

    var ctx_count: u16 = 1;
    if (cipher != null) ctx_count += 1;
    if (signing != null) ctx_count += 1;
    const ctx_pos = try negotiateBody(c, out, proto.Dialect.smb311, ctx_count);
    try out.alignTo(8);
    out.set32(ctx_pos, @intCast(out.len()));
    var pre: [4 + 2 + 32]u8 = undefined;
    wire.put16(&pre, 0, 1); // HashAlgorithmCount
    wire.put16(&pre, 2, 32); // SaltLength
    wire.put16(&pre, 4, sha512_id);
    c.srv.io.random(pre[6..]);
    try putContext(out, proto.NegCtx.preauth_integrity, &pre);
    if (cipher) |id| {
        var e: [4]u8 = undefined;
        wire.put16(&e, 0, 1);
        wire.put16(&e, 2, id);
        try putContext(out, proto.NegCtx.encryption, &e);
    }
    if (signing) |id| {
        var s: [4]u8 = undefined;
        wire.put16(&s, 0, 1);
        wire.put16(&s, 2, id);
        try putContext(out, proto.NegCtx.signing, &s);
    }

    c.neg = .{
        .dialect = proto.Dialect.smb311,
        .cipher = cipher orelse 0,
        .signing_alg = proto.SigningAlg.aes_cmac,
        .signing_required = wire.get16(out.items(), hdr + 2) & proto.SecurityMode.signing_required != 0,
        .client_guid = b[12..28].*,
        .client_caps = wire.get32(b, 8),
        .client_security_mode = wire.get16(b, 4),
    };
    var h = Sha512.init(.{});
    h.update(&c.neg.preauth);
    h.update(msg);
    h.final(&c.neg.preauth);
    return .{ .status = Status.success };
}

/// Fold the finished NEGOTIATE response into the connection's
/// preauthentication hash.
pub fn hashResponse(c: *Conn, response: []const u8) void {
    var h = Sha512.init(.{});
    h.update(&c.neg.preauth);
    h.update(response);
    h.final(&c.neg.preauth);
}

pub const TreeOutcome = struct {
    status: u32,
    tree: ?*Tree = null,
};

/// SMB2 TREE_CONNECT (MS-SMB2 3.3.5.7) on a valid session. The response
/// header's TreeId is patched to the new tree's.
pub fn treeConnect(c: *Conn, s: *Session, msg: []const u8, out: *Buf) !TreeOutcome {
    const gpa = c.gpa;
    const b = msg[hdr..];
    if (b.len < 8 or wire.get16(b, 0) != 9) return .{ .status = Status.invalid_parameter };
    // PathOffset counts from the header with or without the request extension.
    const raw = wire.slice(msg, wire.get16(b, 4), wire.get16(b, 6)) catch return .{ .status = Status.invalid_parameter };
    const path = try wire.utf16ToUtf8(gpa, raw);
    defer gpa.free(path);
    const name = shareName(path) orelse return .{ .status = Status.bad_network_name };
    if (s.trees.count() >= max_trees) return .{ .status = Status.insufficient_resources };

    const ipc = vfs.eqlFold(name, "IPC$");
    var share_name: []u8 = undefined;
    var root: [:0]u8 = undefined;
    var read_only = true;
    if (ipc) {
        share_name = try gpa.dupe(u8, "IPC$");
        errdefer gpa.free(share_name);
        root = try gpa.dupeSentinel(u8, "", 0);
    } else {
        // An anonymous session cannot sign, so with signing required it
        // reaches only IPC$.
        if (s.anonymous and signingRequired(c)) return .{ .status = Status.access_denied };
        const shares = try c.srv.db.listShares(gpa);
        defer {
            for (shares) |sh| sh.free(gpa);
            gpa.free(shares);
        }
        const sh = for (shares) |sh| {
            if (vfs.eqlFold(sh.name, name)) break sh;
        } else return .{ .status = Status.bad_network_name };
        if (s.anonymous and !sh.guest_ok) return .{ .status = Status.access_denied };
        const host = try gpa.dupeSentinel(u8, sh.path, 0);
        defer gpa.free(host);
        root = vfs.realpath(gpa, host) catch |e| {
            c.srv.log(c.id, "tree", "share {s}: path {s} unavailable: {s}", .{ sh.name, sh.path, @errorName(e) });
            return .{ .status = Status.bad_network_name };
        };
        errdefer gpa.free(root);
        const info = vfs.statPath(root) catch return .{ .status = Status.bad_network_name };
        if (!info.isDir()) return .{ .status = Status.bad_network_name };
        share_name = try gpa.dupe(u8, sh.name);
        read_only = sh.read_only;
    }
    errdefer gpa.free(root);
    errdefer gpa.free(share_name);

    const id = nextTreeId(s);
    const t = try gpa.create(Tree);
    errdefer gpa.destroy(t);
    t.* = .{
        .id = id,
        .session_id = s.id,
        .share = share_name,
        .root = root,
        .ipc = ipc,
        .read_only = read_only,
        .connected_ms = c.srv.nowMs(),
    };
    try s.trees.put(gpa, id, t);

    var flags: u32 = proto.ShareFlags.no_caching;
    if (s.encrypt or encryptRequired(c)) flags |= proto.ShareFlags.encrypt_data;
    try out.u16_(16);
    try out.u8_(if (ipc) proto.ShareType.pipe else proto.ShareType.disk);
    try out.u8_(0);
    try out.u32_(flags);
    try out.u32_(0); // Capabilities
    try out.u32_(t.maxAccess());
    out.set32(36, id);
    c.srv.log(c.id, "tree", "{s} connected to {s}", .{ s.user, share_name });
    return .{ .status = Status.success, .tree = t };
}

/// The share component of `\\server\share`, or null when malformed.
pub fn shareName(path: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, "\\\\")) return null;
    const rest = path[2..];
    const sep = std.mem.indexOfScalar(u8, rest, '\\') orelse return null;
    if (sep == 0) return null;
    const name = rest[sep + 1 ..];
    if (name.len == 0 or name.len > max_share_name) return null;
    if (std.mem.indexOfAny(u8, name, "\\/:*?\"<>|") != null) return null;
    for (name) |ch| if (ch < 0x20) return null;
    return name;
}

fn nextTreeId(s: *Session) u32 {
    while (true) {
        const id = s.next_tree_id;
        s.next_tree_id +%= 1;
        if (id == 0 or id == std.math.maxInt(u32) or s.trees.contains(id)) continue;
        return id;
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "shareName" {
    try testing.expectEqualStrings("data", shareName("\\\\hal9000\\data").?);
    try testing.expectEqualStrings("IPC$", shareName("\\\\10.0.0.1\\IPC$").?);
    try testing.expect(shareName("\\\\hal9000") == null);
    try testing.expect(shareName("\\\\\\data") == null);
    try testing.expect(shareName("\\\\hal9000\\") == null);
    try testing.expect(shareName("\\\\hal9000\\a\\b") == null);
    try testing.expect(shareName("hal9000\\data") == null);
    try testing.expect(shareName("\\\\hal9000\\da:ta") == null);
}

const TestConn = conn_mod.TestConn;

/// A NEGOTIATE request offering `dialects`, with a SHA-512 preauth context
/// (unless `preauth_alg` is null), and `ciphers` and `signing` contexts when
/// non-empty.
fn negotiateRequest(gpa: Allocator, msg_id: u64, dialects: []const u16, preauth_alg: ?u16, ciphers: []const u16, signing: []const u16) ![]u8 {
    var b = Buf.init(gpa);
    errdefer b.deinit();
    try b.zeros(hdr);
    conn_mod.testHeader(b.items(), .negotiate, msg_id, 0, 0);
    try b.u16_(36);
    try b.u16_(@intCast(dialects.len));
    try b.u16_(proto.SecurityMode.signing_enabled);
    try b.u16_(0);
    try b.u32_(0); // Capabilities
    try b.bytes("perihelion-guid!");
    const off_pos = b.len();
    try b.u32_(0);
    const count_pos = b.len();
    try b.u16_(0);
    try b.u16_(0);
    for (dialects) |d| try b.u16_(d);
    var count: u16 = 0;
    try b.alignTo(8);
    b.set32(off_pos, @intCast(b.len()));
    if (preauth_alg) |alg| {
        var d: [4 + 2 + 8]u8 = @splat(0x5a);
        wire.put16(&d, 0, 1);
        wire.put16(&d, 2, 8);
        wire.put16(&d, 4, alg);
        try putContext(&b, proto.NegCtx.preauth_integrity, &d);
        count += 1;
    }
    for ([_]struct { t: u16, ids: []const u16 }{ .{ .t = proto.NegCtx.encryption, .ids = ciphers }, .{ .t = proto.NegCtx.signing, .ids = signing } }) |cx| {
        if (cx.ids.len == 0) continue;
        var d: [2 + 2 * 8]u8 = undefined;
        wire.put16(&d, 0, @intCast(cx.ids.len));
        for (cx.ids, 0..) |id, i| wire.put16(&d, 2 + 2 * i, id);
        try putContext(&b, cx.t, d[0 .. 2 + 2 * cx.ids.len]);
        count += 1;
    }
    b.set16(count_pos, count);
    return b.list.toOwnedSlice(gpa);
}

fn run(t: *TestConn, req: []const u8, out: *Buf) !bool {
    out.clear();
    return conn_mod.processChain(t.conn, req, out);
}

test "NEGOTIATE settles 3.1.1, the cipher, and the preauth hash" {
    const gpa = testing.allocator;
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    t.conn.neg = .{};
    var out = Buf.init(gpa);
    defer out.deinit();

    const req = try negotiateRequest(gpa, 0, &.{ 0x0300, 0x0302, 0x0311 }, sha512_id, &.{ proto.Cipher.aes128_ccm, proto.Cipher.aes128_gcm }, &.{ proto.SigningAlg.aes_gmac, proto.SigningAlg.aes_cmac });
    defer gpa.free(req);
    try testing.expect(try run(&t, req, &out));
    const r = out.items();
    try testing.expectEqual(Status.success, conn_mod.statusAt(&out, 0));
    try testing.expectEqual(proto.Dialect.smb311, wire.get16(r, hdr + 4));
    try testing.expectEqual(@as(u16, 3), wire.get16(r, hdr + 6));
    try testing.expectEqual(@as(u8, 0x60), r[wire.get16(r, hdr + 56)]); // SPNEGO
    const ctx_off = wire.get32(r, hdr + 60);
    try testing.expectEqual(@as(u32, 0), ctx_off % 8);
    try testing.expectEqual(proto.NegCtx.preauth_integrity, wire.get16(r, ctx_off));
    try testing.expectEqual(proto.Cipher.aes128_gcm, t.conn.neg.cipher);
    try testing.expectEqual(proto.SigningAlg.aes_cmac, t.conn.neg.signing_alg);
    try testing.expectEqualStrings("perihelion-guid!", &t.conn.neg.client_guid);

    // The hash chains the request and then the response.
    var want: [64]u8 = @splat(0);
    var h = Sha512.init(.{});
    h.update(&want);
    h.update(req);
    h.final(&want);
    h = Sha512.init(.{});
    h.update(&want);
    h.update(r);
    h.final(&want);
    try testing.expectEqualSlices(u8, &want, &t.conn.neg.preauth);
}

test "NEGOTIATE refusals" {
    const gpa = testing.allocator;
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    var out = Buf.init(gpa);
    defer out.deinit();
    const Case = struct { dialects: []const u16, alg: ?u16, ciphers: []const u16 = &.{}, status: u32, keep: bool };
    const cases = [_]Case{
        .{ .dialects = &.{ 0x0202, 0x0300 }, .alg = sha512_id, .status = Status.not_supported, .keep = false },
        .{ .dialects = &.{0x0311}, .alg = null, .status = Status.invalid_parameter, .keep = true },
        .{ .dialects = &.{0x0311}, .alg = 0x0002, .status = Status.no_preauth_integrity_hash_overlap, .keep = true },
        .{ .dialects = &.{}, .alg = sha512_id, .status = Status.invalid_parameter, .keep = true },
    };
    for (cases) |cs| {
        t.conn.neg = .{};
        t.conn.credits = .{};
        const req = try negotiateRequest(gpa, 0, cs.dialects, cs.alg, cs.ciphers, &.{});
        defer gpa.free(req);
        try testing.expectEqual(cs.keep, try run(&t, req, &out));
        try testing.expectEqual(cs.status, conn_mod.statusAt(&out, 0));
        try testing.expectEqual(@as(u16, 0), t.conn.neg.dialect);
    }

    // No common cipher: negotiated, but without encryption.
    t.conn.neg = .{};
    t.conn.credits = .{};
    const req = try negotiateRequest(gpa, 0, &.{0x0311}, sha512_id, &.{proto.Cipher.aes256_gcm}, &.{});
    defer gpa.free(req);
    _ = try run(&t, req, &out);
    try testing.expectEqual(Status.success, conn_mod.statusAt(&out, 0));
    try testing.expectEqual(@as(u16, 0), t.conn.neg.cipher);

    // Other commands before NEGOTIATE end the connection.
    t.conn.neg = .{};
    t.conn.credits = .{};
    var echo: [hdr + 4]u8 = @splat(0);
    conn_mod.testHeader(&echo, .echo, 0, 0, 0);
    try testing.expectError(error.NotNegotiated, run(&t, &echo, &out));
}

test "an SMB1 NEGOTIATE upgrades through the wildcard dialect" {
    const gpa = testing.allocator;
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    t.conn.neg = .{};
    var out = Buf.init(gpa);
    defer out.deinit();
    var smb1: [35 + 11]u8 = @splat(0);
    @memcpy(smb1[0..5], "\xFFSMB\x72");
    wire.put16(&smb1, 33, 11);
    @memcpy(smb1[35..], "\x02SMB 2.???\x00");
    try testing.expect(try conn_mod.handleFrame(t.conn, &smb1, &out));
    try testing.expectEqual(proto.Dialect.wildcard, wire.get16(out.items(), hdr + 4));
    try testing.expectEqual(@as(u16, 1), wire.get16(out.items(), 14)); // credits
    // A second SMB1 frame is refused; the SMB2 NEGOTIATE uses message ID 1.
    out.clear();
    try testing.expectError(error.Smb1, conn_mod.handleFrame(t.conn, &smb1, &out));
    const req = try negotiateRequest(gpa, 1, &.{0x0311}, sha512_id, &.{}, &.{});
    defer gpa.free(req);
    _ = try run(&t, req, &out);
    try testing.expectEqual(Status.success, conn_mod.statusAt(&out, 0));
    try testing.expectEqual(proto.Dialect.smb311, t.conn.neg.dialect);
}

fn treeRequest(gpa: Allocator, msg_id: u64, path: []const u8) ![]u8 {
    var b = Buf.init(gpa);
    errdefer b.deinit();
    try b.zeros(hdr);
    conn_mod.testHeader(b.items(), .tree_connect, msg_id, 0, 0);
    wire.put64(b.items(), 40, 7);
    try b.u16_(9);
    try b.u16_(0);
    try b.u16_(hdr + 8);
    const len_pos = b.len();
    try b.u16_(0);
    const n = try b.utf16(path);
    b.set16(len_pos, @intCast(n));
    return b.list.toOwnedSlice(gpa);
}

test "TREE_CONNECT: shares, IPC$, read-only, and anonymous sessions" {
    const gpa = testing.allocator;
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = buf[0..try tmp.dir.realPath(testing.io, &buf)];
    try t.db.putShare(.{ .name = "Data", .path = dir });
    try t.db.putShare(.{ .name = "pub", .path = dir, .read_only = true, .guest_ok = true });
    try t.db.putShare(.{ .name = "gone", .path = "/nonexistent/skynet" });
    const s = try t.addSession(false);
    t.conn.credits.high = 64;
    var out = Buf.init(gpa);
    defer out.deinit();
    var id: u64 = 0;

    const Case = struct { path: []const u8, status: u32, access: u32 = 0, kind: u8 = 0 };
    const cases = [_]Case{
        .{ .path = "\\\\hal9000\\data", .status = Status.success, .access = proto.Access.file_all, .kind = proto.ShareType.disk },
        .{ .path = "\\\\hal9000\\PUB", .status = Status.success, .access = proto.Access.read_only_max, .kind = proto.ShareType.disk },
        .{ .path = "\\\\hal9000\\ipc$", .status = Status.success, .access = proto.Access.read_only_max, .kind = proto.ShareType.pipe },
        .{ .path = "\\\\hal9000\\nope", .status = Status.bad_network_name },
        .{ .path = "\\\\hal9000\\gone", .status = Status.bad_network_name },
        .{ .path = "data", .status = Status.bad_network_name },
    };
    for (cases) |cs| {
        const req = try treeRequest(gpa, id, cs.path);
        defer gpa.free(req);
        id += 1;
        _ = try run(&t, req, &out);
        const r = out.items();
        try testing.expectEqual(cs.status, conn_mod.statusAt(&out, 0));
        if (cs.status != Status.success) continue;
        try testing.expectEqual(cs.kind, r[hdr + 2]);
        try testing.expectEqual(cs.access, wire.get32(r, hdr + 12));
        const tree = s.trees.get(wire.get32(r, 36)).?;
        try testing.expectEqual(cs.kind == proto.ShareType.pipe, tree.ipc);
    }
    // 1 plus the existing IPC$ tree from addSession.
    try testing.expectEqual(@as(u32, 4), s.trees.count());

    // Anonymous: IPC$ always; shares only when signing is optional and the
    // share allows guests.
    s.anonymous = true;
    t.srv.cfg.signing_required = true;
    const anon = [_]Case{
        .{ .path = "\\\\hal9000\\IPC$", .status = Status.success },
        .{ .path = "\\\\hal9000\\pub", .status = Status.access_denied },
    };
    for (anon) |cs| {
        const req = try treeRequest(gpa, id, cs.path);
        defer gpa.free(req);
        id += 1;
        _ = try run(&t, req, &out);
        try testing.expectEqual(cs.status, conn_mod.statusAt(&out, 0));
    }
    t.srv.cfg.signing_required = false;
    for ([_]Case{
        .{ .path = "\\\\hal9000\\pub", .status = Status.success },
        .{ .path = "\\\\hal9000\\data", .status = Status.access_denied },
    }) |cs| {
        const req = try treeRequest(gpa, id, cs.path);
        defer gpa.free(req);
        id += 1;
        _ = try run(&t, req, &out);
        try testing.expectEqual(cs.status, conn_mod.statusAt(&out, 0));
    }
}

test "fuzz: NEGOTIATE and TREE_CONNECT" {
    const gpa = testing.allocator;
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    try t.db.putShare(.{ .name = "data", .path = "/" });

    const neg = try negotiateRequest(gpa, 0, &.{ 0x0300, 0x0311 }, sha512_id, &.{ proto.Cipher.aes128_ccm, proto.Cipher.aes128_gcm }, &.{proto.SigningAlg.aes_cmac});
    defer gpa.free(neg);
    const tree = try treeRequest(gpa, 0, "\\\\hal9000\\data");
    defer gpa.free(tree);
    const ipc = try treeRequest(gpa, 0, "\\\\hal9000\\IPC$");
    defer gpa.free(ipc);
    const seeds = [_][]const u8{ neg, tree, ipc };

    try @import("../shared/fuzz.zig").run(&t, struct {
        fn one(tc: *TestConn, in: []const u8) !void {
            if (tc.conn.sessions.count() == 0) _ = try tc.addSession(false);
            const s = tc.conn.sessions.get(7).?;
            // Keep the tree table small: drop all but the original IPC$ tree.
            while (s.trees.count() > 1) {
                var it = s.trees.valueIterator();
                const victim = while (it.next()) |x| {
                    if (x.*.id != 3) break x.*;
                } else break;
                conn_mod.disconnectTree(tc.conn, s, victim);
            }
            var out = Buf.init(testing.allocator);
            defer out.deinit();
            // Once on a fresh connection (NEGOTIATE), once negotiated.
            for ([_]u16{ 0, proto.Dialect.smb311 }) |d| {
                tc.conn.neg = .{ .dialect = d };
                tc.conn.credits = .{ .high = conn_mod.Credits.window };
                out.clear();
                _ = conn_mod.handleFrame(tc.conn, in, &out) catch {};
            }
        }
    }.one, &seeds);
}
