//! NEGOTIATE (SMB 3.1.1 only, plus the SMB1 upgrade), SESSION_SETUP, and
//! TREE_CONNECT (ARCHITECTURE.md sections 7.3 to 7.5).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha512 = std.crypto.hash.sha2.Sha512;

const proto = @import("proto.zig");
const Status = proto.Status;
const wire = @import("../shared/wire.zig");
const Buf = wire.Buf;
const crypto = @import("../shared/crypto.zig");
const ntlm = @import("auth/ntlm.zig");
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
/// Sessions, finished or in progress, one connection may hold.
pub const max_sessions = 64;
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
    hashInto(&c.neg.preauth, response);
}

/// Extend a preauthentication hash with one message (MS-SMB2 3.3.5.4,
/// 3.3.5.5).
pub fn hashInto(hash: *[64]u8, msg: []const u8) void {
    var h = Sha512.init(.{});
    h.update(hash);
    h.update(msg);
    h.final(hash);
}

pub const SetupOutcome = struct {
    status: u32,
    session: ?*Session = null,
    /// Sign the response with the new signing key (the final 3.1.1 response).
    sign: bool = false,
    /// Fold the finished response into the session's preauthentication hash.
    hash: bool = false,
};

/// SMB2 SESSION_SETUP (MS-SMB2 3.3.5.5): SPNEGO-wrapped or raw NTLMSSP,
/// NTLMv2 only. `alone` says the request is a whole frame; the preauth hash
/// covers whole messages, so SESSION_SETUP is never compounded. A new
/// session's ID is patched into the response header. A session whose
/// exchange fails is removed.
pub fn sessionSetup(c: *Conn, msg: []const u8, alone: bool, out: *Buf) !SetupOutcome {
    const gpa = c.gpa;
    const b = msg[hdr..];
    if (b.len < 24 or wire.get16(b, 0) != 25 or !alone) return .{ .status = Status.invalid_parameter };
    // Binding needs multichannel, which is not supported.
    if (b[2] & proto.SetupFlags.binding != 0) return .{ .status = Status.request_not_accepted };
    const token = wire.slice(msg, wire.get16(b, 12), wire.get16(b, 14)) catch return .{ .status = Status.invalid_parameter };
    const sid = wire.get64(msg, 40);
    var s: *Session = undefined;
    if (sid == 0) {
        if (c.sessions.count() >= max_sessions) return .{ .status = Status.insufficient_resources };
        var id = c.srv.newId();
        while (c.sessions.contains(id)) id = c.srv.newId();
        s = try gpa.create(Session);
        s.* = .{ .id = id, .created_ms = c.srv.nowMs(), .preauth = c.neg.preauth };
        c.sessions.put(gpa, s.id, s) catch |e| {
            gpa.destroy(s);
            return e;
        };
        out.set64(40, s.id);
    } else {
        s = c.sessions.get(sid) orelse return .{ .status = Status.user_session_deleted };
        // Reauthentication is not supported.
        if (s.state == .valid) return .{ .status = Status.request_not_accepted };
    }
    hashInto(&s.preauth, msg);
    const r = setupStep(c, s, b[3], token, out) catch |e| {
        conn_mod.logoff(c, s);
        return e;
    };
    if (r.status != Status.success and r.status != Status.more_processing_required) conn_mod.logoff(c, s);
    return r;
}

/// The SESSION_SETUP response body carrying `token`.
fn setupBody(out: *Buf, flags: u16, token: []const u8) !void {
    try out.u16_(9);
    try out.u16_(flags);
    try out.u16_(hdr + 8);
    try out.u16_(@intCast(token.len));
    try out.bytes(token);
}

/// One leg of the exchange on session `s`. The body is written only on
/// success or MORE_PROCESSING_REQUIRED.
fn setupStep(c: *Conn, s: *Session, client_mode: u8, token: []const u8, out: *Buf) !SetupOutcome {
    const gpa = c.gpa;
    const more: SetupOutcome = .{ .status = Status.more_processing_required, .session = s, .hash = true };
    if (token.len == 0) {
        // An empty token asks for the server's mechanism list.
        if (s.auth != null) return logonFailure(c, null);
        const init = try spnego.negTokenInit(gpa);
        defer gpa.free(init);
        try setupBody(out, 0, init);
        return more;
    }
    const ct = spnego.parseClientToken(token) catch return logonFailure(c, null);
    if (!ct.offers_ntlm) return logonFailure(c, null);
    if (ct.mech_types_raw.len != 0 and s.mech_types.len == 0) s.mech_types = try gpa.dupe(u8, ct.mech_types_raw);
    const nm = ct.mech_token;
    const kind: u32 = if (nm.len >= 12 and std.mem.eql(u8, nm[0..8], "NTLMSSP\x00")) wire.get32(nm, 8) else 0;

    if (s.auth == null) {
        if (kind == 0 and ct.spnego) {
            // An optimistic token for another mechanism: name NTLMSSP and
            // wait for its NEGOTIATE.
            const resp = try spnego.negTokenResp(gpa, .accept_incomplete, true, null, null);
            defer gpa.free(resp);
            try setupBody(out, 0, resp);
            return more;
        }
        if (kind != 1) return logonFailure(c, null);
        s.auth = .{ .gpa = gpa };
        const cfg = try c.srv.configCopy(gpa);
        defer cfg.free(gpa);
        const dns = try std.ascii.allocLowerString(gpa, cfg.server_name);
        defer gpa.free(dns);
        const chal = s.auth.?.challengeFor(c.srv.io, nm, cfg.server_name, cfg.workgroup, dns, ntNow(c)) catch |e| switch (e) {
            error.Malformed => return logonFailure(c, null),
            else => return e,
        };
        const resp = if (ct.spnego) try spnego.negTokenResp(gpa, .accept_incomplete, true, chal, null) else try gpa.dupe(u8, chal);
        defer gpa.free(resp);
        try setupBody(out, 0, resp);
        return more;
    }

    if (kind != 3) return logonFailure(c, null);
    var res = ntlm.authenticate(&s.auth.?, nm, c, lookupNtHash) catch |e| switch (e) {
        error.LogonFailure, error.Malformed => return logonFailure(c, nm),
        else => return e,
    };
    defer res.deinit(gpa);
    defer std.crypto.secureZero(u8, &res.session_key);
    // A mechListMIC, when sent, must verify (RFC 4178 5).
    const check_mic = ct.mech_list_mic.len != 0 and !res.anonymous;
    if (check_mic) {
        if (ct.mech_list_mic.len != 16) return logonFailure(c, nm);
        const want = res.mic(true, s.mech_types);
        if (!std.crypto.timing_safe.eql([16]u8, want, ct.mech_list_mic[0..16].*)) return logonFailure(c, nm);
    }
    const encrypt = encryptRequired(c);
    if (encrypt and (res.anonymous or c.neg.cipher == 0)) {
        c.srv.log(c.id, "auth", "refused {s}: encryption is required", .{if (res.anonymous) "anonymous logon" else res.user});
        return .{ .status = Status.access_denied };
    }

    var flags: u16 = 0;
    s.anonymous = res.anonymous;
    if (res.anonymous) {
        flags |= proto.SessionFlags.is_null;
    } else {
        s.session_key = res.session_key;
        s.signing_key = crypto.kdf(&s.session_key, "SMBSigningKey\x00", &s.preauth);
        s.enc_key = crypto.kdf(&s.session_key, "SMBS2CCipherKey\x00", &s.preauth);
        s.dec_key = crypto.kdf(&s.session_key, "SMBC2SCipherKey\x00", &s.preauth);
        s.sign = signingRequired(c) or client_mode & proto.SecurityMode.signing_required != 0;
        s.encrypt = encrypt;
        if (encrypt) flags |= proto.SessionFlags.encrypt_data;
    }
    const mic: ?[16]u8 = if (check_mic) res.mic(false, s.mech_types) else null;
    const resp: []u8 = if (ct.spnego)
        try spnego.negTokenResp(gpa, .accept_completed, false, null, if (mic) |*m| m[0..] else null)
    else
        try gpa.alloc(u8, 0);
    defer gpa.free(resp);
    try setupBody(out, flags, resp);

    std.mem.swap([]u8, &s.user, &res.user);
    std.mem.swap([]u8, &s.domain, &res.domain);
    std.mem.swap([]u8, &s.workstation, &res.workstation);
    s.auth.?.deinit();
    s.auth = null;
    s.state = .valid;
    c.srv.watchSession(c.id, s.id, if (s.anonymous) "" else s.user);
    if (s.anonymous)
        c.srv.log(c.id, "auth", "anonymous logon", .{})
    else
        c.srv.log(c.id, "auth", "{s} logged on from {s}", .{ s.user, s.workstation });
    return .{ .status = Status.success, .session = s, .sign = !s.anonymous };
}

/// Count and log a failed logon; the status never says which part was wrong.
fn logonFailure(c: *Conn, authenticate: ?[]const u8) SetupOutcome {
    _ = c.srv.stats.logon_failures.fetchAdd(1, .monotonic);
    const user = if (authenticate) |m| ntlm.userName(c.gpa, m) else null;
    defer if (user) |u| c.gpa.free(u);
    c.srv.log(c.id, "auth", "logon failure for {s}", .{user orelse "(unknown user)"});
    return .{ .status = Status.logon_failure };
}

/// NT hash for SMB logins; admins and unknown users look alike.
fn lookupNtHash(c: *Conn, name: []const u8) ntlm.LookupError![16]u8 {
    const h = c.srv.db.ntHash(name) catch |e| {
        c.srv.log(c.id, "auth", "user lookup failed: {s}", .{@errorName(e)});
        return error.NoSuchUser;
    };
    return h orelse error.NoSuchUser;
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
    // The share's configured path, kept for the activity view and for
    // noticing that the share has since changed.
    var configured: []u8 = &.{};
    defer gpa.free(configured);
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
        configured = try gpa.dupe(u8, sh.path);
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
    c.srv.watchTree(c.id, s.id, id, share_name, configured, read_only);

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
    try testing.expect((try conn_mod.handleFrame(t.conn, &smb1, &out)).keep);
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

/// A SESSION_SETUP request on session `sid` carrying `token`.
fn setupRequest(gpa: Allocator, msg_id: u64, sid: u64, flags: u8, token: []const u8) ![]u8 {
    var b = Buf.init(gpa);
    errdefer b.deinit();
    try b.zeros(hdr);
    conn_mod.testHeader(b.items(), .session_setup, msg_id, 0, 0);
    wire.put64(b.items(), 40, sid);
    try b.u16_(25);
    try b.u8_(flags);
    try b.u8_(proto.SecurityMode.signing_enabled);
    try b.u32_(0); // Capabilities
    try b.u32_(0); // Channel
    try b.u16_(hdr + 24);
    try b.u16_(@intCast(token.len));
    try b.u64_(0); // PreviousSessionId
    try b.bytes(token);
    return b.list.toOwnedSlice(gpa);
}

/// The security buffer of a SESSION_SETUP response.
fn setupToken(resp: []const u8) []const u8 {
    return wire.slice(resp, wire.get16(resp, hdr + 4), wire.get16(resp, hdr + 6)) catch &.{};
}

fn derTlv(b: *Buf, tag: u8, parts: []const []const u8) !void {
    var n: usize = 0;
    for (parts) |p| n += p.len;
    try b.u8_(tag);
    if (n < 0x80) try b.u8_(@intCast(n)) else {
        try b.u8_(0x82);
        try b.u16be(@intCast(n));
    }
    for (parts) |p| try b.bytes(p);
}

/// A client NegTokenInit offering `mech_types` with an optimistic `token`.
fn clientInit(gpa: Allocator, mech_types: []const u8, token: []const u8) ![]u8 {
    var os = Buf.init(gpa);
    defer os.deinit();
    try derTlv(&os, 0x04, &.{token});
    var a0 = Buf.init(gpa);
    defer a0.deinit();
    try derTlv(&a0, 0xa0, &.{mech_types});
    var a2 = Buf.init(gpa);
    defer a2.deinit();
    try derTlv(&a2, 0xa2, &.{os.items()});
    var seq = Buf.init(gpa);
    defer seq.deinit();
    try derTlv(&seq, 0x30, &.{ a0.items(), a2.items() });
    var init_ = Buf.init(gpa);
    defer init_.deinit();
    try derTlv(&init_, 0xa0, &.{seq.items()});
    var oid = Buf.init(gpa);
    defer oid.deinit();
    try derTlv(&oid, 0x06, &.{&spnego.oid_spnego});
    var b = Buf.init(gpa);
    errdefer b.deinit();
    try derTlv(&b, 0x60, &.{ oid.items(), init_.items() });
    return b.list.toOwnedSlice(gpa);
}

const client_flags = ntlm.Flag.unicode | ntlm.Flag.ntlm | ntlm.Flag.extended_session_security |
    ntlm.Flag.key_exch | ntlm.Flag.sign | ntlm.Flag.n128;

fn ntlmNegotiate() [32]u8 {
    var m: [32]u8 = @splat(0);
    @memcpy(m[0..8], "NTLMSSP\x00");
    wire.put32(&m, 8, 1);
    wire.put32(&m, 12, client_flags);
    return m;
}

/// An NTLMv2 AUTHENTICATE answering `chal`, or an anonymous one when
/// `password` is null. `key` gets the exported session key.
fn ntlmAuthenticate(gpa: Allocator, chal: []const u8, user: []const u8, password: ?[]const u8, key: *[16]u8) ![]u8 {
    const HmacMd5 = std.crypto.auth.hmac.HmacMd5;
    var dom = Buf.init(gpa);
    defer dom.deinit();
    var usr = Buf.init(gpa);
    defer usr.deinit();
    _ = try usr.utf16(user);
    var nt = Buf.init(gpa);
    defer nt.deinit();
    var enc: [16]u8 = undefined;
    var enc_s: []const u8 = &.{};
    key.* = @splat(0);
    if (password) |pw| {
        _ = try dom.utf16("WORKGROUP");
        const nth = try crypto.ntHash(gpa, pw);
        const up = try wire.upperUtf16(gpa, user);
        defer gpa.free(up);
        var owf: [16]u8 = undefined;
        var h = HmacMd5.init(&nth);
        h.update(up);
        h.update(dom.items());
        h.final(&owf);
        const ti = try wire.slice(chal, wire.get32(chal, 44), wire.get16(chal, 40));
        var blob = Buf.init(gpa);
        defer blob.deinit();
        try blob.bytes(&.{ 1, 1, 0, 0, 0, 0, 0, 0 });
        try blob.u64_(0);
        try blob.bytes(&@as([8]u8, @splat(0xaa)));
        try blob.u32_(0);
        try blob.bytes(ti);
        try blob.u32_(0);
        var proof: [16]u8 = undefined;
        var h2 = HmacMd5.init(&owf);
        h2.update(chal[24..32]);
        h2.update(blob.items());
        h2.final(&proof);
        try nt.bytes(&proof);
        try nt.bytes(blob.items());
        var base: [16]u8 = undefined;
        HmacMd5.create(&base, &proof, &owf);
        key.* = @splat(0x42);
        enc = key.*;
        var rc = crypto.Rc4.init(&base);
        rc.apply(&enc);
        enc_s = &enc;
    }
    var m = Buf.init(gpa);
    errdefer m.deinit();
    try m.bytes("NTLMSSP\x00");
    try m.u32_(3);
    const parts = [_][]const u8{ &.{}, nt.items(), dom.items(), usr.items(), &.{}, enc_s };
    var off: u32 = 64;
    for (parts) |p| {
        try m.u16_(@intCast(p.len));
        try m.u16_(@intCast(p.len));
        try m.u32_(off);
        off += @intCast(p.len);
    }
    try m.u32_(client_flags);
    for (parts) |p| try m.bytes(p);
    return m.list.toOwnedSlice(gpa);
}

/// Run both legs for `user` through SPNEGO, starting at message ID `id`.
/// Returns the final status; `out` holds the final response.
fn logon(t: *TestConn, id: u64, user: []const u8, password: ?[]const u8, out: *Buf) !u32 {
    const gpa = testing.allocator;
    const mech_types = try spnego.mechTypesNtlm(gpa);
    defer gpa.free(mech_types);
    const neg = ntlmNegotiate();
    const init_tok = try clientInit(gpa, mech_types, &neg);
    defer gpa.free(init_tok);
    const r1 = try setupRequest(gpa, id, 0, 0, init_tok);
    defer gpa.free(r1);
    _ = try run(t, r1, out);
    if (conn_mod.statusAt(out, 0) != Status.more_processing_required) return conn_mod.statusAt(out, 0);
    const sid = wire.get64(out.items(), 40);
    const chal = try gpa.dupe(u8, (try spnego.parseClientToken(setupToken(out.items()))).mech_token);
    defer gpa.free(chal);
    var key: [16]u8 = undefined;
    const auth = try ntlmAuthenticate(gpa, chal, user, password, &key);
    defer gpa.free(auth);
    const ar: ntlm.AuthResult = .{ .user = &.{}, .domain = &.{}, .workstation = &.{}, .anonymous = false, .session_key = key, .flags = client_flags };
    const mic = ar.mic(true, mech_types);
    const tok = try spnego.negTokenResp(gpa, .accept_incomplete, false, auth, &mic);
    defer gpa.free(tok);
    const r2 = try setupRequest(gpa, id + 1, sid, 0, tok);
    defer gpa.free(r2);
    _ = try run(t, r2, out);
    return conn_mod.statusAt(out, 0);
}

test "SESSION_SETUP: NTLMv2 through SPNEGO, keys, MICs, and the signed response" {
    const gpa = testing.allocator;
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    t.srv.cfg.signing_required = true;
    try t.db.putUser("hal", .{ .set = try crypto.ntHash(gpa, "daisy") }, .keep, 0);
    var out = Buf.init(gpa);
    defer out.deinit();
    const mech_types = try spnego.mechTypesNtlm(gpa);
    defer gpa.free(mech_types);
    var preauth = t.conn.neg.preauth;

    // Leg 1: NegTokenInit with the NTLM NEGOTIATE.
    const neg = ntlmNegotiate();
    const init_tok = try clientInit(gpa, mech_types, &neg);
    defer gpa.free(init_tok);
    const r1 = try setupRequest(gpa, 0, 0, 0, init_tok);
    defer gpa.free(r1);
    _ = try run(&t, r1, &out);
    try testing.expectEqual(Status.more_processing_required, conn_mod.statusAt(&out, 0));
    const sid = wire.get64(out.items(), 40);
    try testing.expect(sid != 0);
    try testing.expect(wire.get32(out.items(), 16) & proto.Flags.signed == 0);
    hashInto(&preauth, r1);
    hashInto(&preauth, out.items());
    const chal = try gpa.dupe(u8, (try spnego.parseClientToken(setupToken(out.items()))).mech_token);
    defer gpa.free(chal);
    try testing.expectEqual(@as(u32, 2), wire.get32(chal, 8));

    // Leg 2: AUTHENTICATE with a mechListMIC.
    var key: [16]u8 = undefined;
    const auth = try ntlmAuthenticate(gpa, chal, "hal", "daisy", &key);
    defer gpa.free(auth);
    const ar: ntlm.AuthResult = .{ .user = &.{}, .domain = &.{}, .workstation = &.{}, .anonymous = false, .session_key = key, .flags = client_flags };
    const mic = ar.mic(true, mech_types);
    const tok = try spnego.negTokenResp(gpa, .accept_incomplete, false, auth, &mic);
    defer gpa.free(tok);
    const r2 = try setupRequest(gpa, 1, sid, 0, tok);
    defer gpa.free(r2);
    _ = try run(&t, r2, &out);
    try testing.expectEqual(Status.success, conn_mod.statusAt(&out, 0));
    hashInto(&preauth, r2);

    // The keys come from the session key and the preauth hash, and the final
    // response is signed and carries the server's MIC.
    const o = out.items();
    const sk = crypto.kdf(&key, "SMBSigningKey\x00", &preauth);
    try testing.expectEqual(@as(u16, 0), wire.get16(o, hdr + 2));
    try testing.expect(wire.get32(o, 16) & proto.Flags.signed != 0);
    try testing.expectEqualSlices(u8, &crypto.cmacSigZeroed(&sk, o), o[48..64]);
    const fin = try spnego.parseClientToken(setupToken(o));
    try testing.expectEqualSlices(u8, &ar.mic(false, mech_types), fin.mech_list_mic);
    const s = t.conn.sessions.get(sid).?;
    try testing.expect(s.state == .valid and s.sign and !s.encrypt and s.auth == null);
    try testing.expectEqualStrings("hal", s.user);
    try testing.expectEqualSlices(u8, &sk, &s.signing_key);
    try testing.expectEqualSlices(u8, &crypto.kdf(&key, "SMBC2SCipherKey\x00", &preauth), &s.dec_key);
    try testing.expectEqualSlices(u8, &crypto.kdf(&key, "SMBS2CCipherKey\x00", &preauth), &s.enc_key);

    // A signed TREE_CONNECT on the new session succeeds; reauthentication
    // is refused.
    const tree = try treeRequest(gpa, 2, "\\\\hal9000\\IPC$");
    defer gpa.free(tree);
    wire.put64(tree, 40, sid);
    conn_mod.signMessage(tree, sk);
    _ = try run(&t, tree, &out);
    try testing.expectEqual(Status.success, conn_mod.statusAt(&out, 0));
    const again = try setupRequest(gpa, 3, sid, 0, tok);
    defer gpa.free(again);
    _ = try run(&t, again, &out);
    try testing.expectEqual(Status.request_not_accepted, conn_mod.statusAt(&out, 0));
}

test "SESSION_SETUP: failures, anonymous logons, and policy" {
    const gpa = testing.allocator;
    var t: TestConn = undefined;
    try t.init();
    defer t.deinit();
    try t.db.putUser("hal", .{ .set = try crypto.ntHash(gpa, "daisy") }, .keep, 0);
    try t.db.putUser("art", .keep, .{ .set = "x" }, 0);
    var out = Buf.init(gpa);
    defer out.deinit();

    // A wrong password and an admin fail alike, and leave no session.
    try testing.expectEqual(Status.logon_failure, try logon(&t, 0, "hal", "dave", &out));
    try testing.expectEqual(Status.logon_failure, try logon(&t, 2, "art", "x", &out));
    try testing.expectEqual(Status.logon_failure, try logon(&t, 4, "skynet", "x", &out));
    try testing.expectEqual(@as(u32, 0), t.conn.sessions.count());
    try testing.expectEqual(@as(u64, 3), t.srv.stats.logon_failures.load(.monotonic));

    // Encryption required, but no cipher was negotiated.
    t.srv.cfg.encrypt = true;
    try testing.expectEqual(Status.access_denied, try logon(&t, 6, "hal", "daisy", &out));
    try testing.expectEqual(@as(u32, 0), t.conn.sessions.count());
    // With a cipher, the session encrypts.
    t.conn.neg.cipher = proto.Cipher.aes128_gcm;
    try testing.expectEqual(Status.success, try logon(&t, 8, "hal", "daisy", &out));
    try testing.expectEqual(proto.SessionFlags.encrypt_data, wire.get16(out.items(), hdr + 2));
    try testing.expect(t.conn.sessions.get(wire.get64(out.items(), 40)).?.encrypt);
    t.srv.cfg.encrypt = false;

    // Raw NTLMSSP, anonymous: a null session with an unsigned response.
    var id: u64 = 10;
    const neg = ntlmNegotiate();
    const r1 = try setupRequest(gpa, id, 0, 0, &neg);
    defer gpa.free(r1);
    _ = try run(&t, r1, &out);
    try testing.expectEqual(Status.more_processing_required, conn_mod.statusAt(&out, 0));
    const sid = wire.get64(out.items(), 40);
    const chal = try gpa.dupe(u8, setupToken(out.items()));
    defer gpa.free(chal);
    var key: [16]u8 = undefined;
    const auth = try ntlmAuthenticate(gpa, chal, "", null, &key);
    defer gpa.free(auth);
    const r2 = try setupRequest(gpa, id + 1, sid, 0, auth);
    defer gpa.free(r2);
    _ = try run(&t, r2, &out);
    try testing.expectEqual(Status.success, conn_mod.statusAt(&out, 0));
    try testing.expectEqual(proto.SessionFlags.is_null, wire.get16(out.items(), hdr + 2));
    try testing.expect(wire.get32(out.items(), 16) & proto.Flags.signed == 0);
    try testing.expect(t.conn.sessions.get(sid).?.anonymous);
    id += 2;

    // An empty token gets the server's NegTokenInit.
    const empty = try setupRequest(gpa, id, 0, 0, &.{});
    defer gpa.free(empty);
    _ = try run(&t, empty, &out);
    id += 1;
    try testing.expectEqual(Status.more_processing_required, conn_mod.statusAt(&out, 0));
    try testing.expect((try spnego.parseClientToken(setupToken(out.items()))).offers_ntlm);

    // Binding, an unknown session, and an AUTHENTICATE out of turn.
    const bind = try setupRequest(gpa, id, 0, proto.SetupFlags.binding, &neg);
    defer gpa.free(bind);
    _ = try run(&t, bind, &out);
    id += 1;
    try testing.expectEqual(Status.request_not_accepted, conn_mod.statusAt(&out, 0));
    const unknown = try setupRequest(gpa, id, 999999, 0, &neg);
    defer gpa.free(unknown);
    _ = try run(&t, unknown, &out);
    id += 1;
    try testing.expectEqual(Status.user_session_deleted, conn_mod.statusAt(&out, 0));
    const early = try setupRequest(gpa, id, 0, 0, auth);
    defer gpa.free(early);
    _ = try run(&t, early, &out);
    id += 1;
    try testing.expectEqual(Status.logon_failure, conn_mod.statusAt(&out, 0));
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

test "fuzz: NEGOTIATE, SESSION_SETUP, and TREE_CONNECT" {
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
    const mech_types = try spnego.mechTypesNtlm(gpa);
    defer gpa.free(mech_types);
    const ntlm_neg = ntlmNegotiate();
    const init_tok = try clientInit(gpa, mech_types, &ntlm_neg);
    defer gpa.free(init_tok);
    const setup1 = try setupRequest(gpa, 0, 0, 0, init_tok);
    defer gpa.free(setup1);
    const setup_raw = try setupRequest(gpa, 0, 0, 0, &ntlm_neg);
    defer gpa.free(setup_raw);
    const seeds = [_][]const u8{ neg, tree, ipc, setup1, setup_raw };

    try @import("../shared/fuzz.zig").run(&t, struct {
        fn one(tc: *TestConn, in: []const u8) !void {
            // Drop sessions that earlier inputs started, keeping session 7.
            while (true) {
                var sit = tc.conn.sessions.valueIterator();
                const extra = while (sit.next()) |x| {
                    if (x.*.id != 7) break x.*;
                } else break;
                conn_mod.logoff(tc.conn, extra);
            }
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
