//! zsmbt's SMB 3.1.1 client: frames, NEGOTIATE, NTLMv2 through SPNEGO,
//! signing, and the session and tree commands. Its encoders are written
//! apart from the server's; only the constants (`proto`) and the primitives
//! (`crypto`) are shared.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const HmacMd5 = std.crypto.auth.hmac.HmacMd5;
const Md5 = std.crypto.hash.Md5;
const proto = @import("proto");
const crypto = @import("crypto");

pub const hdr = proto.header_size;
const max_frame = 16 * 1024 * 1024;
const trace_keep = 32;

// ---------------------------------------------------------------- Msg

/// A growing little-endian message.
pub const Msg = struct {
    gpa: Allocator,
    list: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator) Msg {
        return .{ .gpa = gpa };
    }
    pub fn deinit(m: *Msg) void {
        m.list.deinit(m.gpa);
    }
    pub fn len(m: *const Msg) usize {
        return m.list.items.len;
    }
    pub fn items(m: *Msg) []u8 {
        return m.list.items;
    }
    pub fn toOwned(m: *Msg) ![]u8 {
        return m.list.toOwnedSlice(m.gpa);
    }
    pub fn bytes(m: *Msg, v: []const u8) !void {
        try m.list.appendSlice(m.gpa, v);
    }
    pub fn u8_(m: *Msg, v: u8) !void {
        try m.list.append(m.gpa, v);
    }
    pub fn u16_(m: *Msg, v: u16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .little);
        try m.bytes(&b);
    }
    pub fn u32_(m: *Msg, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try m.bytes(&b);
    }
    pub fn u64_(m: *Msg, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try m.bytes(&b);
    }
    pub fn zeros(m: *Msg, n: usize) !void {
        try m.list.appendNTimes(m.gpa, 0, n);
    }
    pub fn alignTo(m: *Msg, a: usize) !void {
        try m.zeros(std.mem.alignForward(usize, m.len(), a) - m.len());
    }
    pub fn set16(m: *Msg, off: usize, v: u16) void {
        std.mem.writeInt(u16, m.list.items[off..][0..2], v, .little);
    }
    pub fn set32(m: *Msg, off: usize, v: u32) void {
        std.mem.writeInt(u32, m.list.items[off..][0..4], v, .little);
    }
    /// UTF-16LE of `s`; returns the byte count written.
    pub fn utf16(m: *Msg, s: []const u8) !usize {
        const start = m.len();
        var it = (try std.unicode.Utf8View.init(s)).iterator();
        while (it.nextCodepoint()) |cp| {
            if (cp < 0x10000) {
                try m.u16_(@intCast(cp));
            } else {
                const c = cp - 0x10000;
                try m.u16_(@intCast(0xD800 + (c >> 10)));
                try m.u16_(@intCast(0xDC00 + (c & 0x3ff)));
            }
        }
        return m.len() - start;
    }
};

pub fn get16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .little);
}
pub fn get32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}
pub fn get64(b: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, b[off..][0..8], .little);
}

// ---------------------------------------------------------------- frames

/// One request. `body` follows the 64-byte header as given.
pub const Request = struct {
    command: u16,
    credit_charge: u16 = 1,
    /// Credits asked for.
    credits: u16 = 64,
    flags: u32 = 0,
    /// Null: the next ID, which this request then uses up.
    message_id: ?u64 = null,
    tree_id: u32 = 0,
    session_id: u64 = 0,
    body: []const u8 = &.{},
    /// Null: sign when the client has a signing key.
    sign: ?bool = null,
};

/// One response frame, header included.
pub const Reply = struct {
    gpa: Allocator,
    raw: []u8,

    pub fn deinit(r: Reply) void {
        r.gpa.free(r.raw);
    }
    pub fn status(r: Reply) u32 {
        return get32(r.raw, 8);
    }
    pub fn command(r: Reply) u16 {
        return get16(r.raw, 12);
    }
    pub fn credits(r: Reply) u16 {
        return get16(r.raw, 14);
    }
    pub fn flags(r: Reply) u32 {
        return get32(r.raw, 16);
    }
    pub fn messageId(r: Reply) u64 {
        return get64(r.raw, 24);
    }
    pub fn treeId(r: Reply) u32 {
        return get32(r.raw, 36);
    }
    pub fn sessionId(r: Reply) u64 {
        return get64(r.raw, 40);
    }
    pub fn signed(r: Reply) bool {
        return r.flags() & proto.Flags.signed != 0;
    }
    pub fn body(r: Reply) []const u8 {
        return r.raw[hdr..];
    }
    /// The bytes at `off` from the start of the header, for fields that are
    /// offsets (null if they lie outside the frame).
    pub fn at(r: Reply, off: usize, n: usize) ?[]const u8 {
        if (off > r.raw.len or n > r.raw.len - off) return null;
        return r.raw[off..][0..n];
    }
};

const Trace = struct { out: bool, bytes: []u8 };

pub const ReadError = error{ ConnectionClosed, Timeout, FrameTooLarge, BadSignature, OutOfMemory };

/// What NEGOTIATE settled.
pub const Negotiated = struct {
    dialect: u16 = 0,
    security_mode: u16 = 0,
    capabilities: u32 = 0,
    max_transact: u32 = 0,
    max_read: u32 = 0,
    max_write: u32 = 0,
    guid: [16]u8 = @splat(0),
    preauth_alg: ?u16 = null,
    cipher: ?u16 = null,
    signing_alg: ?u16 = null,
    credits: u16 = 0,
    /// The security buffer starts with the SPNEGO tag (0x60).
    spnego: bool = false,
};

pub const NegotiateOptions = struct {
    dialects: []const u16 = &.{proto.Dialect.smb311},
    security_mode: u16 = proto.SecurityMode.signing_enabled,
    capabilities: u32 = 0,
    /// Context lists; null leaves that context out.
    preauth_algs: ?[]const u16 = &.{1},
    ciphers: ?[]const u16 = &.{ proto.Cipher.aes128_gcm, proto.Cipher.aes128_ccm },
    signing_algs: ?[]const u16 = &.{proto.SigningAlg.aes_cmac},
    /// Send the preauth context twice.
    preauth_twice: bool = false,
    /// Null: the next ID.
    message_id: ?u64 = 0,
};

pub const LoginResult = struct {
    status: u32,
    session_flags: u16 = 0,
    /// The final response carried a signature.
    signed: bool = false,
};

pub const Client = struct {
    gpa: Allocator,
    io: Io,
    stream: net.Stream,
    reader: net.Stream.Reader,
    rbuf: [16 * 1024]u8 = undefined,
    next_id: u64 = 0,
    /// Credits granted and not yet spent.
    credits: u32 = 1,
    neg: Negotiated = .{},
    /// SHA-512 chain over NEGOTIATE and SESSION_SETUP (MS-SMB2 3.2.5.3).
    preauth: [64]u8 = @splat(0),
    session_id: u64 = 0,
    session_key: [16]u8 = @splat(0),
    signing_key: ?[16]u8 = null,
    trace: std.ArrayList(Trace) = .empty,

    /// Connects to `addr`. Reads give up after `timeout_s` seconds.
    pub fn connect(gpa: Allocator, io: Io, addr: net.IpAddress, timeout_s: u32) !*Client {
        const c = try gpa.create(Client);
        errdefer gpa.destroy(c);
        const stream = try addr.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        c.* = .{ .gpa = gpa, .io = io, .stream = stream, .reader = undefined };
        c.reader = stream.reader(io, &c.rbuf);
        const tv = std.c.timeval{ .sec = @intCast(timeout_s), .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        return c;
    }

    pub fn deinit(c: *Client) void {
        c.stream.close(c.io);
        for (c.trace.items) |t| c.gpa.free(t.bytes);
        c.trace.deinit(c.gpa);
        c.gpa.destroy(c);
    }

    // ------------------------------------------------------------ transport

    fn note(c: *Client, out: bool, frame: []const u8) void {
        const copy = c.gpa.dupe(u8, frame) catch return;
        if (c.trace.items.len == trace_keep) c.gpa.free(c.trace.orderedRemove(0).bytes);
        c.trace.append(c.gpa, .{ .out = out, .bytes = copy }) catch c.gpa.free(copy);
    }

    /// Sends `frame` behind its 4-byte length.
    pub fn sendRaw(c: *Client, frame: []const u8) !void {
        c.note(true, frame);
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(frame.len), .big);
        var wbuf: [4096]u8 = undefined;
        var w = c.stream.writer(c.io, &wbuf);
        try w.interface.writeAll(&len);
        try w.interface.writeAll(frame);
        try w.interface.flush();
    }

    /// Sends arbitrary bytes, with no length prefix.
    pub fn sendBytes(c: *Client, data: []const u8) !void {
        var wbuf: [4096]u8 = undefined;
        var w = c.stream.writer(c.io, &wbuf);
        try w.interface.writeAll(data);
        try w.interface.flush();
    }

    fn readAll(c: *Client, buf: []u8) ReadError!void {
        c.reader.interface.readSliceAll(buf) catch |e| switch (e) {
            error.EndOfStream => return error.ConnectionClosed,
            // SO_RCVTIMEO surfaces as a timeout or, on some systems, as
            // an unexpected errno (EAGAIN).
            error.ReadFailed => return switch (c.reader.err orelse error.Unexpected) {
                error.ConnectionTimedOut, error.Unexpected => error.Timeout,
                else => error.ConnectionClosed,
            },
        };
    }

    /// The next frame, unchecked.
    pub fn recvFrame(c: *Client) ReadError![]u8 {
        var len_buf: [4]u8 = undefined;
        try c.readAll(&len_buf);
        const n = std.mem.readInt(u32, &len_buf, .big);
        if (n > max_frame) return error.FrameTooLarge;
        const frame = try c.gpa.alloc(u8, n);
        errdefer c.gpa.free(frame);
        try c.readAll(frame);
        c.note(false, frame);
        return frame;
    }

    /// The next response; a signature, if present, must verify.
    pub fn recv(c: *Client) ReadError!Reply {
        const raw = try c.recvFrame();
        const r: Reply = .{ .gpa = c.gpa, .raw = raw };
        errdefer r.deinit();
        if (raw.len >= hdr and r.signed()) {
            if (c.signing_key) |*k| {
                if (!std.crypto.timing_safe.eql([16]u8, crypto.cmacSigZeroed(k, raw), raw[48..64].*))
                    return error.BadSignature;
            }
        }
        if (raw.len >= hdr) c.credits +|= r.credits();
        return r;
    }

    /// The next response, or null if the server closed the connection.
    pub fn recvOrClosed(c: *Client) !?Reply {
        return c.recv() catch |e| if (e == error.ConnectionClosed) null else e;
    }

    /// Whether the server closes the connection without sending anything
    /// more; a silent open connection is false.
    pub fn expectClosed(c: *Client) bool {
        const raw = c.recvFrame() catch |e| return e == error.ConnectionClosed;
        c.gpa.free(raw);
        return false;
    }

    // ------------------------------------------------------------ requests

    /// Builds the frame for `req`, signed when it applies.
    pub fn build(c: *Client, req: Request) ![]u8 {
        var m = Msg.init(c.gpa);
        errdefer m.deinit();
        const do_sign = (req.sign orelse true) and c.signing_key != null and req.session_id != 0;
        const id = req.message_id orelse blk: {
            const id = c.next_id;
            c.next_id += @max(req.credit_charge, 1);
            break :blk id;
        };
        try m.bytes(&proto.protocol_id);
        try m.u16_(hdr);
        try m.u16_(req.credit_charge);
        try m.u32_(0); // Status
        try m.u16_(req.command);
        try m.u16_(req.credits);
        try m.u32_(req.flags | if (do_sign) proto.Flags.signed else 0);
        try m.u32_(0); // NextCommand
        try m.u64_(id);
        try m.u32_(0); // Reserved
        try m.u32_(req.tree_id);
        try m.u64_(req.session_id);
        try m.zeros(16); // Signature
        try m.bytes(req.body);
        const frame = try m.toOwned();
        if (do_sign) c.sign(frame);
        return frame;
    }

    /// Signs `frame` in place with the session's signing key.
    pub fn sign(c: *Client, frame: []u8) void {
        const sig = crypto.cmacSigZeroed(&c.signing_key.?, frame);
        @memcpy(frame[48..64], &sig);
    }

    /// Sends `req` and waits for its response.
    pub fn call(c: *Client, req: Request) !Reply {
        const frame = try c.build(req);
        defer c.gpa.free(frame);
        if (c.credits > 0) c.credits -= 1;
        try c.sendRaw(frame);
        return c.recv();
    }

    // ------------------------------------------------------------ NEGOTIATE

    /// A NEGOTIATE request frame for `o`, message ID 0 unless it already
    /// went out.
    pub fn negotiateFrame(c: *Client, o: NegotiateOptions) ![]u8 {
        var b = Msg.init(c.gpa);
        defer b.deinit();
        try b.u16_(36);
        try b.u16_(@intCast(o.dialects.len));
        try b.u16_(o.security_mode);
        try b.u16_(0);
        try b.u32_(o.capabilities);
        var guid: [16]u8 = undefined;
        c.io.random(&guid);
        try b.bytes(&guid);
        const ctx_off = b.len();
        try b.u32_(0); // NegotiateContextOffset
        const ctx_count = b.len();
        try b.u16_(0);
        try b.u16_(0);
        for (o.dialects) |d| try b.u16_(d);

        var count: u16 = 0;
        const any = o.preauth_algs != null or o.ciphers != null or o.signing_algs != null;
        if (any) {
            try b.alignTo(8);
            b.set32(ctx_off, @intCast(hdr + b.len()));
        }
        if (o.preauth_algs) |algs| {
            for (0..@as(usize, if (o.preauth_twice) 2 else 1)) |_| {
                var d = Msg.init(c.gpa);
                defer d.deinit();
                try d.u16_(@intCast(algs.len));
                try d.u16_(32);
                for (algs) |a| try d.u16_(a);
                var salt: [32]u8 = undefined;
                c.io.random(&salt);
                try d.bytes(&salt);
                try putContext(&b, proto.NegCtx.preauth_integrity, d.items());
                count += 1;
            }
        }
        inline for (.{
            .{ proto.NegCtx.encryption, o.ciphers },
            .{ proto.NegCtx.signing, o.signing_algs },
        }) |pair| {
            if (pair[1]) |ids| {
                var d = Msg.init(c.gpa);
                defer d.deinit();
                try d.u16_(@intCast(ids.len));
                for (ids) |a| try d.u16_(a);
                try putContext(&b, pair[0], d.items());
                count += 1;
            }
        }
        b.set16(ctx_count, count);
        return c.build(.{ .command = @intFromEnum(proto.Command.negotiate), .credits = 1, .credit_charge = 0, .message_id = o.message_id, .body = b.items() });
    }

    /// Sends a NEGOTIATE for `o` and returns the response. On success it
    /// records what was settled and starts the preauthentication hash.
    pub fn negotiate(c: *Client, o: NegotiateOptions) !Reply {
        const frame = try c.negotiateFrame(o);
        defer c.gpa.free(frame);
        if (o.message_id) |id| c.next_id = id + 1;
        try c.sendRaw(frame);
        const r = try c.recv();
        errdefer r.deinit();
        if (r.status() == proto.Status.success and r.raw.len >= hdr + 64) {
            c.parseNegotiate(r);
            if (c.neg.dialect == proto.Dialect.smb311) {
                c.preauth = @splat(0);
                crypto.preauthExtend(&c.preauth, frame);
                crypto.preauthExtend(&c.preauth, r.raw);
            }
        }
        return r;
    }

    fn parseNegotiate(c: *Client, r: Reply) void {
        const b = r.raw;
        var n: Negotiated = .{
            .security_mode = get16(b, hdr + 2),
            .dialect = get16(b, hdr + 4),
            .capabilities = get32(b, hdr + 24),
            .max_transact = get32(b, hdr + 28),
            .max_read = get32(b, hdr + 32),
            .max_write = get32(b, hdr + 36),
            .credits = r.credits(),
        };
        @memcpy(&n.guid, b[hdr + 8 ..][0..16]);
        if (r.at(get16(b, hdr + 56), get16(b, hdr + 58))) |sec| n.spnego = sec.len > 0 and sec[0] == 0x60;
        var pos: usize = get32(b, hdr + 60);
        for (0..get16(b, hdr + 6)) |_| {
            pos = std.mem.alignForward(usize, pos, 8);
            const head = r.at(pos, 8) orelse break;
            const data = r.at(pos + 8, get16(head, 2)) orelse break;
            pos += 8 + data.len;
            switch (get16(head, 0)) {
                proto.NegCtx.preauth_integrity => if (data.len >= 6) {
                    n.preauth_alg = get16(data, 4);
                },
                proto.NegCtx.encryption => if (data.len >= 4) {
                    n.cipher = get16(data, 2);
                },
                proto.NegCtx.signing => if (data.len >= 4) {
                    n.signing_alg = get16(data, 2);
                },
                else => {},
            }
        }
        c.neg = n;
    }

    // ------------------------------------------------------------ SESSION_SETUP

    fn setupFrame(c: *Client, session_id: u64, security_mode: u16, token: []const u8) ![]u8 {
        var b = Msg.init(c.gpa);
        defer b.deinit();
        try b.u16_(25);
        try b.u8_(0); // Flags
        try b.u8_(@intCast(security_mode));
        try b.u32_(0); // Capabilities
        try b.u32_(0); // Channel
        try b.u16_(hdr + 24);
        try b.u16_(@intCast(token.len));
        try b.u64_(0); // PreviousSessionId
        try b.bytes(token);
        return c.build(.{ .command = @intFromEnum(proto.Command.session_setup), .session_id = session_id, .sign = false, .body = b.items() });
    }

    /// Logs on with NTLMv2 through SPNEGO. The result is the second
    /// response's status; on success the client holds the session and its
    /// signing key. `user` is ASCII.
    pub fn login(c: *Client, user: []const u8, password: []const u8) !LoginResult {
        const gpa = c.gpa;
        const mode: u16 = proto.SecurityMode.signing_enabled;

        // Leg 1: NegTokenInit carrying the NTLM NEGOTIATE.
        var nm: [32]u8 = @splat(0);
        @memcpy(nm[0..8], "NTLMSSP\x00");
        std.mem.writeInt(u32, nm[8..12], 1, .little);
        std.mem.writeInt(u32, nm[12..16], ntlm_flags, .little);
        const init_tok = try negTokenInit(gpa, &nm);
        defer gpa.free(init_tok);
        const f1 = try c.setupFrame(0, mode, init_tok);
        defer gpa.free(f1);
        try c.sendRaw(f1);
        const r1 = try c.recv();
        defer r1.deinit();
        if (r1.status() != proto.Status.more_processing_required) return .{ .status = r1.status() };
        const sid = r1.sessionId();
        crypto.preauthExtend(&c.preauth, f1);
        crypto.preauthExtend(&c.preauth, r1.raw);

        const sec = r1.at(get16(r1.raw, hdr + 4), get16(r1.raw, hdr + 6)) orelse return error.BadSecurityBuffer;
        const at = std.mem.indexOf(u8, sec, "NTLMSSP\x00") orelse return error.NoChallenge;
        const chal = sec[at..];

        // Leg 2: the NTLM AUTHENTICATE and the SPNEGO mechListMIC.
        var session_key: [16]u8 = undefined;
        const auth = try c.ntlmAuthenticate(chal, user, password, &session_key);
        defer gpa.free(auth);
        const mic = ntlmMic(&session_key, &mech_types);
        const resp_tok = try negTokenResp(gpa, auth, &mic);
        defer gpa.free(resp_tok);
        const f2 = try c.setupFrame(sid, mode, resp_tok);
        defer gpa.free(f2);
        try c.sendRaw(f2);
        crypto.preauthExtend(&c.preauth, f2);

        // The keys come from the hash through the second request; check the
        // response's signature once they exist.
        const raw = try c.recvFrame();
        const r2: Reply = .{ .gpa = gpa, .raw = raw };
        defer r2.deinit();
        if (r2.raw.len < hdr) return error.ShortReply;
        c.credits +|= r2.credits();
        var res: LoginResult = .{ .status = r2.status(), .signed = r2.signed() };
        if (r2.status() == proto.Status.success) {
            res.session_flags = get16(r2.raw, hdr + 2);
            c.session_id = sid;
            c.session_key = session_key;
            c.signing_key = crypto.kdf(&session_key, "SMBSigningKey\x00", &c.preauth);
            if (r2.signed() and !std.crypto.timing_safe.eql([16]u8, crypto.cmacSigZeroed(&c.signing_key.?, r2.raw), r2.raw[48..64].*))
                return error.BadSignature;
        } else {
            crypto.preauthExtend(&c.preauth, r2.raw);
        }
        return res;
    }

    fn ntlmAuthenticate(c: *Client, chal: []const u8, user: []const u8, password: []const u8, key_out: *[16]u8) ![]u8 {
        const gpa = c.gpa;
        if (chal.len < 48 or get32(chal, 8) != 2) return error.NoChallenge;
        const ti_len = get16(chal, 40);
        const ti_off = get32(chal, 44);
        if (ti_off > chal.len or ti_len > chal.len - ti_off) return error.NoChallenge;
        const target_info = chal[ti_off..][0..ti_len];

        var dom = Msg.init(gpa);
        defer dom.deinit();
        _ = try dom.utf16("WORKGROUP");
        var usr = Msg.init(gpa);
        defer usr.deinit();
        _ = try usr.utf16(user);
        const up = try gpa.dupe(u8, user);
        defer gpa.free(up);
        for (up) |*ch| ch.* = std.ascii.toUpper(ch.*);
        var up16 = Msg.init(gpa);
        defer up16.deinit();
        _ = try up16.utf16(up);

        // MS-NLMP 3.3.2: NTOWFv2, the blob, the proof, and the session keys.
        const nth = try crypto.ntHash(gpa, password);
        var owf: [16]u8 = undefined;
        var h = HmacMd5.init(&nth);
        h.update(up16.items());
        h.update(dom.items());
        h.final(&owf);
        var client_chal: [8]u8 = undefined;
        c.io.random(&client_chal);
        var blob = Msg.init(gpa);
        defer blob.deinit();
        try blob.bytes(&.{ 1, 1, 0, 0, 0, 0, 0, 0 });
        try blob.u64_(0); // Timestamp
        try blob.bytes(&client_chal);
        try blob.u32_(0);
        try blob.bytes(target_info);
        try blob.u32_(0);
        var proof: [16]u8 = undefined;
        var h2 = HmacMd5.init(&owf);
        h2.update(chal[24..32]);
        h2.update(blob.items());
        h2.final(&proof);
        var base: [16]u8 = undefined;
        HmacMd5.create(&base, &proof, &owf);
        c.io.random(key_out);
        var enc = key_out.*;
        var rc = crypto.Rc4.init(&base);
        rc.apply(&enc);

        var nt = Msg.init(gpa);
        defer nt.deinit();
        try nt.bytes(&proof);
        try nt.bytes(blob.items());

        var m = Msg.init(gpa);
        errdefer m.deinit();
        try m.bytes("NTLMSSP\x00");
        try m.u32_(3);
        const parts = [_][]const u8{ &.{}, nt.items(), dom.items(), usr.items(), &.{}, &enc };
        var off: u32 = 64;
        for (parts) |p| {
            try m.u16_(@intCast(p.len));
            try m.u16_(@intCast(p.len));
            try m.u32_(off);
            off += @intCast(p.len);
        }
        try m.u32_(ntlm_flags);
        for (parts) |p| try m.bytes(p);
        return m.toOwned();
    }

    // ------------------------------------------------------------ session and tree commands

    /// TREE_CONNECT to `\\host\share`.
    pub fn treeConnect(c: *Client, host: []const u8, share: []const u8) !Reply {
        const unc = try std.fmt.allocPrint(c.gpa, "\\\\{s}\\{s}", .{ host, share });
        defer c.gpa.free(unc);
        return c.treeConnectPath(unc);
    }

    /// TREE_CONNECT to a path as given.
    pub fn treeConnectPath(c: *Client, path: []const u8) !Reply {
        const body = try treeConnectBody(c.gpa, path);
        defer c.gpa.free(body);
        return c.call(.{ .command = @intFromEnum(proto.Command.tree_connect), .session_id = c.session_id, .body = body });
    }

    pub fn treeDisconnect(c: *Client, tree_id: u32) !Reply {
        return c.call(.{ .command = @intFromEnum(proto.Command.tree_disconnect), .session_id = c.session_id, .tree_id = tree_id, .body = &.{ 4, 0, 0, 0 } });
    }

    pub fn logoff(c: *Client) !Reply {
        return c.call(.{ .command = @intFromEnum(proto.Command.logoff), .session_id = c.session_id, .body = &.{ 4, 0, 0, 0 } });
    }

    pub fn echo(c: *Client) !Reply {
        return c.call(.{ .command = @intFromEnum(proto.Command.echo), .session_id = c.session_id, .body = &.{ 4, 0, 0, 0 } });
    }

    // ------------------------------------------------------------ trace

    /// The recent frames as one line each, for a failure report.
    pub fn writeTrace(c: *Client, w: *Io.Writer) !void {
        for (c.trace.items) |t| {
            const b = t.bytes;
            if (b.len < hdr or !std.mem.eql(u8, b[0..4], &proto.protocol_id)) {
                try w.print("    {s} {d} bytes, not an SMB2 frame\n", .{ if (t.out) "->" else "<-", b.len });
                continue;
            }
            const cmd: proto.Command = @enumFromInt(get16(b, 12));
            const st = get32(b, 8);
            try w.print("    {s} {s} id={d} credits={d} flags=0x{x} tree={d} session=0x{x}", .{
                if (t.out) "->" else "<-",
                @tagName(cmd),
                get64(b, 24),
                get16(b, 14),
                get32(b, 16),
                get32(b, 36),
                get64(b, 40),
            });
            if (!t.out) try w.print(" status=0x{x:0>8} {s}", .{ st, proto.Status.name(st) });
            try w.print(" ({d} bytes)\n", .{b.len});
        }
    }
};

/// The body of a TREE_CONNECT request for `path`.
pub fn treeConnectBody(gpa: Allocator, path: []const u8) ![]u8 {
    var b = Msg.init(gpa);
    errdefer b.deinit();
    try b.u16_(9);
    try b.u16_(0); // Flags
    try b.u16_(hdr + 8);
    const len_pos = b.len();
    try b.u16_(0);
    const n = try b.utf16(path);
    b.set16(len_pos, @intCast(n));
    return b.toOwned();
}

// ---------------------------------------------------------------- contexts

fn putContext(out: *Msg, ctx_type: u16, data: []const u8) !void {
    try out.alignTo(8);
    try out.u16_(ctx_type);
    try out.u16_(@intCast(data.len));
    try out.u32_(0);
    try out.bytes(data);
}

// ---------------------------------------------------------------- SPNEGO and NTLM

/// DER of the mechanism list: SEQUENCE { NTLMSSP }.
const mech_types = [_]u8{ 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
const oid_spnego = [_]u8{ 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

const ntlm_flags: u32 = 0x00000001 | // unicode
    0x00000004 | // request target
    0x00000010 | // sign
    0x00000200 | // ntlm
    0x00008000 | // always sign
    0x00080000 | // extended session security
    0x20000000 | // 128-bit
    0x40000000; // key exchange

fn der(m: *Msg, tag: u8, content: []const u8) !void {
    try m.u8_(tag);
    if (content.len < 0x80) {
        try m.u8_(@intCast(content.len));
    } else if (content.len < 0x10000) {
        try m.u8_(0x82);
        try m.u8_(@intCast(content.len >> 8));
        try m.u8_(@intCast(content.len & 0xff));
    } else return error.TokenTooLong;
    try m.bytes(content);
}

fn wrap(gpa: Allocator, tag: u8, content: []const u8) ![]u8 {
    var m = Msg.init(gpa);
    errdefer m.deinit();
    try der(&m, tag, content);
    return m.toOwned();
}

/// NegTokenInit offering NTLMSSP with `token` as the optimistic mechToken.
fn negTokenInit(gpa: Allocator, token: []const u8) ![]u8 {
    const octets = try wrap(gpa, 0x04, token);
    defer gpa.free(octets);
    const a0 = try wrap(gpa, 0xa0, &mech_types);
    defer gpa.free(a0);
    const a2 = try wrap(gpa, 0xa2, octets);
    defer gpa.free(a2);
    const parts = try std.mem.concat(gpa, u8, &.{ a0, a2 });
    defer gpa.free(parts);
    const seq = try wrap(gpa, 0x30, parts);
    defer gpa.free(seq);
    const init_ = try wrap(gpa, 0xa0, seq);
    defer gpa.free(init_);
    const all = try std.mem.concat(gpa, u8, &.{ &oid_spnego, init_ });
    defer gpa.free(all);
    return wrap(gpa, 0x60, all);
}

/// NegTokenResp (accept-incomplete) carrying `token` and `mic`.
fn negTokenResp(gpa: Allocator, token: []const u8, mic: []const u8) ![]u8 {
    const state = try wrap(gpa, 0xa0, &.{ 0x0a, 0x01, 0x01 });
    defer gpa.free(state);
    const t_octets = try wrap(gpa, 0x04, token);
    defer gpa.free(t_octets);
    const t = try wrap(gpa, 0xa2, t_octets);
    defer gpa.free(t);
    const m_octets = try wrap(gpa, 0x04, mic);
    defer gpa.free(m_octets);
    const m = try wrap(gpa, 0xa3, m_octets);
    defer gpa.free(m);
    const all = try std.mem.concat(gpa, u8, &.{ state, t, m });
    defer gpa.free(all);
    const seq = try wrap(gpa, 0x30, all);
    defer gpa.free(seq);
    return wrap(gpa, 0xa1, seq);
}

/// The NTLM signature of `msg` with sequence number 0 (MS-NLMP 3.4.4.2),
/// client to server: the SPNEGO mechListMIC.
fn ntlmMic(session_key: *const [16]u8, msg: []const u8) [16]u8 {
    var sign_key: [16]u8 = undefined;
    var seal_key: [16]u8 = undefined;
    var md = Md5.init(.{});
    md.update(session_key);
    md.update("session key to client-to-server signing key magic constant\x00");
    md.final(&sign_key);
    md = Md5.init(.{});
    md.update(session_key);
    md.update("session key to client-to-server sealing key magic constant\x00");
    md.final(&seal_key);
    var h = HmacMd5.init(&sign_key);
    h.update(&.{ 0, 0, 0, 0 });
    h.update(msg);
    var full: [16]u8 = undefined;
    h.final(&full);
    var out: [16]u8 = @splat(0);
    out[0] = 1;
    @memcpy(out[4..12], full[0..8]);
    var rc = crypto.Rc4.init(&seal_key);
    rc.apply(out[4..12]);
    return out;
}

test "DER lengths" {
    var m = Msg.init(std.testing.allocator);
    defer m.deinit();
    try der(&m, 0x04, "abc");
    try std.testing.expectEqualSlices(u8, &.{ 0x04, 3, 'a', 'b', 'c' }, m.items());
    const big = try std.testing.allocator.alloc(u8, 300);
    defer std.testing.allocator.free(big);
    m.list.clearRetainingCapacity();
    try der(&m, 0x04, big);
    try std.testing.expectEqualSlices(u8, &.{ 0x04, 0x82, 0x01, 0x2c }, m.items()[0..4]);
}

test "NegTokenInit starts with the SPNEGO OID" {
    const t = try negTokenInit(std.testing.allocator, "NTLMSSP\x00");
    defer std.testing.allocator.free(t);
    try std.testing.expectEqual(@as(u8, 0x60), t[0]);
    try std.testing.expect(std.mem.indexOf(u8, t, &oid_spnego) != null);
}
