//! NTLMSSP server side (MS-NLMP): CHALLENGE generation and NTLMv2 verification.

const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("../../shared/wire.zig");
const crypto = @import("../../shared/crypto.zig");
const HmacMd5 = std.crypto.auth.hmac.HmacMd5;
const Md5 = std.crypto.hash.Md5;

pub const Flag = struct {
    pub const unicode: u32 = 0x00000001;
    pub const oem: u32 = 0x00000002;
    pub const request_target: u32 = 0x00000004;
    pub const sign: u32 = 0x00000010;
    pub const seal: u32 = 0x00000020;
    pub const lm_key: u32 = 0x00000080;
    pub const ntlm: u32 = 0x00000200;
    pub const anonymous: u32 = 0x00000800;
    pub const always_sign: u32 = 0x00008000;
    pub const target_type_domain: u32 = 0x00010000;
    pub const target_type_server: u32 = 0x00020000;
    pub const extended_session_security: u32 = 0x00080000;
    pub const target_info: u32 = 0x00800000;
    pub const version: u32 = 0x02000000;
    pub const n128: u32 = 0x20000000;
    pub const key_exch: u32 = 0x40000000;
    pub const n56: u32 = 0x80000000;
};

const supported = Flag.unicode | Flag.request_target | Flag.sign | Flag.seal | Flag.ntlm |
    Flag.always_sign | Flag.extended_session_security | Flag.target_info | Flag.version |
    Flag.n128 | Flag.key_exch | Flag.n56;

pub const Server = struct {
    gpa: Allocator,
    challenge: [8]u8 = undefined,
    flags: u32 = 0,
    negotiate_msg: []u8 = &.{},
    challenge_msg: []u8 = &.{},

    pub fn deinit(s: *Server) void {
        s.gpa.free(s.negotiate_msg);
        s.gpa.free(s.challenge_msg);
        s.* = undefined;
    }

    /// Consumes a NEGOTIATE_MESSAGE and returns a CHALLENGE_MESSAGE (owned by `s`).
    pub fn challengeFor(s: *Server, io: std.Io, negotiate: []const u8, nb_name: []const u8, nb_domain: []const u8, dns_name: []const u8, now_nt: u64) ![]const u8 {
        if (negotiate.len < 16 or !std.mem.eql(u8, negotiate[0..8], "NTLMSSP\x00") or wire.get32(negotiate, 8) != 1)
            return error.Malformed;
        const cflags = wire.get32(negotiate, 12);
        s.negotiate_msg = try s.gpa.dupe(u8, negotiate);
        io.random(&s.challenge);

        var flags = (cflags & supported) | Flag.target_type_server | Flag.target_info | Flag.ntlm | Flag.unicode;
        if (cflags & Flag.extended_session_security == 0) flags &= ~Flag.extended_session_security;
        if (cflags & Flag.version == 0) flags &= ~Flag.version;
        flags |= Flag.extended_session_security;
        s.flags = flags;

        var tinfo = wire.Buf.init(s.gpa);
        defer tinfo.deinit();
        try avPair(&tinfo, 2, nb_domain);
        try avPair(&tinfo, 1, nb_name);
        try avPair(&tinfo, 4, dns_name);
        try avPair(&tinfo, 3, dns_name);
        try tinfo.u16_(7);
        try tinfo.u16_(8);
        try tinfo.u64_(now_nt);
        try tinfo.u32_(0); // MsvAvEOL

        var b = wire.Buf.init(s.gpa);
        errdefer b.deinit();
        try b.bytes("NTLMSSP\x00");
        try b.u32_(2);
        const tn_len = wire.utf16Len(nb_name);
        try b.u16_(@intCast(tn_len));
        try b.u16_(@intCast(tn_len));
        try b.u32_(56);
        try b.u32_(flags);
        try b.bytes(&s.challenge);
        try b.zeros(8);
        try b.u16_(@intCast(tinfo.len()));
        try b.u16_(@intCast(tinfo.len()));
        try b.u32_(@intCast(56 + tn_len));
        // Version: 10.0 build 20348, NTLM revision 15.
        try b.bytes(&.{ 10, 0, 0x7C, 0x4F, 0, 0, 0, 15 });
        _ = try b.utf16(nb_name);
        try b.bytes(tinfo.items());
        s.challenge_msg = try b.list.toOwnedSlice(s.gpa);
        return s.challenge_msg;
    }
};

fn avPair(b: *wire.Buf, id: u16, val: []const u8) !void {
    try b.u16_(id);
    try b.u16_(@intCast(wire.utf16Len(val)));
    _ = try b.utf16(val);
}

pub const AuthResult = struct {
    user: []u8,
    domain: []u8,
    workstation: []u8,
    anonymous: bool,
    session_key: [16]u8,
    flags: u32,

    pub fn deinit(r: *AuthResult, gpa: Allocator) void {
        gpa.free(r.user);
        gpa.free(r.domain);
        gpa.free(r.workstation);
    }

    pub fn signKey(r: *const AuthResult, client: bool) [16]u8 {
        return deriveKey(&r.session_key, if (client)
            "session key to client-to-server signing key magic constant\x00"
        else
            "session key to server-to-client signing key magic constant\x00");
    }
    pub fn sealKey(r: *const AuthResult, client: bool) [16]u8 {
        return deriveKey(&r.session_key, if (client)
            "session key to client-to-server sealing key magic constant\x00"
        else
            "session key to server-to-client sealing key magic constant\x00");
    }

    /// NTLM message signature (MS-NLMP 3.4.4.2) with sequence number 0,
    /// as used for the SPNEGO mechListMIC.
    pub fn mic(r: *const AuthResult, client: bool, msg: []const u8) [16]u8 {
        const sk = r.signKey(client);
        var h = HmacMd5.init(&sk);
        h.update(&.{ 0, 0, 0, 0 });
        h.update(msg);
        var full: [16]u8 = undefined;
        h.final(&full);
        var out: [16]u8 = undefined;
        wire.put32(&out, 0, 1);
        @memcpy(out[4..12], full[0..8]);
        if (r.flags & Flag.key_exch != 0) {
            var rc = crypto.Rc4.init(&r.sealKey(client));
            rc.apply(out[4..12]);
        }
        wire.put32(&out, 12, 0);
        return out;
    }
};

fn deriveKey(key: *const [16]u8, magic: []const u8) [16]u8 {
    var h = Md5.init(.{});
    h.update(key);
    h.update(magic);
    var out: [16]u8 = undefined;
    h.final(&out);
    return out;
}

fn field(msg: []const u8, off: usize) ![]const u8 {
    if (msg.len < off + 8) return error.Malformed;
    const len = wire.get16(msg, off);
    const o = wire.get32(msg, off + 4);
    return wire.slice(msg, o, len);
}

pub const LookupError = error{ NoSuchUser, OutOfMemory };

/// The user name (UTF-8) of an AUTHENTICATE message, for logging; null when
/// the message is malformed. The caller frees the result.
pub fn userName(gpa: Allocator, msg: []const u8) ?[]u8 {
    if (msg.len < 64 or !std.mem.eql(u8, msg[0..8], "NTLMSSP\x00") or wire.get32(msg, 8) != 3) return null;
    const raw = field(msg, 36) catch return null;
    return wire.utf16ToUtf8(gpa, raw) catch null;
}

/// `lookup` receives the user name (UTF-8) and returns the 16-byte NT hash.
const av_flag_mic: u32 = 0x00000002;
/// Offset of the MIC in an AUTHENTICATE message, after the version.
const mic_off = 72;
const mic_end = 88;

/// The MsvAvFlags value among the AV pairs of an NTLMv2 blob (0 if none).
fn avFlags(pairs: []const u8) u32 {
    var i: usize = 0;
    while (i + 4 <= pairs.len) {
        const id = wire.get16(pairs, i);
        const len = wire.get16(pairs, i + 2);
        i += 4;
        if (id == 0 or i + len > pairs.len) return 0;
        if (id == 6 and len == 4) return wire.get32(pairs, i);
        i += len;
    }
    return 0;
}

/// Whether the AUTHENTICATE MIC matches HMAC_MD5(ExportedSessionKey,
/// NEGOTIATE || CHALLENGE || AUTHENTICATE with a zeroed MIC).
fn validMic(s: *const Server, msg: []const u8, key: *const [16]u8) bool {
    if (msg.len < mic_end or s.negotiate_msg.len == 0 or s.challenge_msg.len == 0) return false;
    var want: [16]u8 = undefined;
    var h = HmacMd5.init(key);
    h.update(s.negotiate_msg);
    h.update(s.challenge_msg);
    h.update(msg[0..mic_off]);
    h.update(&@as([16]u8, @splat(0)));
    h.update(msg[mic_end..]);
    h.final(&want);
    return std.crypto.timing_safe.eql([16]u8, want, msg[mic_off..mic_end][0..16].*);
}

pub fn authenticate(
    s: *Server,
    msg: []const u8,
    lookup_ctx: anytype,
    comptime lookup: fn (@TypeOf(lookup_ctx), []const u8) LookupError![16]u8,
) !AuthResult {
    const gpa = s.gpa;
    if (msg.len < 64 or !std.mem.eql(u8, msg[0..8], "NTLMSSP\x00") or wire.get32(msg, 8) != 3)
        return error.Malformed;
    const lm = try field(msg, 12);
    const nt = try field(msg, 20);
    const dom_raw = try field(msg, 28);
    const user_raw = try field(msg, 36);
    const ws_raw = try field(msg, 44);
    const enc_key = try field(msg, 52);
    const flags = wire.get32(msg, 60);

    const user = try wire.utf16ToUtf8(gpa, user_raw);
    errdefer gpa.free(user);
    const domain = try wire.utf16ToUtf8(gpa, dom_raw);
    errdefer gpa.free(domain);
    const ws = try wire.utf16ToUtf8(gpa, ws_raw);
    errdefer gpa.free(ws);

    if (user.len == 0 and nt.len == 0 and (lm.len == 0 or (lm.len == 1 and lm[0] == 0))) {
        return .{ .user = user, .domain = domain, .workstation = ws, .anonymous = true, .session_key = @splat(0), .flags = flags };
    }
    if (nt.len < 16 + 28) return error.LogonFailure; // NTLMv1 / LM are refused.

    const nt_hash = lookup(lookup_ctx, user) catch |e| switch (e) {
        error.NoSuchUser => return error.LogonFailure,
        else => |x| return x,
    };

    const user_up = try wire.upperUtf16(gpa, user);
    defer gpa.free(user_up);

    // Try the domain as sent, then upper-cased, then empty (client variations).
    const dom_up = try wire.upperUtf16(gpa, domain);
    defer gpa.free(dom_up);
    const candidates = [_][]const u8{ dom_raw, dom_up, &.{} };
    const proof = nt[0..16];
    const blob = nt[16..];
    for (candidates) |dom| {
        var owf: [16]u8 = undefined;
        var h = HmacMd5.init(&nt_hash);
        h.update(user_up);
        h.update(dom);
        h.final(&owf);

        var calc: [16]u8 = undefined;
        var h2 = HmacMd5.init(&owf);
        h2.update(&s.challenge);
        h2.update(blob);
        h2.final(&calc);
        if (!std.crypto.timing_safe.eql([16]u8, calc, proof.*)) continue;

        var base: [16]u8 = undefined;
        HmacMd5.create(&base, proof, &owf);
        // The exported session key is the base key, unless the client
        // exchanged a random one (MS-NLMP 3.2.5.1.2): then it must have
        // sent one, and it is used when signing or sealing was negotiated.
        var key = base;
        if (flags & Flag.key_exch != 0) {
            if (enc_key.len != 16) return error.Malformed;
            if (flags & (Flag.sign | Flag.seal) != 0) {
                @memcpy(&key, enc_key);
                var rc = crypto.Rc4.init(&base);
                rc.apply(&key);
            }
        }
        // A client that signs its messages says so in MsvAvFlags, and then
        // the MIC covers all three messages.
        if (avFlags(blob[28..]) & av_flag_mic != 0 and !validMic(s, msg, &key)) return error.LogonFailure;
        return .{ .user = user, .domain = domain, .workstation = ws, .anonymous = false, .session_key = key, .flags = flags };
    }
    return error.LogonFailure;
}

// ------------------------------------------------------------------ tests

const TestLookup = struct {
    hash: [16]u8,
    fn get(self: *const TestLookup, name: []const u8) LookupError![16]u8 {
        if (!std.ascii.eqlIgnoreCase(name, "user")) return error.NoSuchUser;
        return self.hash;
    }
};

test "NTLMv2 verification (MS-NLMP 4.2.4 vectors)" {
    const gpa = std.testing.allocator;
    // MS-NLMP 4.2.4: User "User", Domain "Domain", Password "Password",
    // ServerChallenge 0123456789abcdef, client challenge aaaaaaaaaaaaaaaa, time 0.
    var s: Server = .{ .gpa = gpa, .challenge = crypto.hex("0123456789abcdef") };
    defer s.deinit();
    const lk: TestLookup = .{ .hash = try crypto.ntHash(gpa, "Password") };

    // temp = 0101 0000 00000000 time(0) clientchallenge 00000000 avpairs 00000000
    var blob = wire.Buf.init(gpa);
    defer blob.deinit();
    try blob.bytes(&.{ 1, 1, 0, 0, 0, 0, 0, 0 });
    try blob.zeros(8);
    try blob.bytes(&crypto.hex("aaaaaaaaaaaaaaaa"));
    try blob.zeros(4);
    // AV pairs from the spec: NbDomainName "Domain", NbComputerName "Server", EOL.
    try avPair(&blob, 2, "Domain");
    try avPair(&blob, 1, "Server");
    try blob.u32_(0);
    try blob.zeros(4);

    const user_up = try wire.upperUtf16(gpa, "User");
    defer gpa.free(user_up);
    var dom_list: std.ArrayList(u8) = .empty;
    defer dom_list.deinit(gpa);
    try wire.appendUtf16(gpa, &dom_list, "Domain");
    var owf: [16]u8 = undefined;
    var h = HmacMd5.init(&lk.hash);
    h.update(user_up);
    h.update(dom_list.items);
    h.final(&owf);
    try std.testing.expectEqualSlices(u8, &crypto.hex("0c868a403bfd7a93a3001ef22ef02e3f"), &owf);
    var proof: [16]u8 = undefined;
    var h2 = HmacMd5.init(&owf);
    h2.update(&s.challenge);
    h2.update(blob.items());
    h2.final(&proof);
    try std.testing.expectEqualSlices(u8, &crypto.hex("68cd0ab851e51c96aabc927bebef6a1c"), &proof);

    // Build an AUTHENTICATE message.
    var nt = wire.Buf.init(gpa);
    defer nt.deinit();
    try nt.bytes(&proof);
    try nt.bytes(blob.items());
    var m = wire.Buf.init(gpa);
    defer m.deinit();
    try m.bytes("NTLMSSP\x00");
    try m.u32_(3);
    const payload_off: u32 = 88;
    var off = payload_off;
    const parts = [_][]const u8{ &.{}, nt.items(), dom_list.items, &.{ 'U', 0, 's', 0, 'e', 0, 'r', 0 }, &.{}, &.{} };
    for (parts) |p| {
        try m.u16_(@intCast(p.len));
        try m.u16_(@intCast(p.len));
        try m.u32_(off);
        off += @intCast(p.len);
    }
    try m.u32_(Flag.unicode | Flag.extended_session_security | Flag.ntlm);
    try m.zeros(24);
    for (parts) |p| try m.bytes(p);
    var res = try authenticate(&s, m.items(), &lk, TestLookup.get);
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("User", res.user);
    try std.testing.expectEqualSlices(u8, &crypto.hex("8de40ccadbc14a82f15cb0ad0de95ca3"), &res.session_key);
}

/// An AUTHENTICATE message from user "User" (password "Password", domain
/// "Domain") as a client builds it. `av_flags` goes in MsvAvFlags; when it
/// has the MIC bit the MIC is filled in (and spoiled if `bad_mic`).
/// `exchange` makes the client send a random session key (0x33...) with
/// `key_len` bytes; the caller frees the result.
fn testAuthenticate(gpa: Allocator, s: *Server, flags: u32, av_flags: ?u32, bad_mic: bool, key_len: usize) ![]u8 {
    const hash = try crypto.ntHash(gpa, "Password");
    var dom: std.ArrayList(u8) = .empty;
    defer dom.deinit(gpa);
    try wire.appendUtf16(gpa, &dom, "Domain");
    var blob = wire.Buf.init(gpa);
    defer blob.deinit();
    try blob.bytes(&.{ 1, 1, 0, 0, 0, 0, 0, 0 });
    try blob.zeros(8);
    try blob.bytes(&crypto.hex("aaaaaaaaaaaaaaaa"));
    try blob.zeros(4);
    try avPair(&blob, 2, "Domain");
    if (av_flags) |f| {
        try blob.u16_(6);
        try blob.u16_(4);
        try blob.u32_(f);
    }
    try blob.u32_(0);
    try blob.zeros(4);

    const user_up = try wire.upperUtf16(gpa, "User");
    defer gpa.free(user_up);
    var owf: [16]u8 = undefined;
    var h = HmacMd5.init(&hash);
    h.update(user_up);
    h.update(dom.items);
    h.final(&owf);
    var proof: [16]u8 = undefined;
    var h2 = HmacMd5.init(&owf);
    h2.update(&s.challenge);
    h2.update(blob.items());
    h2.final(&proof);
    var base: [16]u8 = undefined;
    HmacMd5.create(&base, &proof, &owf);

    // What the client exports: the base key, or a random one it sends
    // encrypted under the base key.
    var exported = base;
    var sent: [16]u8 = @splat(0x33);
    if (flags & Flag.key_exch != 0) {
        exported = sent;
        var rc = crypto.Rc4.init(&base);
        rc.apply(&sent);
        if (flags & (Flag.sign | Flag.seal) == 0) exported = base;
    }

    var nt = wire.Buf.init(gpa);
    defer nt.deinit();
    try nt.bytes(&proof);
    try nt.bytes(blob.items());
    var m = wire.Buf.init(gpa);
    errdefer m.deinit();
    try m.bytes("NTLMSSP\x00");
    try m.u32_(3);
    const parts = [_][]const u8{ &.{}, nt.items(), dom.items, &.{ 'U', 0, 's', 0, 'e', 0, 'r', 0 }, &.{}, sent[0..key_len] };
    var off: u32 = mic_end;
    for (parts) |p| {
        try m.u16_(@intCast(p.len));
        try m.u16_(@intCast(p.len));
        try m.u32_(off);
        off += @intCast(p.len);
    }
    try m.u32_(flags);
    try m.zeros(24);
    for (parts) |p| try m.bytes(p);
    const out = try m.list.toOwnedSlice(gpa);
    if (av_flags) |f| if (f & av_flag_mic != 0) {
        var mic: [16]u8 = undefined;
        var hm = HmacMd5.init(&exported);
        hm.update(s.negotiate_msg);
        hm.update(s.challenge_msg);
        hm.update(out);
        hm.final(&mic);
        @memcpy(out[mic_off..mic_end], &mic);
        if (bad_mic) out[mic_off] ^= 1;
    };
    return out;
}

fn testServer(gpa: Allocator) !Server {
    return .{
        .gpa = gpa,
        .challenge = crypto.hex("0123456789abcdef"),
        .negotiate_msg = try gpa.dupe(u8, "NTLMSSP-negotiate"),
        .challenge_msg = try gpa.dupe(u8, "NTLMSSP-challenge"),
    };
}

test "the AUTHENTICATE MIC is verified when the client says it sent one" {
    const gpa = std.testing.allocator;
    var s = try testServer(gpa);
    defer s.deinit();
    const lk: TestLookup = .{ .hash = try crypto.ntHash(gpa, "Password") };
    const plain = Flag.unicode | Flag.extended_session_security | Flag.ntlm;

    const good = try testAuthenticate(gpa, &s, plain, av_flag_mic, false, 16);
    defer gpa.free(good);
    var res = try authenticate(&s, good, &lk, TestLookup.get);
    res.deinit(gpa);

    const bad = try testAuthenticate(gpa, &s, plain, av_flag_mic, true, 16);
    defer gpa.free(bad);
    try std.testing.expectError(error.LogonFailure, authenticate(&s, bad, &lk, TestLookup.get));

    // A different NEGOTIATE than the one the MIC covers.
    gpa.free(s.negotiate_msg);
    s.negotiate_msg = try gpa.dupe(u8, "NTLMSSP-tampered");
    try std.testing.expectError(error.LogonFailure, authenticate(&s, good, &lk, TestLookup.get));

    // No MIC claimed, none checked.
    const none = try testAuthenticate(gpa, &s, plain, null, false, 16);
    defer gpa.free(none);
    var r2 = try authenticate(&s, none, &lk, TestLookup.get);
    r2.deinit(gpa);
}

test "a random session key is exchanged only with signing or sealing" {
    const gpa = std.testing.allocator;
    var s = try testServer(gpa);
    defer s.deinit();
    const lk: TestLookup = .{ .hash = try crypto.ntHash(gpa, "Password") };
    const plain = Flag.unicode | Flag.extended_session_security | Flag.ntlm;
    const random: [16]u8 = @splat(0x33);

    const signed = try testAuthenticate(gpa, &s, plain | Flag.key_exch | Flag.sign, av_flag_mic, false, 16);
    defer gpa.free(signed);
    var r1 = try authenticate(&s, signed, &lk, TestLookup.get);
    defer r1.deinit(gpa);
    try std.testing.expectEqualSlices(u8, &random, &r1.session_key);

    // Key exchange without sign or seal keeps the base key.
    const unsigned = try testAuthenticate(gpa, &s, plain | Flag.key_exch, av_flag_mic, false, 16);
    defer gpa.free(unsigned);
    var r2 = try authenticate(&s, unsigned, &lk, TestLookup.get);
    defer r2.deinit(gpa);
    try std.testing.expect(!std.mem.eql(u8, &random, &r2.session_key));

    // Key exchange needs a key of 16 bytes.
    const short = try testAuthenticate(gpa, &s, plain | Flag.key_exch | Flag.sign, null, false, 8);
    defer gpa.free(short);
    try std.testing.expectError(error.Malformed, authenticate(&s, short, &lk, TestLookup.get));
}

/// A minimal AUTHENTICATE message for user "user" with an NTLMv2-sized
/// response, as a fuzz seed.
fn seedAuthenticate(gpa: Allocator) ![]u8 {
    var m = wire.Buf.init(gpa);
    errdefer m.deinit();
    try m.bytes("NTLMSSP\x00");
    try m.u32_(3);
    const user = [_]u8{ 'u', 0, 's', 0, 'e', 0, 'r', 0 };
    const nt: [60]u8 = @splat(0x11);
    const key: [16]u8 = @splat(0x22);
    const parts = [_][]const u8{ &.{}, &nt, &.{ 'D', 0 }, &user, &.{}, &key };
    var off: u32 = 88;
    for (parts) |p| {
        try m.u16_(@intCast(p.len));
        try m.u16_(@intCast(p.len));
        try m.u32_(off);
        off += @intCast(p.len);
    }
    try m.u32_(Flag.unicode | Flag.extended_session_security | Flag.ntlm | Flag.key_exch);
    try m.zeros(24);
    for (parts) |p| try m.bytes(p);
    return m.list.toOwnedSlice(gpa);
}

test "fuzz: NEGOTIATE and AUTHENTICATE parsing" {
    const gpa = std.testing.allocator;
    const seed = try seedAuthenticate(gpa);
    defer gpa.free(seed);
    try @import("../../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            var s: Server = .{ .gpa = std.testing.allocator, .challenge = @splat(1) };
            defer s.deinit();
            _ = s.challengeFor(std.testing.io, in, "HAL", "WORKGROUP", "hal.local", 0) catch {};
            const lk: TestLookup = .{ .hash = @splat(3) };
            var r = authenticate(&s, in, &lk, TestLookup.get) catch return;
            r.deinit(std.testing.allocator);
        }
    }.one, &.{ seed, "NTLMSSP\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" });
}
