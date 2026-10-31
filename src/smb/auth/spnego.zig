//! Minimal SPNEGO (RFC 4178) DER encoding/decoding supporting the NTLMSSP mechanism.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Buf = @import("../../shared/wire.zig").Buf;

pub const oid_spnego = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
pub const oid_ntlmssp = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

pub const Tlv = struct {
    tag: u8,
    value: []const u8,
    /// Entire encoding including tag and length octets.
    raw: []const u8,
    rest: []const u8,
};

pub fn parseTlv(b: []const u8) error{Malformed}!Tlv {
    if (b.len < 2) return error.Malformed;
    const tag = b[0];
    var len: usize = b[1];
    var hdr: usize = 2;
    if (len & 0x80 != 0) {
        const n = len & 0x7f;
        if (n == 0 or n > 4 or b.len < 2 + n) return error.Malformed;
        len = 0;
        for (b[2 .. 2 + n]) |c| len = (len << 8) | c;
        hdr = 2 + n;
    }
    if (b.len - hdr < len) return error.Malformed;
    return .{ .tag = tag, .value = b[hdr .. hdr + len], .raw = b[0 .. hdr + len], .rest = b[hdr + len ..] };
}

pub const ClientToken = struct {
    /// The NTLMSSP message carried in the token.
    mech_token: []const u8 = &.{},
    /// DER encoding of the mechTypes SEQUENCE (needed for mechListMIC).
    mech_types_raw: []const u8 = &.{},
    mech_list_mic: []const u8 = &.{},
    /// True if the client wrapped the token in SPNEGO.
    spnego: bool = false,
    offers_ntlm: bool = false,
};

/// Accepts either a SPNEGO NegTokenInit/NegTokenResp or a raw NTLMSSP blob.
pub fn parseClientToken(b: []const u8) error{Malformed}!ClientToken {
    if (b.len >= 8 and std.mem.eql(u8, b[0..8], "NTLMSSP\x00")) {
        return .{ .mech_token = b, .offers_ntlm = true };
    }
    var out: ClientToken = .{ .spnego = true };
    const outer = try parseTlv(b);
    var body: []const u8 = undefined;
    if (outer.tag == 0x60) {
        // [APPLICATION 0] { OID spnego, [0] NegTokenInit }
        const oid = try parseTlv(outer.value);
        if (oid.tag != 0x06) return error.Malformed;
        const inner = try parseTlv(oid.rest);
        if (inner.tag != 0xa0) return error.Malformed;
        body = inner.value;
    } else if (outer.tag == 0xa1 or outer.tag == 0xa0) {
        body = outer.value;
    } else return error.Malformed;

    const seq = try parseTlv(body);
    if (seq.tag != 0x30) return error.Malformed;
    var it = seq.value;
    while (it.len > 0) {
        const f = try parseTlv(it);
        it = f.rest;
        switch (f.tag) {
            0xa0 => if (outer.tag != 0xa1) {
                // mechTypes (NegTokenInit) - for NegTokenResp [0] is negState.
                const list = try parseTlv(f.value);
                out.mech_types_raw = list.raw;
                var m = list.value;
                while (m.len > 0) {
                    const o = try parseTlv(m);
                    m = o.rest;
                    if (o.tag == 0x06 and std.mem.eql(u8, o.value, &oid_ntlmssp)) out.offers_ntlm = true;
                }
            },
            0xa2 => {
                const os = try parseTlv(f.value);
                if (os.tag != 0x04) return error.Malformed;
                out.mech_token = os.value;
                if (outer.tag == 0xa1) out.offers_ntlm = true;
            },
            0xa3 => {
                const os = try parseTlv(f.value);
                if (os.tag == 0x04) out.mech_list_mic = os.value;
            },
            else => {},
        }
    }
    if (outer.tag == 0xa1) out.offers_ntlm = true;
    return out;
}

fn putLen(b: *Buf, len: usize) !void {
    if (len < 0x80) {
        try b.u8_(@intCast(len));
    } else if (len <= 0xff) {
        try b.u8_(0x81);
        try b.u8_(@intCast(len));
    } else if (len <= 0xffff) {
        try b.u8_(0x82);
        try b.u16be(@intCast(len));
    } else {
        try b.u8_(0x84);
        try b.u32be(@intCast(len));
    }
}

fn tlv(gpa: Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |p| total += p.len;
    var b = Buf.init(gpa);
    errdefer b.deinit();
    try b.u8_(tag);
    try putLen(&b, total);
    for (parts) |p| try b.bytes(p);
    return b.list.toOwnedSlice(gpa);
}

/// mechTypes SEQUENCE advertising only NTLMSSP.
pub fn mechTypesNtlm(gpa: Allocator) ![]u8 {
    const oid = try tlv(gpa, 0x06, &.{&oid_ntlmssp});
    defer gpa.free(oid);
    return tlv(gpa, 0x30, &.{oid});
}

/// The initial NegTokenInit placed in the NEGOTIATE response security buffer.
pub fn negTokenInit(gpa: Allocator) ![]u8 {
    const types = try mechTypesNtlm(gpa);
    defer gpa.free(types);
    const a0 = try tlv(gpa, 0xa0, &.{types});
    defer gpa.free(a0);
    const hint_str = try tlv(gpa, 0x1b, &.{"not_defined_in_RFC4178@please_ignore"});
    defer gpa.free(hint_str);
    const hint_a0 = try tlv(gpa, 0xa0, &.{hint_str});
    defer gpa.free(hint_a0);
    const hint_seq = try tlv(gpa, 0x30, &.{hint_a0});
    defer gpa.free(hint_seq);
    const a3 = try tlv(gpa, 0xa3, &.{hint_seq});
    defer gpa.free(a3);
    const seq = try tlv(gpa, 0x30, &.{ a0, a3 });
    defer gpa.free(seq);
    const init_ = try tlv(gpa, 0xa0, &.{seq});
    defer gpa.free(init_);
    const oid = try tlv(gpa, 0x06, &.{&oid_spnego});
    defer gpa.free(oid);
    return tlv(gpa, 0x60, &.{ oid, init_ });
}

pub const NegState = enum(u8) { accept_completed = 0, accept_incomplete = 1, reject = 2 };

pub fn negTokenResp(gpa: Allocator, state: NegState, include_mech: bool, token: ?[]const u8, mic: ?[]const u8) ![]u8 {
    var parts: std.ArrayList([]u8) = .empty;
    defer {
        for (parts.items) |p| gpa.free(p);
        parts.deinit(gpa);
    }
    {
        const e = try tlv(gpa, 0x0a, &.{&[_]u8{@intFromEnum(state)}});
        defer gpa.free(e);
        try parts.append(gpa, try tlv(gpa, 0xa0, &.{e}));
    }
    if (include_mech) {
        const o = try tlv(gpa, 0x06, &.{&oid_ntlmssp});
        defer gpa.free(o);
        try parts.append(gpa, try tlv(gpa, 0xa1, &.{o}));
    }
    if (token) |t| {
        const o = try tlv(gpa, 0x04, &.{t});
        defer gpa.free(o);
        try parts.append(gpa, try tlv(gpa, 0xa2, &.{o}));
    }
    if (mic) |m| {
        const o = try tlv(gpa, 0x04, &.{m});
        defer gpa.free(o);
        try parts.append(gpa, try tlv(gpa, 0xa3, &.{o}));
    }
    const consts: []const []const u8 = @ptrCast(parts.items);
    const seq = try tlv(gpa, 0x30, consts);
    defer gpa.free(seq);
    return tlv(gpa, 0xa1, &.{seq});
}

test "negTokenInit parses back" {
    const gpa = std.testing.allocator;
    const t = try negTokenInit(gpa);
    defer gpa.free(t);
    const parsed = try parseClientToken(t);
    try std.testing.expect(parsed.offers_ntlm);
    const r = try negTokenResp(gpa, .accept_incomplete, true, "NTLMSSP\x00abc", null);
    defer gpa.free(r);
    const p2 = try parseClientToken(r);
    try std.testing.expectEqualStrings("NTLMSSP\x00abc", p2.mech_token);
}

test "fuzz: parseClientToken" {
    const gpa = std.testing.allocator;
    const init = try negTokenInit(gpa);
    defer gpa.free(init);
    const resp = try negTokenResp(gpa, .accept_incomplete, true, "NTLMSSP\x00\x03\x00\x00\x00", "0123456789abcdef");
    defer gpa.free(resp);
    try @import("../../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            const t = parseClientToken(in) catch return;
            // Every slice it returns lies inside the input.
            const lo = @intFromPtr(in.ptr);
            for ([_][]const u8{ t.mech_token, t.mech_types_raw, t.mech_list_mic }) |s| {
                if (s.len == 0) continue;
                try std.testing.expect(@intFromPtr(s.ptr) >= lo and @intFromPtr(s.ptr) + s.len <= lo + in.len);
            }
        }
    }.one, &.{ init, resp, "NTLMSSP\x00\x01\x00\x00\x00" });
}
