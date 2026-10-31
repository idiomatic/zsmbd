//! Cryptographic primitives needed by NTLM and SMB2/3 that are not in std:
//! MD4, RC4, AES-CCM with SMB's 11-byte nonce, and the SP800-108 KDF.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const CmacAes128 = std.crypto.auth.cmac.CmacAes128;
const Aes128 = std.crypto.core.aes.Aes128;

// ---------------------------------------------------------------- MD4 (RFC 1320)

pub fn md4(out: *[16]u8, msg: []const u8) void {
    var h = [4]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    var i: usize = 0;
    while (msg.len - i >= 64) : (i += 64) md4Block(&h, msg[i..][0..64]);
    // Final one or two blocks: remaining bytes, 0x80, zero pad, 64-bit length.
    var tail: [128]u8 = @splat(0);
    const rem = msg.len - i;
    @memcpy(tail[0..rem], msg[i..]);
    tail[rem] = 0x80;
    const tail_len: usize = if (rem < 56) 64 else 128;
    std.mem.writeInt(u64, tail[tail_len - 8 ..][0..8], @as(u64, msg.len) * 8, .little);
    md4Block(&h, tail[0..64]);
    if (tail_len == 128) md4Block(&h, tail[64..128]);
    for (h, 0..) |v, k| std.mem.writeInt(u32, out[k * 4 ..][0..4], v, .little);
}

fn md4Block(h: *[4]u32, block: *const [64]u8) void {
    var x: [16]u32 = undefined;
    for (&x, 0..) |*w, k| w.* = std.mem.readInt(u32, block[k * 4 ..][0..4], .little);
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    const F = struct {
        fn f(X: u32, Y: u32, Z: u32) u32 {
            return (X & Y) | (~X & Z);
        }
        fn g(X: u32, Y: u32, Z: u32) u32 {
            return (X & Y) | (X & Z) | (Y & Z);
        }
        fn hh(X: u32, Y: u32, Z: u32) u32 {
            return X ^ Y ^ Z;
        }
    };
    const r1 = [_]u5{ 3, 7, 11, 19 };
    inline for (0..16) |k| {
        const s = r1[k % 4];
        switch (k % 4) {
            0 => a = std.math.rotl(u32, a +% F.f(b, c, d) +% x[k], s),
            1 => d = std.math.rotl(u32, d +% F.f(a, b, c) +% x[k], s),
            2 => c = std.math.rotl(u32, c +% F.f(d, a, b) +% x[k], s),
            else => b = std.math.rotl(u32, b +% F.f(c, d, a) +% x[k], s),
        }
    }
    const r2 = [_]u5{ 3, 5, 9, 13 };
    const o2 = [_]usize{ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
    inline for (0..16) |k| {
        const s = r2[k % 4];
        const m = x[o2[k]] +% 0x5A827999;
        switch (k % 4) {
            0 => a = std.math.rotl(u32, a +% F.g(b, c, d) +% m, s),
            1 => d = std.math.rotl(u32, d +% F.g(a, b, c) +% m, s),
            2 => c = std.math.rotl(u32, c +% F.g(d, a, b) +% m, s),
            else => b = std.math.rotl(u32, b +% F.g(c, d, a) +% m, s),
        }
    }
    const r3 = [_]u5{ 3, 9, 11, 15 };
    const o3 = [_]usize{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
    inline for (0..16) |k| {
        const s = r3[k % 4];
        const m = x[o3[k]] +% 0x6ED9EBA1;
        switch (k % 4) {
            0 => a = std.math.rotl(u32, a +% F.hh(b, c, d) +% m, s),
            1 => d = std.math.rotl(u32, d +% F.hh(a, b, c) +% m, s),
            2 => c = std.math.rotl(u32, c +% F.hh(d, a, b) +% m, s),
            else => b = std.math.rotl(u32, b +% F.hh(c, d, a) +% m, s),
        }
    }
    h[0] +%= a;
    h[1] +%= b;
    h[2] +%= c;
    h[3] +%= d;
}

/// NT one-way function: MD4 of the UTF-16LE password.
pub fn ntHash(gpa: std.mem.Allocator, password: []const u8) ![16]u8 {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try @import("wire.zig").appendUtf16(gpa, &list, password);
    var out: [16]u8 = undefined;
    md4(&out, list.items);
    std.crypto.secureZero(u8, list.items);
    return out;
}

// ---------------------------------------------------------------- RC4

pub const Rc4 = struct {
    s: [256]u8,
    i: u8 = 0,
    j: u8 = 0,

    pub fn init(key: []const u8) Rc4 {
        var r: Rc4 = .{ .s = undefined };
        for (&r.s, 0..) |*v, k| v.* = @intCast(k);
        var j: u8 = 0;
        for (0..256) |k| {
            j = j +% r.s[k] +% key[k % key.len];
            std.mem.swap(u8, &r.s[k], &r.s[j]);
        }
        return r;
    }

    pub fn apply(r: *Rc4, data: []u8) void {
        for (data) |*b| {
            r.i +%= 1;
            r.j +%= r.s[r.i];
            std.mem.swap(u8, &r.s[r.i], &r.s[r.j]);
            b.* ^= r.s[r.s[r.i] +% r.s[r.j]];
        }
    }
};

// ---------------------------------------------------------------- SMB3 KDF

/// SP800-108 counter-mode KDF with HMAC-SHA256, producing a 128-bit key
/// (MS-SMB2 3.1.4.2). `label` and `context` include their NUL terminators.
pub fn kdf(key: []const u8, label: []const u8, context: []const u8) [16]u8 {
    var h = HmacSha256.init(key);
    h.update(&.{ 0, 0, 0, 1 });
    h.update(label);
    h.update(&.{0});
    h.update(context);
    h.update(&.{ 0, 0, 0, 128 });
    var out: [32]u8 = undefined;
    h.final(&out);
    return out[0..16].*;
}

pub fn hmacSha256Sig(key: []const u8, msg: []const u8) [16]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, msg, key);
    return out[0..16].*;
}

pub fn cmacSig(key: *const [16]u8, msg: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    CmacAes128.create(&out, msg, key);
    return out;
}

// ---------------------------------------------------------------- AES-128-CCM (16-byte tag)

pub const ccm_nonce_len = 11;

fn Ccm(comptime nl: usize) type {
    const L: u8 = 15 - nl;
    return struct {
        fn mac(ctx: anytype, nonce: *const [nl]u8, ad: []const u8, m: []const u8) [16]u8 {
            var b0: [16]u8 = @splat(0);
            b0[0] = (if (ad.len > 0) @as(u8, 0x40) else 0) | (((16 - 2) / 2) << 3) | (L - 1);
            @memcpy(b0[1 .. 1 + nl], nonce);
            var len = m.len;
            var k: usize = 15;
            while (k > nl) : (k -= 1) {
                b0[k] = @truncate(len);
                len >>= 8;
            }
            var x: [16]u8 = undefined;
            ctx.encrypt(&x, &b0);
            if (ad.len > 0) {
                var blk: [16]u8 = @splat(0);
                std.mem.writeInt(u16, blk[0..2], @intCast(ad.len), .big);
                var pos: usize = 2;
                var i: usize = 0;
                while (i < ad.len) {
                    const n = @min(16 - pos, ad.len - i);
                    @memcpy(blk[pos..][0..n], ad[i..][0..n]);
                    i += n;
                    pos += n;
                    if (pos == 16 or i == ad.len) {
                        for (&x, blk) |*a, b| a.* ^= b;
                        ctx.encrypt(&x, &x);
                        blk = @splat(0);
                        pos = 0;
                    }
                }
            }
            var i: usize = 0;
            while (i < m.len) {
                const n = @min(16, m.len - i);
                for (x[0..n], m[i..][0..n]) |*a, b| a.* ^= b;
                ctx.encrypt(&x, &x);
                i += n;
            }
            return x;
        }

        fn ctr(ctx: anytype, nonce: *const [nl]u8, out: []u8, in: []const u8) [16]u8 {
            var a: [16]u8 = @splat(0);
            a[0] = L - 1;
            @memcpy(a[1 .. 1 + nl], nonce);
            var s0: [16]u8 = undefined;
            ctx.encrypt(&s0, &a);
            var counter: u64 = 1;
            var i: usize = 0;
            while (i < in.len) : (counter += 1) {
                var c = counter;
                var k: usize = 15;
                while (k > nl) : (k -= 1) {
                    a[k] = @truncate(c);
                    c >>= 8;
                }
                var ks: [16]u8 = undefined;
                ctx.encrypt(&ks, &a);
                const n = @min(16, in.len - i);
                for (out[i..][0..n], in[i..][0..n], ks[0..n]) |*o, p, kk| o.* = p ^ kk;
                i += n;
            }
            return s0;
        }

        pub fn encrypt(c: []u8, tag: *[16]u8, m: []const u8, ad: []const u8, nonce: *const [nl]u8, key: [16]u8) void {
            const ctx = Aes128.initEnc(key);
            const t = mac(ctx, nonce, ad, m);
            const s0 = ctr(ctx, nonce, c, m);
            for (tag, t, s0) |*o, a, b| o.* = a ^ b;
        }

        pub fn decrypt(m: []u8, c: []const u8, tag: [16]u8, ad: []const u8, nonce: *const [nl]u8, key: [16]u8) error{AuthenticationFailed}!void {
            const ctx = Aes128.initEnc(key);
            const s0 = ctr(ctx, nonce, m, c);
            const t = mac(ctx, nonce, ad, m);
            var expect: [16]u8 = undefined;
            for (&expect, t, s0) |*o, a, b| o.* = a ^ b;
            if (!std.crypto.timing_safe.eql([16]u8, expect, tag)) {
                std.crypto.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
        }
    };
}

pub const ccmEncrypt = Ccm(11).encrypt;
pub const ccmDecrypt = Ccm(11).decrypt;

test "ccm matches std with 13-byte nonce" {
    const Std = std.crypto.aead.aes_ccm.Aes128Ccm16;
    const key = hex("404142434445464748494a4b4c4d4e4f");
    const nonce = hex("10111213141516171819202122");
    const msg = "0123456789abcdef0123456789abcdef-tail-bytes!";
    const ad = "associated data that spans more than one block....";
    var c1: [msg.len]u8 = undefined;
    var t1: [16]u8 = undefined;
    Std.encrypt(&c1, &t1, msg, ad, nonce, key);
    var c2: [msg.len]u8 = undefined;
    var t2: [16]u8 = undefined;
    Ccm(13).encrypt(&c2, &t2, msg, ad, &nonce, key);
    try std.testing.expectEqualSlices(u8, &c1, &c2);
    try std.testing.expectEqualSlices(u8, &t1, &t2);
}

test "md4 vectors" {
    var out: [16]u8 = undefined;
    md4(&out, "");
    try std.testing.expectEqualSlices(u8, &hex("31d6cfe0d16ae931b73c59d7e0c089c0"), &out);
    md4(&out, "abc");
    try std.testing.expectEqualSlices(u8, &hex("a448017aaf21d8525fc10ae87aa6729d"), &out);
    md4(&out, "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    try std.testing.expectEqualSlices(u8, &hex("e33b4ddc9c38f2199c3e7b164fcc0536"), &out);
    md4(&out, "abcdefghijklmnopqrstuvwxyz");
    try std.testing.expectEqualSlices(u8, &hex("d79e1c308aa5bbcdeea8ed63df412da9"), &out);
    const nt = try ntHash(std.testing.allocator, "Password");
    try std.testing.expectEqualSlices(u8, &hex("a4f49c406510bdcab6824ee7c30fd852"), &nt);
}

test "ccm roundtrip" {
    const key: [16]u8 = @splat(7);
    const nonce: [11]u8 = @splat(3);
    const msg = "the quick brown fox jumps over the lazy dog";
    var c: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ccmEncrypt(&c, &tag, msg, "header-data-aad", &nonce, key);
    var p: [msg.len]u8 = undefined;
    try ccmDecrypt(&p, &c, tag, "header-data-aad", &nonce, key);
    try std.testing.expectEqualStrings(msg, &p);
}

pub fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
