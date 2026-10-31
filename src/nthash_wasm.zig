//! WebAssembly build of the NT hash (crypto.ntHash) for the admin web page,
//! so an SMB password set from the browser is hashed before it is sent.
//!
//! JavaScript writes the UTF-8 password at `input_ptr()`, calls
//! `nt_hash(len)`, and reads 16 bytes at `output_ptr()`. It also rates
//! passwords with the server's strength estimate (`strength(len)`).

const std = @import("std");
const crypto = @import("shared/crypto.zig");
const strength_mod = @import("policy/strength.zig");

var input: [1024]u8 = undefined;
var output: [16]u8 = undefined;
var heap: [8 * 1024]u8 = undefined;

export fn input_ptr() [*]u8 {
    return &input;
}

export fn output_ptr() [*]u8 {
    return &output;
}

/// Hashes input[0..len] into output and wipes the input; returns 0 on success.
export fn nt_hash(len: usize) i32 {
    if (len > input.len) return -1;
    defer std.crypto.secureZero(u8, input[0..len]);
    var fba = std.heap.FixedBufferAllocator.init(&heap);
    output = crypto.ntHash(fba.allocator(), input[0..len]) catch return -1;
    return 0;
}

/// Rates input[0..len] and wipes the input. Returns the estimated bits in the
/// low 16 bits and the level (0 weak, 1 fair, 2 strong) in the next 8.
export fn strength(len: usize) u32 {
    if (len > input.len) return 0;
    defer std.crypto.secureZero(u8, input[0..len]);
    const e = strength_mod.estimate(input[0..len]);
    return @min(e.bits, 0xffff) | @as(u32, @intFromEnum(e.level)) << 16;
}

test "nt_hash matches the server's NT hash" {
    const pw = "pässwörd 😀";
    @memcpy(input_ptr()[0..pw.len], pw);
    try std.testing.expectEqual(0, nt_hash(pw.len));
    try std.testing.expectEqual(try crypto.ntHash(std.testing.allocator, pw), output);
    try std.testing.expectEqual(-1, nt_hash(input.len + 1));
}

test "strength matches the server's estimate" {
    const pw = "correct horse battery staple";
    @memcpy(input_ptr()[0..pw.len], pw);
    const r = strength(pw.len);
    const e = strength_mod.estimate(pw);
    try std.testing.expectEqual(e.bits, r & 0xffff);
    try std.testing.expectEqual(@intFromEnum(e.level), r >> 16);
}
