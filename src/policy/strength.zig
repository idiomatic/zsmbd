//! Password strength estimate. zsmbd reports strength but never refuses a
//! password for it. Shared by the server, the CLI, and the browser (through
//! nthash_wasm.zig).
//!
//! The estimate is deliberately simple: length times the bits per character
//! of the character classes used, with repeated and sequential characters
//! counted at half weight, and a short list of very common passwords rated
//! weak outright. It cannot recognize dictionary words or personal details.

const std = @import("std");

pub const Level = enum(u8) {
    weak,
    fair,
    strong,
};

pub const fair_bits = 40;
pub const strong_bits = 64;

pub const Estimate = struct {
    /// Rough guessing entropy in bits.
    bits: u32,
    level: Level,
};

/// Lowercase bases that are rated weak, even with digits or symbols appended.
const common = [_][]const u8{
    "password", "passw0rd", "123456",  "12345678", "qwerty", "qwertyuiop", "abc123",
    "letmein",  "welcome",  "admin",   "iloveyou", "monkey", "dragon",     "football",
    "baseball", "sunshine", "princess", "secret",  "changeme", "trustno1", "111111",
};

fn isCommon(pw: []const u8) bool {
    // Strip trailing digits and symbols ("Password1!" -> "password").
    var end = pw.len;
    while (end > 0 and !std.ascii.isAlphabetic(pw[end - 1])) end -= 1;
    const base = if (end == 0) pw else pw[0..end];
    for (common) |c| if (std.ascii.eqlIgnoreCase(base, c)) return true;
    return false;
}

pub fn estimate(pw: []const u8) Estimate {
    var lower = false;
    var upper = false;
    var digit = false;
    var symbol = false;
    var other = false;
    var weight: f64 = 0;
    var prev: ?u21 = null;
    var i: usize = 0;
    while (i < pw.len) {
        var cp: u21 = pw[i];
        var n: usize = 1;
        if (std.unicode.utf8ByteSequenceLength(pw[i])) |l| {
            if (i + l <= pw.len) if (std.unicode.utf8Decode(pw[i .. i + l])) |c| {
                cp = c;
                n = l;
            } else |_| {};
        } else |_| {}
        i += n;
        switch (cp) {
            'a'...'z' => lower = true,
            'A'...'Z' => upper = true,
            '0'...'9' => digit = true,
            0x20...0x2f, 0x3a...0x40, 0x5b...0x60, 0x7b...0x7e => symbol = true,
            else => other = true,
        }
        const predictable = if (prev) |p| cp == p or cp == p +% 1 or p == cp +% 1 else false;
        weight += if (predictable) 0.5 else 1.0;
        prev = cp;
    }
    var pool: f64 = 0;
    if (lower) pool += 26;
    if (upper) pool += 26;
    if (digit) pool += 10;
    if (symbol) pool += 33;
    if (other) pool += 100;
    const bits: u32 = if (pool == 0) 0 else @intFromFloat(@min(weight * @log2(pool), 1000));
    if (isCommon(pw)) return .{ .bits = @min(bits, 10), .level = .weak };
    return .{ .bits = bits, .level = if (bits < fair_bits) .weak else if (bits < strong_bits) .fair else .strong };
}

test "estimates" {
    try std.testing.expectEqual(Level.weak, estimate("").level);
    try std.testing.expectEqual(Level.weak, estimate("abcdefgh").level);
    try std.testing.expectEqual(Level.weak, estimate("Password1!").level);
    try std.testing.expectEqual(Level.weak, estimate("aaaaaaaaaaaa").level);
    try std.testing.expectEqual(Level.fair, estimate("sunflower7").level);
    try std.testing.expectEqual(Level.strong, estimate("correct horse battery staple").level);
    try std.testing.expectEqual(Level.strong, estimate("hRp7Xq2mKw9tLz4v").level);
    try std.testing.expect(estimate("pässwörd 😀 ok").bits > estimate("passwrd ok").bits);
}
