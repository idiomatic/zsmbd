//! Little-endian encoding helpers and UTF-16LE conversion.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{Malformed};

pub inline fn get16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .little);
}
pub inline fn get32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}
pub inline fn get64(b: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, b[off..][0..8], .little);
}
pub inline fn put16(b: []u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, b[off..][0..2], v, .little);
}
pub inline fn put32(b: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, b[off..][0..4], v, .little);
}
pub inline fn put64(b: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, b[off..][0..8], v, .little);
}

/// Returns `b[off..off+len]` or error.Malformed when out of bounds.
pub fn slice(b: []const u8, off: usize, len: usize) Error![]const u8 {
    if (off > b.len or len > b.len - off) return error.Malformed;
    return b[off..][0..len];
}

/// A growable little-endian output buffer.
pub const Buf = struct {
    list: std.ArrayList(u8) = .empty,
    gpa: Allocator,

    pub fn init(gpa: Allocator) Buf {
        return .{ .gpa = gpa };
    }
    pub fn deinit(self: *Buf) void {
        self.list.deinit(self.gpa);
    }
    pub fn len(self: *const Buf) usize {
        return self.list.items.len;
    }
    pub fn items(self: *const Buf) []u8 {
        return self.list.items;
    }
    pub fn clear(self: *Buf) void {
        self.list.clearRetainingCapacity();
    }
    pub fn u8_(self: *Buf, v: u8) !void {
        try self.list.append(self.gpa, v);
    }
    pub fn u16_(self: *Buf, v: u16) !void {
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, v, .little);
        try self.list.appendSlice(self.gpa, &t);
    }
    pub fn u32_(self: *Buf, v: u32) !void {
        var t: [4]u8 = undefined;
        std.mem.writeInt(u32, &t, v, .little);
        try self.list.appendSlice(self.gpa, &t);
    }
    pub fn u64_(self: *Buf, v: u64) !void {
        var t: [8]u8 = undefined;
        std.mem.writeInt(u64, &t, v, .little);
        try self.list.appendSlice(self.gpa, &t);
    }
    pub fn u16be(self: *Buf, v: u16) !void {
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, v, .big);
        try self.list.appendSlice(self.gpa, &t);
    }
    pub fn u32be(self: *Buf, v: u32) !void {
        var t: [4]u8 = undefined;
        std.mem.writeInt(u32, &t, v, .big);
        try self.list.appendSlice(self.gpa, &t);
    }
    pub fn bytes(self: *Buf, v: []const u8) !void {
        try self.list.appendSlice(self.gpa, v);
    }
    pub fn zeros(self: *Buf, n: usize) !void {
        try self.list.appendNTimes(self.gpa, 0, n);
    }
    /// Reserve `n` bytes and return their offset (zero filled).
    pub fn reserve(self: *Buf, n: usize) !usize {
        const off = self.list.items.len;
        try self.zeros(n);
        return off;
    }
    pub fn alignTo(self: *Buf, a: usize) !void {
        const r = self.list.items.len % a;
        if (r != 0) try self.zeros(a - r);
    }
    /// Pad relative to a base offset.
    pub fn alignFrom(self: *Buf, base: usize, a: usize) !void {
        const r = (self.list.items.len - base) % a;
        if (r != 0) try self.zeros(a - r);
    }
    pub fn set16(self: *Buf, off: usize, v: u16) void {
        put16(self.list.items, off, v);
    }
    pub fn set32(self: *Buf, off: usize, v: u32) void {
        put32(self.list.items, off, v);
    }
    pub fn set64(self: *Buf, off: usize, v: u64) void {
        put64(self.list.items, off, v);
    }
    /// Append UTF-8 string as UTF-16LE (no terminator). Returns bytes written.
    pub fn utf16(self: *Buf, s: []const u8) !usize {
        const start = self.list.items.len;
        try appendUtf16(self.gpa, &self.list, s);
        return self.list.items.len - start;
    }
};

const Decoded = struct { cp: u21, adv: usize };

/// The code point starting at `s[i]` and its length in bytes; an invalid or
/// truncated sequence yields U+FFFD for one byte.
fn decodeOne(s: []const u8, i: usize) Decoded {
    if (std.unicode.utf8ByteSequenceLength(s[i])) |n| {
        if (i + n <= s.len) {
            if (std.unicode.utf8Decode(s[i .. i + n])) |cp| return .{ .cp = cp, .adv = n } else |_| {}
        }
    } else |_| {}
    return .{ .cp = 0xFFFD, .adv = 1 };
}

/// Append UTF-8 text encoded as UTF-16LE bytes. Invalid sequences become U+FFFD.
pub fn appendUtf16(gpa: Allocator, list: *std.ArrayList(u8), s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) {
        const d = decodeOne(s, i);
        const cp = d.cp;
        i += d.adv;
        if (cp >= 0x10000) {
            const v = cp - 0x10000;
            try appendU16(gpa, list, @intCast(0xD800 + (v >> 10)));
            try appendU16(gpa, list, @intCast(0xDC00 + (v & 0x3FF)));
        } else {
            try appendU16(gpa, list, @intCast(cp));
        }
    }
}

fn appendU16(gpa: Allocator, list: *std.ArrayList(u8), v: u16) !void {
    var t: [2]u8 = undefined;
    std.mem.writeInt(u16, &t, v, .little);
    try list.appendSlice(gpa, &t);
}

/// Bytes `appendUtf16` writes for `s`.
pub fn utf16Len(s: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const d = decodeOne(s, i);
        n += if (d.cp >= 0x10000) 4 else 2;
        i += d.adv;
    }
    return n;
}

/// Decode UTF-16LE bytes into newly allocated UTF-8.
pub fn utf16ToUtf8(gpa: Allocator, b: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, b.len);
    var i: usize = 0;
    while (i + 1 < b.len) : (i += 2) {
        var cp: u21 = get16(b, i);
        if (cp >= 0xD800 and cp < 0xDC00 and i + 3 < b.len) {
            const lo = get16(b, i + 2);
            if (lo >= 0xDC00 and lo < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else cp = 0xFFFD;
        } else if (cp >= 0xD800 and cp < 0xE000) cp = 0xFFFD;
        var tmp: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &tmp) catch 0;
        try out.appendSlice(gpa, tmp[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

/// Uppercase an ASCII/UTF-8 string into UTF-16LE (simple case mapping for ASCII
/// and Latin-1; sufficient for NTLM user names).
pub fn upperUtf16(gpa: Allocator, s: []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try appendUtf16(gpa, &list, s);
    var i: usize = 0;
    while (i + 1 < list.items.len) : (i += 2) {
        const c = get16(list.items, i);
        const up: u16 = if ((c >= 'a' and c <= 'z') or (c >= 0xE0 and c <= 0xFE and c != 0xF7)) c - 32 else c;
        put16(list.items, i, up);
    }
    return list.toOwnedSlice(gpa);
}

test "utf16 roundtrip" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendUtf16(gpa, &list, "héllo 😀");
    try std.testing.expectEqual(utf16Len("héllo 😀"), list.items.len);
    const back = try utf16ToUtf8(gpa, list.items);
    defer gpa.free(back);
    try std.testing.expectEqualStrings("héllo 😀", back);
}

test "utf16Len matches appendUtf16 on invalid UTF-8" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "\xe9t", "a\xe9", "\xf0\x9f", "\xc3\x28x", "\xed\xa0\x80" }) |s| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try appendUtf16(gpa, &list, s);
        try std.testing.expectEqual(list.items.len, utf16Len(s));
    }
}

test "fuzz: UTF-16 decoding round-trips" {
    try @import("fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            const gpa = std.testing.allocator;
            const s = try utf16ToUtf8(gpa, in);
            defer gpa.free(s);
            try std.testing.expect(std.unicode.utf8ValidateSlice(s));
            // Valid UTF-8 survives a trip through UTF-16 unchanged.
            var list: std.ArrayList(u8) = .empty;
            defer list.deinit(gpa);
            try appendUtf16(gpa, &list, s);
            try std.testing.expectEqual(utf16Len(s), list.items.len);
            const back = try utf16ToUtf8(gpa, list.items);
            defer gpa.free(back);
            try std.testing.expectEqualStrings(s, back);
        }
    }.one, &.{ "h\x00\xe9\x00l\x00", "=\xd8\x00\xde", "\x00\xd8a\x00", "\x00\xdc" });
}
