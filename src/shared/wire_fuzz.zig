//! wire.zig's fuzz target, apart from wire.zig because zsmbd's tests and
//! libsmbd's both import wire.zig, and a fuzz target in two test binaries
//! fights over its corpus. Only libsmbd's test root (smbd.zig) imports this.

const std = @import("std");
const wire = @import("wire.zig");
const utf16ToUtf8 = wire.utf16ToUtf8;
const appendUtf16 = wire.appendUtf16;
const utf16Len = wire.utf16Len;

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
