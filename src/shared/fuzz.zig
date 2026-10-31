//! Fuzz harness for parsers of untrusted input (SECURITY.md lists them).
//!
//! `run` feeds a target the corpus plus a fixed number of deterministic
//! mutations of it, so every `zig build test` exercises malformed input with
//! reproducible results. `zig build test --fuzz` additionally runs the same
//! targets under Zig's coverage-guided fuzzer.
//!
//! A target must return normally for any input: parse errors are expected
//! and swallowed by the target, so only a crash, a safety-check panic, a
//! leak (std.testing.allocator), or a failed invariant fails the test.

const std = @import("std");

pub const max_input = 4096;

/// Mutations per corpus entry in ordinary test runs.
pub const rounds = 400;

pub fn run(
    ctx: anytype,
    comptime target: fn (@TypeOf(ctx), []const u8) anyerror!void,
    corpus: []const []const u8,
) !void {
    // Store problems are logged as warnings; thousands of them are noise.
    const saved = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = saved;

    const W = struct {
        c: @TypeOf(ctx),
        fn one(w: @This(), s: *std.testing.Smith) anyerror!void {
            var buf: [max_input]u8 = undefined;
            const n = s.slice(&buf);
            return target(w.c, buf[0..n]);
        }
    };
    try std.testing.fuzz(W{ .c = ctx }, W.one, .{ .corpus = corpus });

    var prng: std.Random.DefaultPrng = .init(0x5eed_2b5d);
    const r = prng.random();
    var buf: [max_input]u8 = undefined;
    try target(ctx, "");
    for (corpus) |seed| {
        try target(ctx, seed);
        for (0..rounds) |_| {
            const n = mutate(r, seed, &buf);
            try target(ctx, buf[0..n]);
        }
    }
}

const interesting = [_]u32{ 0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff };

/// A copy of `seed` with one to four random edits, in `buf`.
fn mutate(r: std.Random, seed: []const u8, buf: *[max_input]u8) usize {
    var n: usize = @min(seed.len, buf.len);
    @memcpy(buf[0..n], seed[0..n]);
    const edits = r.intRangeAtMost(usize, 1, 4);
    for (0..edits) |_| {
        switch (r.uintLessThan(u8, 7)) {
            // Flip a bit.
            0 => if (n > 0) {
                buf[r.uintLessThan(usize, n)] ^= @as(u8, 1) << r.int(u3);
            },
            // A random byte.
            1 => if (n > 0) {
                buf[r.uintLessThan(usize, n)] = r.int(u8);
            },
            // A boundary value as a little-endian u16 or u32 (lengths, offsets).
            2, 3 => {
                const w: usize = if (r.boolean()) 2 else 4;
                if (n >= w) {
                    const at = r.uintLessThan(usize, n - w + 1);
                    const v = interesting[r.uintLessThan(usize, interesting.len)];
                    if (w == 2) std.mem.writeInt(u16, buf[at..][0..2], @truncate(v), .little) else std.mem.writeInt(u32, buf[at..][0..4], v, .little);
                }
            },
            // Truncate.
            4 => if (n > 0) {
                n = r.uintLessThan(usize, n);
            },
            // Insert random bytes.
            5 => {
                const k = @min(r.intRangeAtMost(usize, 1, 16), max_input - n);
                const at = if (n == 0) 0 else r.uintLessThan(usize, n + 1);
                std.mem.copyBackwards(u8, buf[at + k .. n + k], buf[at..n]);
                r.bytes(buf[at .. at + k]);
                n += k;
            },
            // Duplicate a chunk.
            else => if (n > 0) {
                const at = r.uintLessThan(usize, n);
                const k = @min(r.intRangeAtMost(usize, 1, 32), n - at, max_input - n);
                std.mem.copyBackwards(u8, buf[at + k .. n + k], buf[at..n]);
                n += k;
            },
        }
    }
    return n;
}
