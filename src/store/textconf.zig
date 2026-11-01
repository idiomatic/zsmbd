//! Settings and shares in a plain-text file (`--config FILE`), in place of
//! SQLite. The file may be edited by hand; a changed file is reloaded on the
//! next lookup. zsmbd's own edits keep everything they don't change
//! (comments, order, layout):
//!
//!     # Settings come before the first section; comments are whole lines.
//!     server_name = FILES
//!     # One section per share; read_only and guest_ok default to no.
//!     [data]
//!     path = /srv/data
//!     comment = Team files
//!     read_only = yes
//!
//! Callers serialize access (Db.mutex).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const db = @import("types.zig");
const tf = @import("textfile.zig");
const File = tf.File;
const Error = tf.Error;
const fail = tf.fail;
const trim = tf.trim;
const Share = db.Share;

const Setting = struct { key: []u8, value: []u8 };

/// Settings and shares in one configuration file.
pub const Conf = struct {
    file: File,
    text: []u8 = &.{},
    settings: std.ArrayList(Setting) = .empty,
    shares: std.ArrayList(Share) = .empty,

    pub fn open(gpa: Allocator, io: Io, path: []const u8) Error!*Conf {
        const c = try gpa.create(Conf);
        errdefer gpa.destroy(c);
        c.* = .{ .file = try File.open(gpa, io, path) };
        errdefer c.close();
        try c.refresh();
        if (c.file.broken) return error.Store;
        return c;
    }

    pub fn close(c: *Conf) void {
        const gpa = c.file.gpa;
        c.clear();
        c.file.close();
        gpa.destroy(c);
    }

    fn clear(c: *Conf) void {
        const gpa = c.file.gpa;
        for (c.settings.items) |x| {
            gpa.free(x.key);
            gpa.free(x.value);
        }
        c.settings.deinit(gpa);
        for (c.shares.items) |x| x.free(gpa);
        c.shares.deinit(gpa);
        gpa.free(c.text);
        c.text = &.{};
    }

    /// Reload the file if it changed. A file that no longer parses is
    /// reported once, and the previous contents stay in use.
    fn refresh(c: *Conf) Error!void {
        const text = try c.file.changed() orelse return;
        if (c.install(text)) {
            c.file.broken = false;
        } else |e| {
            c.file.gpa.free(text);
            if (e == error.OutOfMemory) return e;
            c.file.broken = true;
        }
    }

    /// Parse `text` (taking ownership on success) as the new configuration.
    fn install(c: *Conf, text: []u8) Error!void {
        const gpa = c.file.gpa;
        var settings: std.ArrayList(Setting) = .empty;
        var shares: std.ArrayList(Share) = .empty;
        errdefer {
            for (settings.items) |x| {
                gpa.free(x.key);
                gpa.free(x.value);
            }
            settings.deinit(gpa);
            for (shares.items) |x| x.free(gpa);
            shares.deinit(gpa);
        }
        try parseConf(gpa, c.file.path, text, &settings, &shares);
        c.clear();
        c.text = text;
        c.settings = settings;
        c.shares = shares;
    }

    fn edit(c: *Conf) Error!Editor {
        try c.refresh();
        try c.file.writable();
        return Editor.init(c.file.gpa, c.text);
    }

    /// Install edited text: parse it, then write it.
    fn commit(c: *Conf, ed: *Editor) Error!void {
        const text = try ed.text();
        c.install(text) catch |e| {
            c.file.gpa.free(text);
            return e;
        };
        try c.file.write(c.text, 0o644);
    }

    pub fn getSetting(c: *Conf, gpa: Allocator, key: []const u8) Error!?[]u8 {
        try c.refresh();
        for (c.settings.items) |x| if (std.mem.eql(u8, x.key, key)) return try gpa.dupe(u8, x.value);
        return null;
    }

    pub fn setSetting(c: *Conf, key: []const u8, value: []const u8) Error!void {
        var ed = try c.edit();
        defer ed.deinit();
        try ed.set(ed.global(), key, value);
        try c.commit(&ed);
    }

    pub fn listShares(c: *Conf, gpa: Allocator) Error![]Share {
        try c.refresh();
        var out: std.ArrayList(Share) = .empty;
        errdefer {
            for (out.items) |x| x.free(gpa);
            out.deinit(gpa);
        }
        for (c.shares.items) |x| try out.append(gpa, try x.dupe(gpa));
        std.mem.sort(Share, out.items, {}, struct {
            fn lt(_: void, a: Share, b: Share) bool {
                return std.ascii.lessThanIgnoreCase(a.name, b.name);
            }
        }.lt);
        return out.toOwnedSlice(gpa);
    }

    pub fn putShare(c: *Conf, sh: Share) Error!void {
        var ed = try c.edit();
        defer ed.deinit();
        const r = ed.section(sh.name) orelse try ed.addSection(sh.name);
        try ed.setHeader(r, sh.name);
        try ed.set(ed.section(sh.name).?, "path", sh.path);
        if (sh.comment.len > 0) try ed.set(ed.section(sh.name).?, "comment", sh.comment) else ed.remove(ed.section(sh.name).?, "comment");
        if (sh.read_only) try ed.set(ed.section(sh.name).?, "read_only", "yes") else ed.remove(ed.section(sh.name).?, "read_only");
        if (sh.guest_ok) try ed.set(ed.section(sh.name).?, "guest_ok", "yes") else ed.remove(ed.section(sh.name).?, "guest_ok");
        try c.commit(&ed);
    }

    pub fn deleteShare(c: *Conf, name: []const u8) Error!bool {
        var ed = try c.edit();
        defer ed.deinit();
        const r = ed.section(name) orelse return false;
        ed.removeSection(r);
        try c.commit(&ed);
        return true;
    }
};

const Line = union(enum) {
    blank,
    header: []const u8,
    pair: struct { key: []const u8, value: []const u8 },
    bad,
};

fn classify(raw: []const u8) Line {
    const l = trim(raw);
    if (l.len == 0 or l[0] == '#' or l[0] == ';') return .blank;
    if (l[0] == '[') {
        if (l[l.len - 1] != ']') return .bad;
        return .{ .header = trim(l[1 .. l.len - 1]) };
    }
    const eq = std.mem.indexOfScalar(u8, l, '=') orelse return .bad;
    const key = trim(l[0..eq]);
    if (key.len == 0) return .bad;
    return .{ .pair = .{ .key = key, .value = trim(l[eq + 1 ..]) } };
}

fn isGlobal(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "global");
}

fn parseBool(v: []const u8) ?bool {
    for ([_][]const u8{ "yes", "true", "on", "1" }) |t| if (std.ascii.eqlIgnoreCase(v, t)) return true;
    for ([_][]const u8{ "no", "false", "off", "0" }) |f| if (std.ascii.eqlIgnoreCase(v, f)) return false;
    return null;
}

fn parseConf(gpa: Allocator, file: []const u8, text: []const u8, settings: *std.ArrayList(Setting), shares: *std.ArrayList(Share)) Error!void {
    var share: ?*Share = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (it.next()) |raw| {
        n += 1;
        switch (classify(raw)) {
            .blank => {},
            .bad => return fail("{s}:{d}: expected `key = value` or `[share]`", .{ file, n }),
            .header => |name| {
                if (share) |sh| if (sh.path.len == 0) return fail("{s}: share [{s}] has no path", .{ file, sh.name });
                if (isGlobal(name)) {
                    share = null;
                    continue;
                }
                if (name.len == 0) return fail("{s}:{d}: empty share name", .{ file, n });
                for (shares.items) |x| if (std.ascii.eqlIgnoreCase(x.name, name)) return fail("{s}:{d}: share [{s}] appears twice", .{ file, n, name });
                const sh = try shares.addOne(gpa);
                sh.* = .{ .name = &.{}, .path = &.{}, .comment = &.{} };
                sh.name = try gpa.dupe(u8, name);
                share = sh;
            },
            .pair => |p| if (share) |sh| {
                if (std.mem.eql(u8, p.key, "path")) {
                    gpa.free(sh.path);
                    sh.path = try gpa.dupe(u8, p.value);
                } else if (std.mem.eql(u8, p.key, "comment")) {
                    gpa.free(sh.comment);
                    sh.comment = try gpa.dupe(u8, p.value);
                } else if (std.mem.eql(u8, p.key, "read_only") or std.mem.eql(u8, p.key, "guest_ok")) {
                    const v = parseBool(p.value) orelse return fail("{s}:{d}: {s} is yes or no", .{ file, n, p.key });
                    if (p.key[0] == 'r') sh.read_only = v else sh.guest_ok = v;
                } else return fail("{s}:{d}: unknown share option `{s}`", .{ file, n, p.key });
            } else {
                const old = for (settings.items) |*x| {
                    if (std.mem.eql(u8, x.key, p.key)) break x;
                } else null;
                if (old) |x| {
                    gpa.free(x.value);
                    x.value = try gpa.dupe(u8, p.value);
                } else {
                    const k = try gpa.dupe(u8, p.key);
                    errdefer gpa.free(k);
                    try settings.append(gpa, .{ .key = k, .value = try gpa.dupe(u8, p.value) });
                }
            },
        }
    }
    if (share) |sh| if (sh.path.len == 0) return fail("{s}: share [{s}] has no path", .{ file, sh.name });
}

// ---------------------------------------------------------------- editing

/// Line-based editor for zsmbd.conf that leaves untouched lines as they are.
const Editor = struct {
    arena: std.heap.ArenaAllocator,
    lines: std.ArrayList([]const u8) = .empty,

    const Range = struct { header: ?usize, start: usize, end: usize };

    fn init(gpa: Allocator, conf: []const u8) Error!Editor {
        var ed: Editor = .{ .arena = .init(gpa) };
        errdefer ed.arena.deinit();
        const a = ed.arena.allocator();
        if (conf.len == 0) {
            try ed.lines.append(a, "# zsmbd settings (key = value), then one [section] per share.");
        } else {
            var it = std.mem.splitScalar(u8, if (conf[conf.len - 1] == '\n') conf[0 .. conf.len - 1] else conf, '\n');
            while (it.next()) |l| try ed.lines.append(a, l);
        }
        return ed;
    }

    fn deinit(ed: *Editor) void {
        ed.arena.deinit();
    }

    fn text(ed: *Editor) Error![]u8 {
        const gpa = ed.arena.child_allocator;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        for (ed.lines.items) |l| {
            try out.appendSlice(gpa, l);
            try out.append(gpa, '\n');
        }
        return out.toOwnedSlice(gpa);
    }

    fn headerAt(ed: *Editor, i: usize) ?[]const u8 {
        return switch (classify(ed.lines.items[i])) {
            .header => |h| h,
            else => null,
        };
    }

    fn endOf(ed: *Editor, start: usize) usize {
        var i = start;
        while (i < ed.lines.items.len and ed.headerAt(i) == null) i += 1;
        return i;
    }

    /// The settings that come before the first section.
    fn global(ed: *Editor) Range {
        return .{ .header = null, .start = 0, .end = ed.endOf(0) };
    }

    fn section(ed: *Editor, name: []const u8) ?Range {
        for (ed.lines.items, 0..) |_, i| {
            const h = ed.headerAt(i) orelse continue;
            if (!isGlobal(h) and std.ascii.eqlIgnoreCase(h, name)) return .{ .header = i, .start = i + 1, .end = ed.endOf(i + 1) };
        }
        return null;
    }

    fn addSection(ed: *Editor, name: []const u8) Error!Range {
        const a = ed.arena.allocator();
        const n = ed.lines.items.len;
        if (n > 0 and trim(ed.lines.items[n - 1]).len > 0) try ed.lines.append(a, "");
        try ed.lines.append(a, try std.fmt.allocPrint(a, "[{s}]", .{name}));
        const h = ed.lines.items.len - 1;
        return .{ .header = h, .start = h + 1, .end = h + 1 };
    }

    fn setHeader(ed: *Editor, r: Range, name: []const u8) Error!void {
        ed.lines.items[r.header.?] = try std.fmt.allocPrint(ed.arena.allocator(), "[{s}]", .{name});
    }

    fn isKey(ed: *Editor, i: usize, key: []const u8) bool {
        return switch (classify(ed.lines.items[i])) {
            .pair => |p| std.mem.eql(u8, p.key, key),
            else => false,
        };
    }

    /// Set `key` in region `r`. The parser keeps a key's last value, so the
    /// last occurrence is replaced and earlier ones are removed. A setting is
    /// also removed from `[global]` sections, which would override it.
    fn set(ed: *Editor, r: Range, key: []const u8, value: []const u8) Error!void {
        const a = ed.arena.allocator();
        const line = try std.fmt.allocPrint(a, "{s} = {s}", .{ key, value });
        if (r.header == null) ed.removeFromGlobalSections(key);
        var keep: ?usize = null;
        var i = r.end;
        while (i > r.start) {
            i -= 1;
            if (!ed.isKey(i, key)) continue;
            if (keep) |*k| {
                _ = ed.lines.orderedRemove(i);
                k.* -= 1;
            } else keep = i;
        }
        if (keep) |k| {
            ed.lines.items[k] = line;
            return;
        }
        const end = r.end;
        // After the region's last setting; else after its opening comments.
        var at = r.start;
        for (r.start..end) |j| switch (classify(ed.lines.items[j])) {
            .pair => at = j + 1,
            else => {},
        };
        if (at == r.start) {
            while (at < end and trim(ed.lines.items[at]).len > 0) at += 1;
        }
        if (at < ed.lines.items.len and ed.headerAt(at) != null) try ed.lines.insert(a, at, "");
        try ed.lines.insert(a, at, line);
    }

    fn removeFromGlobalSections(ed: *Editor, key: []const u8) void {
        var in_global = false;
        var i: usize = 0;
        while (i < ed.lines.items.len) {
            if (ed.headerAt(i)) |h| in_global = isGlobal(h);
            if (in_global and ed.isKey(i, key)) _ = ed.lines.orderedRemove(i) else i += 1;
        }
    }

    /// Remove every occurrence of `key` in region `r`.
    fn remove(ed: *Editor, r: Range, key: []const u8) void {
        var i = r.end;
        while (i > r.start) {
            i -= 1;
            if (ed.isKey(i, key)) _ = ed.lines.orderedRemove(i);
        }
    }

    /// Remove a section, leaving the comments and blank lines at its end,
    /// which introduce the next section.
    fn removeSection(ed: *Editor, r: Range) void {
        var start = r.header.?;
        var end = r.end;
        while (end > r.start and classify(ed.lines.items[end - 1]) == .blank) end -= 1;
        if (start > 0 and trim(ed.lines.items[start - 1]).len == 0) start -= 1;
        ed.lines.replaceRangeAssumeCapacity(start, end - start, &.{});
    }
};
// ---------------------------------------------------------------- tests

const testing = std.testing;
const tmpPath = tf.tmpPath;
const readBack = tf.readBack;

test "settings and shares keep hand edits" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "zsmbd.conf", .data =
        \\# my server
        \\workgroup = HOME
        \\
        \\# team files
        \\[data]
        \\path = /srv/data
        \\read_only = yes
        \\
    });
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const c = try Conf.open(testing.allocator, testing.io, try tmpPath(&tmp, &buf, "zsmbd.conf"));
    defer c.close();

    const wg = (try c.getSetting(testing.allocator, "workgroup")).?;
    defer testing.allocator.free(wg);
    try testing.expectEqualStrings("HOME", wg);
    try c.setSetting("server_name", "HAL9000");
    try c.setSetting("workgroup", "PERIHELION");
    try c.putShare(.{ .name = "art", .path = "/srv/art", .comment = "Pictures", .guest_ok = true });
    try c.putShare(.{ .name = "DATA", .path = "/srv/data2" });
    const text = try readBack(&tmp, "zsmbd.conf");
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        \\# my server
        \\workgroup = PERIHELION
        \\server_name = HAL9000
        \\
        \\# team files
        \\[DATA]
        \\path = /srv/data2
        \\
        \\[art]
        \\path = /srv/art
        \\comment = Pictures
        \\guest_ok = yes
        \\
    , text);

    try testing.expect(try c.deleteShare("data"));
    try testing.expect(!try c.deleteShare("data"));
    const shares = try c.listShares(testing.allocator);
    defer db.freeShares(testing.allocator, shares);
    try testing.expectEqual(@as(usize, 1), shares.len);
    try testing.expect(shares[0].guest_ok and !shares[0].read_only);

    // A broken edit keeps the last good contents and blocks changes.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "zsmbd.conf", .data = "[art]\npath = /srv/art\nbogus\n" });
    const again = try c.listShares(testing.allocator);
    defer db.freeShares(testing.allocator, again);
    try testing.expectEqualStrings("art", again[0].name);
    try testing.expectError(error.Store, c.setSetting("workgroup", "SKYNET"));
}

fn freeParsed(gpa: Allocator, settings: *std.ArrayList(Setting), shares: *std.ArrayList(Share)) void {
    for (settings.items) |x| {
        gpa.free(x.key);
        gpa.free(x.value);
    }
    settings.deinit(gpa);
    for (shares.items) |x| x.free(gpa);
    shares.deinit(gpa);
}

test "fuzz: configuration parsing and editing" {
    try @import("../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            const gpa = testing.allocator;
            var settings: std.ArrayList(Setting) = .empty;
            var shares: std.ArrayList(Share) = .empty;
            defer freeParsed(gpa, &settings, &shares);
            parseConf(gpa, "fuzz.conf", in, &settings, &shares) catch return;
            // Anything that parses still parses after zsmbd's edits, and
            // the edits take effect.
            var ed = try Editor.init(gpa, in);
            defer ed.deinit();
            try ed.set(ed.global(), "workgroup", "PERIHELION");
            const r = ed.section("hal") orelse try ed.addSection("hal");
            try ed.setHeader(r, "hal");
            try ed.set(ed.section("hal").?, "path", "/srv/hal");
            const text = try ed.text();
            defer gpa.free(text);
            var s2: std.ArrayList(Setting) = .empty;
            var sh2: std.ArrayList(Share) = .empty;
            defer freeParsed(gpa, &s2, &sh2);
            try parseConf(gpa, "edited.conf", text, &s2, &sh2);
            const found = for (sh2.items) |x| {
                if (std.ascii.eqlIgnoreCase(x.name, "hal")) break std.mem.eql(u8, x.path, "/srv/hal");
            } else false;
            try testing.expect(found);
            const wg = for (s2.items) |x| {
                if (std.mem.eql(u8, x.key, "workgroup")) break x.value;
            } else "";
            try testing.expectEqualStrings("PERIHELION", wg);
        }
    }.one, &.{ "# c\nworkgroup = HOME\n\n[data]\npath = /srv\nread_only = yes\n", "[global]\nserver_name=X\n[hal]\npath=/a\ncomment = c\n", "a=b\n[x]\npath=/\n" });
}
