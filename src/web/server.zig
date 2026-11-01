//! Embedded admin web server: a single-page UI plus a small JSON API for
//! shares, users, settings and live activity.
//!
//! Security model: admin users log in with their password (argon2id) and get
//! an HttpOnly, SameSite=Strict session cookie. Every state-changing request
//! must also carry the header `X-Zsmbd: 1`; browsers won't send a custom
//! header cross-origin without a CORS preflight, which this server never
//! approves. Bind to localhost unless you put TLS in front of it.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const http = std.http;
const Allocator = std.mem.Allocator;
const db_mod = @import("../store/store.zig");
const Db = db_mod.Db;
const auth = @import("../policy/auth.zig");

const index_html = @embedFile("index.html");
/// crypto.ntHash compiled to WebAssembly (src/nthash_wasm.zig), so the page
/// can hash SMB passwords before sending them.
const nthash_wasm = @import("nthash_wasm").bytes;
const cookie_name = "zsmbd_session";
const session_ttl_ms: i64 = 12 * 60 * 60 * 1000;
const max_body = 64 * 1024;

/// Hooks into the running SMB server. The defaults report no activity, so the
/// admin server works on its own (e.g. before the SMB side is wired up).
pub const Live = struct {
    ctx: ?*anyopaque = null,
    /// Write a JSON object of the form
    /// {"connections":[...],"events":[...],"stats":{...}} — see index.html
    /// (`renderActivity`) for the fields the UI reads.
    writeActivity: *const fn (ctx: ?*anyopaque, gpa: Allocator, w: *Io.Writer) anyerror!void = emptyActivity,
    /// Drop a client connection; returns false if it no longer exists.
    kick: *const fn (ctx: ?*anyopaque, conn_id: u64) bool = noKick,
    /// Settings changed in the database; reload them.
    reload: *const fn (ctx: ?*anyopaque) void = noReload,

    fn emptyActivity(_: ?*anyopaque, _: Allocator, w: *Io.Writer) anyerror!void {
        try w.writeAll(
            \\{"connections":[],"events":[],"stats":{},"smb_running":false}
        );
    }
    fn noKick(_: ?*anyopaque, _: u64) bool {
        return false;
    }
    fn noReload(_: ?*anyopaque) void {}
};

const WebSession = struct { user: []u8, expires_ms: i64 };

pub const Admin = struct {
    gpa: Allocator,
    io: Io,
    db: *Db,
    live: Live = .{},
    mutex: Io.Mutex = .init,
    sessions: std.StringHashMapUnmanaged(WebSession) = .empty,

    fn nowMs(a: *Admin) i64 {
        return Io.Clock.real.now(a.io).toMilliseconds();
    }

    /// Accept loop; runs until the listener fails. One thread per HTTP connection.
    pub fn serve(a: *Admin, addr: net.IpAddress) !void {
        var listener = try addr.listen(a.io, .{ .reuse_address = true });
        defer listener.deinit(a.io);
        std.log.info("zsmbd {s}: admin web UI on http://{f}/", .{ @import("build_options").version, addr });
        while (true) {
            const stream = listener.accept(a.io) catch |e| {
                std.log.warn("admin accept: {s}", .{@errorName(e)});
                continue;
            };
            const t = std.Thread.spawn(.{}, connMain, .{ a, stream }) catch {
                stream.close(a.io);
                continue;
            };
            t.detach();
        }
    }

    fn connMain(a: *Admin, stream: net.Stream) void {
        defer stream.close(a.io);
        var rbuf: [16 * 1024]u8 = undefined;
        var wbuf: [16 * 1024]u8 = undefined;
        var r = stream.reader(a.io, &rbuf);
        var w = stream.writer(a.io, &wbuf);
        var hs = http.Server.init(&r.interface, &w.interface);
        while (true) {
            var req = hs.receiveHead() catch return;
            a.handle(&req) catch |e| {
                std.log.warn("admin request failed: {s}", .{@errorName(e)});
                return;
            };
            if (!req.head.keep_alive) return;
        }
    }

    // ------------------------------------------------------------ sessions

    fn newSession(a: *Admin, user: []const u8) ![64]u8 {
        var raw: [32]u8 = undefined;
        a.io.random(&raw);
        const token = std.fmt.bytesToHex(raw, .lower);
        const key = try a.gpa.dupe(u8, &token);
        errdefer a.gpa.free(key);
        const u = try a.gpa.dupe(u8, user);
        errdefer a.gpa.free(u);
        a.mutex.lockUncancelable(a.io);
        defer a.mutex.unlock(a.io);
        a.pruneLocked();
        try a.sessions.put(a.gpa, key, .{ .user = u, .expires_ms = a.nowMs() + session_ttl_ms });
        return token;
    }

    fn pruneLocked(a: *Admin) void {
        const now = a.nowMs();
        var it = a.sessions.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.expires_ms < now) {
                const k = e.key_ptr.*;
                a.gpa.free(e.value_ptr.user);
                a.sessions.removeByPtr(e.key_ptr);
                a.gpa.free(k);
                it = a.sessions.iterator();
            }
        }
    }

    /// Returns a copy of the logged-in user's name and extends the session.
    fn sessionUser(a: *Admin, gpa: Allocator, token: []const u8) !?[]u8 {
        a.mutex.lockUncancelable(a.io);
        defer a.mutex.unlock(a.io);
        const s = a.sessions.getPtr(token) orelse return null;
        const now = a.nowMs();
        if (s.expires_ms < now) return null;
        s.expires_ms = now + session_ttl_ms;
        return try gpa.dupe(u8, s.user);
    }

    fn endSession(a: *Admin, token: []const u8) void {
        a.mutex.lockUncancelable(a.io);
        defer a.mutex.unlock(a.io);
        if (a.sessions.fetchRemove(token)) |kv| {
            a.gpa.free(kv.value.user);
            a.gpa.free(kv.key);
        }
    }

    /// Drop sessions of a user (after deletion or demotion).
    fn endUserSessions(a: *Admin, user: []const u8) void {
        a.mutex.lockUncancelable(a.io);
        defer a.mutex.unlock(a.io);
        var again = true;
        while (again) {
            again = false;
            var it = a.sessions.iterator();
            while (it.next()) |e| {
                if (std.ascii.eqlIgnoreCase(e.value_ptr.user, user)) {
                    const k = e.key_ptr.*;
                    a.gpa.free(e.value_ptr.user);
                    a.sessions.removeByPtr(e.key_ptr);
                    a.gpa.free(k);
                    again = true;
                    break;
                }
            }
        }
    }

    // ------------------------------------------------------------ request handling

    fn handle(a: *Admin, req: *http.Server.Request) !void {
        var arena_state = std.heap.ArenaAllocator.init(a.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // A request without Content-Length or chunked encoding has no body
        // (RFC 9112 6.3); std.http asserts one of the two is present.
        if (req.head.method.requestHasBody() and req.head.content_length == null and req.head.transfer_encoding == .none)
            req.head.content_length = 0;

        const target = try arena.dupe(u8, req.head.target);
        const qpos = std.mem.indexOfScalar(u8, target, '?');
        const path = target[0 .. qpos orelse target.len];
        const query = if (qpos) |q| target[q + 1 ..] else "";
        const method = req.head.method;

        // Read headers we need before the body invalidates them.
        var token: ?[]const u8 = null;
        var csrf_ok = false;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "cookie")) {
                if (cookieValue(h.value, cookie_name)) |v| token = try arena.dupe(u8, v);
            } else if (std.ascii.eqlIgnoreCase(h.name, "x-zsmbd")) {
                csrf_ok = std.mem.eql(u8, h.value, "1");
            }
        }

        if (method == .GET and (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html"))) {
            return req.respond(index_html, .{ .extra_headers = &.{
                .{ .name = "content-type", .value = "text/html; charset=utf-8" },
                .{ .name = "cache-control", .value = "no-store" },
                .{ .name = "x-frame-options", .value = "DENY" },
                .{ .name = "x-content-type-options", .value = "nosniff" },
                .{ .name = "content-security-policy", .value = "default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'" },
            } });
        }
        if (method == .GET and std.mem.eql(u8, path, "/nthash.wasm")) {
            return req.respond(nthash_wasm, .{ .extra_headers = &.{
                .{ .name = "content-type", .value = "application/wasm" },
                .{ .name = "x-content-type-options", .value = "nosniff" },
            } });
        }
        if (!std.mem.startsWith(u8, path, "/api/")) return respondError(req, .not_found, "not found");

        const mutating = method != .GET and method != .HEAD;
        if (mutating and !csrf_ok) return respondError(req, .forbidden, "missing X-Zsmbd header");

        var body: []const u8 = "";
        const has_body = req.head.content_length != null or req.head.transfer_encoding == .chunked;
        if (method.requestHasBody() and has_body) {
            if (req.head.expect != null) return respondError(req, .expectation_failed, "expect not supported");
            if ((req.head.content_length orelse 0) > max_body) return respondError(req, .payload_too_large, "body too large");
            var bbuf: [4096]u8 = undefined;
            const br = req.readerExpectNone(&bbuf);
            body = br.allocRemaining(arena, .limited(max_body)) catch return respondError(req, .bad_request, "cannot read body");
        }

        if (method == .POST and std.mem.eql(u8, path, "/api/login")) return a.login(req, arena, body);

        const user = if (token) |t| try a.sessionUser(arena, t) else null;
        if (user == null) return respondError(req, .unauthorized, "not logged in");

        const R = struct {
            fn is(m: http.Method, p: []const u8, want_m: http.Method, want_p: []const u8) bool {
                return m == want_m and std.mem.eql(u8, p, want_p);
            }
        };
        if (R.is(method, path, .POST, "/api/logout")) {
            a.endSession(token.?);
            return req.respond("{}", .{ .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json" },
                .{ .name = "set-cookie", .value = cookie_name ++ "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" },
            } });
        }
        if (R.is(method, path, .GET, "/api/me")) return respondJson(req, arena, .{ .user = user.? });
        if (R.is(method, path, .GET, "/api/activity")) return a.activity(req, arena);
        if (R.is(method, path, .POST, "/api/kick")) return a.kick(req, arena, body);
        if (R.is(method, path, .GET, "/api/shares")) return a.listShares(req, arena);
        if (R.is(method, path, .PUT, "/api/shares")) return a.putShare(req, arena, body);
        if (R.is(method, path, .DELETE, "/api/shares")) return a.deleteShare(req, arena, query);
        if (R.is(method, path, .GET, "/api/users")) return a.listUsers(req, arena);
        if (R.is(method, path, .PUT, "/api/users")) return a.putUser(req, arena, body);
        if (R.is(method, path, .DELETE, "/api/users")) return a.deleteUser(req, arena, query);
        if (R.is(method, path, .GET, "/api/settings")) return a.getSettings(req, arena);
        if (R.is(method, path, .PUT, "/api/settings")) return a.putSettings(req, arena, body);
        return respondError(req, .not_found, "not found");
    }

    fn login(a: *Admin, req: *http.Server.Request, arena: Allocator, body: []const u8) !void {
        const In = struct { user: []const u8, password: []const u8 };
        const in = std.json.parseFromSliceLeaky(In, arena, body, .{ .ignore_unknown_fields = true }) catch
            return respondError(req, .bad_request, "expected {\"user\",\"password\"}");
        const name = try auth.checkWebLogin(a.gpa, a.io, a.db, in.user, in.password) orelse {
            // Slow down password guessing.
            a.io.sleep(.fromMilliseconds(750), .awake) catch {};
            return respondError(req, .unauthorized, "wrong user name or password, or no web console access");
        };
        defer a.gpa.free(name);
        const token = try a.newSession(name);
        const cookie = try std.fmt.allocPrint(arena, "{s}={s}; HttpOnly; SameSite=Strict; Path=/; Max-Age={d}", .{ cookie_name, token, @divTrunc(session_ttl_ms, 1000) });
        const json = try std.json.Stringify.valueAlloc(arena, .{ .user = name }, .{});
        return req.respond(json, .{ .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "cache-control", .value = "no-store" },
            .{ .name = "set-cookie", .value = cookie },
        } });
    }

    fn activity(a: *Admin, req: *http.Server.Request, arena: Allocator) !void {
        var aw: Io.Writer.Allocating = .init(arena);
        try a.live.writeActivity(a.live.ctx, arena, &aw.writer);
        return req.respond(aw.written(), .{ .extra_headers = &json_headers });
    }

    fn kick(a: *Admin, req: *http.Server.Request, arena: Allocator, body: []const u8) !void {
        const In = struct { id: u64 };
        const in = std.json.parseFromSliceLeaky(In, arena, body, .{ .ignore_unknown_fields = true }) catch
            return respondError(req, .bad_request, "expected {\"id\"}");
        if (!a.live.kick(a.live.ctx, in.id)) return respondError(req, .not_found, "no such connection");
        return respondJson(req, arena, .{ .ok = true });
    }

    fn listShares(a: *Admin, req: *http.Server.Request, arena: Allocator) !void {
        const shares = try a.db.listShares(arena);
        return respondJson(req, arena, shares);
    }

    fn putShare(a: *Admin, req: *http.Server.Request, arena: Allocator, body: []const u8) !void {
        const In = struct { name: []const u8, path: []const u8, comment: []const u8 = "", read_only: bool = false, guest_ok: bool = false };
        const in = std.json.parseFromSliceLeaky(In, arena, body, .{ .ignore_unknown_fields = true }) catch
            return respondError(req, .bad_request, "expected {\"name\",\"path\",...}");
        auth.validateShareName(in.name) catch |e| return respondError(req, .bad_request, auth.describe(e));
        auth.validateSharePath(arena, in.path) catch |e| return respondError(req, .bad_request, auth.describe(e));
        auth.validateComment(in.comment) catch |e| return respondError(req, .bad_request, auth.describe(e));
        try a.db.putShare(.{ .name = in.name, .path = in.path, .comment = in.comment, .read_only = in.read_only, .guest_ok = in.guest_ok });
        return respondJson(req, arena, .{ .ok = true });
    }

    fn deleteShare(a: *Admin, req: *http.Server.Request, arena: Allocator, query: []const u8) !void {
        const name = try queryParam(arena, query, "name") orelse return respondError(req, .bad_request, "missing name");
        if (!try a.db.deleteShare(name)) return respondError(req, .not_found, "no such share");
        return respondJson(req, arena, .{ .ok = true });
    }

    fn listUsers(a: *Admin, req: *http.Server.Request, arena: Allocator) !void {
        const users = try a.db.listUsers(arena);
        const Out = struct { name: []const u8, access: []const u8, has_smb: bool, has_web: bool, created: i64 };
        const out = try arena.alloc(Out, users.len);
        for (users, out) |u, *o| o.* = .{ .name = u.name, .access = auth.accessName(u.has_smb, u.has_web), .has_smb = u.has_smb, .has_web = u.has_web, .created = u.created };
        return respondJson(req, arena, out);
    }

    fn putUser(a: *Admin, req: *http.Server.Request, arena: Allocator, body: []const u8) !void {
        // `smb_password` is the SMB password, or `nt_hash` its NT hash computed in
        // the browser (32 hex digits); `web_password` is the web console
        // password. Empty or absent means unchanged. `no_smb_password` and
        // `no_web_password` clear them. A missing user is created first.
        // Unknown fields are refused, so a misspelled password isn't silently
        // dropped.
        const In = struct { name: []const u8, smb_password: ?[]const u8 = null, nt_hash: ?[]const u8 = null, web_password: ?[]const u8 = null, no_smb_password: bool = false, no_web_password: bool = false };
        const in = std.json.parseFromSliceLeaky(In, arena, body, .{}) catch
            return respondError(req, .bad_request, "expected {\"name\",\"smb_password\" or \"nt_hash\",\"web_password\",\"no_smb_password\",\"no_web_password\"}");
        var nt_hash: ?[16]u8 = null;
        if (in.nt_hash) |h| if (h.len > 0) {
            var nt: [16]u8 = undefined;
            const ok = h.len == 32 and if (std.fmt.hexToBytes(&nt, h)) |_| true else |_| false;
            if (!ok) return respondError(req, .bad_request, auth.describe(error.InvalidNtHash));
            nt_hash = nt;
        };
        const pw: auth.Passwords = .{
            .smb = if (in.smb_password) |p| (if (p.len > 0) p else null) else null,
            .nt_hash = nt_hash,
            .web = if (in.web_password) |p| (if (p.len > 0) p else null) else null,
        };
        if ((in.no_smb_password and pw.hasSmb()) or (in.no_web_password and pw.web != null))
            return respondError(req, .bad_request, "a password can't be both set and cleared");
        const existing = try a.db.userAuth(arena, in.name);
        const warning = a.changeUser(in.name, existing == null, in.no_smb_password, in.no_web_password, pw) catch |e|
            return respondError(req, .bad_request, auth.describe(e));
        if (existing) |u| if (in.no_web_password or pw.web != null) a.endUserSessions(u.name);
        var texts: std.ArrayList([]const u8) = .empty;
        var it = warning.iterator();
        while (it.next()) |w| try texts.append(arena, w.text());
        return respondJson(req, arena, .{ .ok = true, .warnings = texts.items });
    }

    /// Create (when `create`), then clear, then set passwords.
    fn changeUser(a: *Admin, name: []const u8, create: bool, no_smb: bool, no_web: bool, pw: auth.Passwords) !auth.Warnings {
        if (create) try auth.addUser(a.io, a.db, name);
        if (no_smb or no_web) try auth.revokePasswords(a.gpa, a.io, a.db, name, no_smb, no_web);
        return auth.grantPasswords(a.gpa, a.io, a.db, name, pw);
    }

    fn deleteUser(a: *Admin, req: *http.Server.Request, arena: Allocator, query: []const u8) !void {
        const name = try queryParam(arena, query, "name") orelse return respondError(req, .bad_request, "missing name");
        auth.deleteUser(a.gpa, a.db, name) catch |e| switch (e) {
            error.NotFound => return respondError(req, .not_found, "no such user"),
            else => return respondError(req, .bad_request, auth.describe(e)),
        };
        a.endUserSessions(name);
        return respondJson(req, arena, .{ .ok = true });
    }

    fn getSettings(a: *Admin, req: *http.Server.Request, arena: Allocator) !void {
        const Out = struct { key: []const u8, value: []const u8, default: []const u8, kind: []const u8, help: []const u8 };
        var out: [auth.settings.len]Out = undefined;
        for (auth.settings, &out) |s, *o| {
            const v = try a.db.getSetting(arena, s.key);
            o.* = .{ .key = s.key, .value = v orelse s.default, .default = s.default, .kind = @tagName(s.kind), .help = s.help };
        }
        return respondJson(req, arena, &out);
    }

    fn putSettings(a: *Admin, req: *http.Server.Request, arena: Allocator, body: []const u8) !void {
        const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch
            return respondError(req, .bad_request, "expected a JSON object");
        if (parsed != .object) return respondError(req, .bad_request, "expected a JSON object");
        // Validate everything first so a bad value changes nothing.
        var values: std.ArrayList(struct { key: []const u8, value: []const u8 }) = .empty;
        var it = parsed.object.iterator();
        while (it.next()) |e| {
            const raw: []const u8 = switch (e.value_ptr.*) {
                .string => |s| s,
                .bool => |b| if (b) "true" else "false",
                else => return respondError(req, .bad_request, "setting values must be strings or booleans"),
            };
            const v = auth.normalizeSetting(e.key_ptr.*, raw) catch
                return respondError(req, .bad_request, try std.fmt.allocPrint(arena, "invalid value for {s}", .{e.key_ptr.*}));
            try values.append(arena, .{ .key = e.key_ptr.*, .value = v });
        }
        for (values.items) |kv| try a.db.setSetting(kv.key, kv.value);
        a.live.reload(a.live.ctx);
        return respondJson(req, arena, .{ .ok = true });
    }
};

const json_headers = [_]http.Header{
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "cache-control", .value = "no-store" },
};

fn respondJson(req: *http.Server.Request, arena: Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(arena, value, .{});
    return req.respond(json, .{ .extra_headers = &json_headers });
}

fn respondError(req: *http.Server.Request, status: http.Status, msg: []const u8) !void {
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    std.json.Stringify.value(.{ .@"error" = msg }, .{}, &w) catch {};
    return req.respond(w.buffered(), .{ .status = status, .extra_headers = &json_headers });
}

fn cookieValue(header: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, header, ';');
    while (it.next()) |part| {
        const p = std.mem.trim(u8, part, " ");
        if (p.len > name.len and std.mem.startsWith(u8, p, name) and p[name.len] == '=') return p[name.len + 1 ..];
    }
    return null;
}

/// Returns the percent-decoded value of `key` in a query string.
fn queryParam(arena: Allocator, query: []const u8, key: []const u8) !?[]u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (!std.mem.eql(u8, kv[0..eq], key)) continue;
        const raw = kv[eq + 1 ..];
        var out = try arena.alloc(u8, raw.len);
        var n: usize = 0;
        var i: usize = 0;
        while (i < raw.len) : (i += 1) {
            if (raw[i] == '%' and i + 2 < raw.len) {
                out[n] = std.fmt.parseInt(u8, raw[i + 1 .. i + 3], 16) catch return null;
                i += 2;
            } else if (raw[i] == '+') {
                out[n] = ' ';
            } else out[n] = raw[i];
            n += 1;
        }
        return out[0..n];
    }
    return null;
}

test "cookie and query parsing" {
    try std.testing.expectEqualStrings("abc", cookieValue("x=1; zsmbd_session=abc; y=2", cookie_name).?);
    try std.testing.expect(cookieValue("zsmbd_sessionx=1", cookie_name) == null);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const v = (try queryParam(arena.allocator(), "a=1&name=My%20Share", "name")).?;
    try std.testing.expectEqualStrings("My Share", v);
}

test "fuzz: cookie and query parsing" {
    try @import("../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();
            if (cookieValue(in, "zsmbd_session")) |v| try std.testing.expect(v.len < in.len);
            if (try queryParam(arena.allocator(), in, "name")) |v| try std.testing.expect(v.len <= in.len);
        }
    }.one, &.{ "zsmbd_session=abc; other=1", "name=hal%20art&x=%zz", "name=%4", "name=+%41" });
}
