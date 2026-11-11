//! libsmbd's C interface (include/smbd.h): opaque servers over smbd.Server,
//! a C host behind smbd.Host, and integer error codes. Every server in the
//! process shares one std.Io.Threaded, made by the first `smbd_new` and
//! freed by the last `smbd_free`.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const smbd = @import("smbd.zig");

const gpa = std.heap.c_allocator;

pub const OK: c_int = 0;
pub const ENOMEM: c_int = -1;
pub const EINVAL: c_int = -2;
pub const EADDRINUSE: c_int = -3;
pub const EACCES: c_int = -4;
pub const ESTOPPED: c_int = -5;
pub const EFAIL: c_int = -6;

/// Listeners per server (IPv4 and IPv6, with room to spare).
const max_listeners = 4;
/// Longer user names are no user (NTLM user names are far shorter).
const max_user = 256;

pub const CShare = extern struct {
    name: ?[*:0]const u8,
    path: ?[*:0]const u8,
    comment: ?[*:0]const u8,
    read_only: bool,
    guest_ok: bool,
};

pub const CHost = extern struct {
    ctx: ?*anyopaque,
    list_shares: ?*const fn (ctx: ?*anyopaque, out: *Shares) callconv(.c) c_int,
    nt_hash: ?*const fn (ctx: ?*anyopaque, user: [*:0]const u8, hash: *[16]u8) callconv(.c) c_int,
    log: ?*const fn (ctx: ?*anyopaque, level: c_int, conn_id: u64, kind: [*:0]const u8, msg: [*:0]const u8) callconv(.c) void,
};

pub const CConfig = extern struct {
    server_name: ?[*:0]const u8,
    workgroup: ?[*:0]const u8,
    signing_required: bool,
    encrypt: bool,
};

pub const CStats = extern struct {
    connections_now: u64,
    connections_total: u64,
    bytes_in: u64,
    bytes_out: u64,
    data_read: u64,
    data_written: u64,
    requests: u64,
    logon_failures: u64,
};

/// What `list_shares` adds to: `smbd_shares *` in C.
pub const Shares = struct {
    gpa: Allocator,
    list: std.ArrayList(smbd.Share) = .empty,
    out_of_memory: bool = false,

    fn deinit(s: *Shares) void {
        for (s.list.items) |sh| sh.free(s.gpa);
        s.list.deinit(s.gpa);
    }
};

const Handle = struct {
    srv: smbd.Server,
    host: CHost,
    io: Io,
    listeners: [max_listeners]Io.net.Server = undefined,
    n_listeners: usize = 0,
    stopped: std.atomic.Value(bool) = .init(false),
};

// ---------------------------------------------------------------- shared Io

var io_lock: std.atomic.Mutex = .unlocked;
var io_refs: usize = 0;
var threaded: Io.Threaded = undefined;

fn lockIo() void {
    while (!io_lock.tryLock()) std.atomic.spinLoopHint();
}

fn acquireIo() Io {
    lockIo();
    defer io_lock.unlock();
    if (io_refs == 0) threaded = .init(gpa, .{});
    io_refs += 1;
    return threaded.io();
}

fn releaseIo() void {
    lockIo();
    defer io_lock.unlock();
    io_refs -= 1;
    if (io_refs == 0) threaded.deinit();
}

// ---------------------------------------------------------------- the host

const vtable: smbd.Host.VTable = .{ .listShares = hostShares, .ntHash = hostNtHash, .log = hostLog };

fn handleOf(ctx: ?*anyopaque) *Handle {
    return @ptrCast(@alignCast(ctx.?));
}

fn hostShares(ctx: ?*anyopaque, a: Allocator) smbd.Error![]smbd.Share {
    const h = handleOf(ctx);
    var s: Shares = .{ .gpa = a };
    errdefer s.deinit();
    const rc = h.host.list_shares.?(h.host.ctx, &s);
    if (s.out_of_memory) return error.OutOfMemory;
    if (rc != 0) return error.HostFailed;
    return s.list.toOwnedSlice(a);
}

fn hostNtHash(ctx: ?*anyopaque, name: []const u8) smbd.Error!?[16]u8 {
    const h = handleOf(ctx);
    if (name.len > max_user or std.mem.indexOfScalar(u8, name, 0) != null) return null;
    var buf: [max_user + 1]u8 = undefined;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    var hash: [16]u8 = undefined;
    const rc = h.host.nt_hash.?(h.host.ctx, buf[0..name.len :0], &hash);
    defer std.crypto.secureZero(u8, &hash);
    if (rc < 0) return error.HostFailed;
    return if (rc > 0) hash else null;
}

fn hostLog(ctx: ?*anyopaque, level: smbd.Level, conn_id: u64, kind: []const u8, msg: []const u8) void {
    const h = handleOf(ctx);
    const f = h.host.log orelse return;
    var kb: [32]u8 = undefined;
    var mb: [256]u8 = undefined;
    f(h.host.ctx, @intFromEnum(level), conn_id, cString(&kb, kind), cString(&mb, msg));
}

/// `s`, truncated to fit `buf`, with a NUL.
fn cString(buf: []u8, s: []const u8) [*:0]const u8 {
    const n = @min(s.len, buf.len - 1);
    @memcpy(buf[0..n], s[0..n]);
    buf[n] = 0;
    return buf[0..n :0];
}

fn config(c: *const CConfig) ?smbd.Config {
    const name = c.server_name orelse return null;
    return .{
        .server_name = std.mem.span(name),
        .workgroup = if (c.workgroup) |w| std.mem.span(w) else "WORKGROUP",
        .signing_required = c.signing_required,
        .encrypt = c.encrypt,
    };
}

// ---------------------------------------------------------------- exports

export fn smbd_version() [*:0]const u8 {
    return @import("build_options").version ++ "";
}

export fn smbd_hardware_aes() c_int {
    return @intFromBool(smbd.hardware_aes);
}

export fn smbd_strerror(err: c_int) [*:0]const u8 {
    return switch (err) {
        OK => "success",
        ENOMEM => "out of memory",
        EINVAL => "invalid argument",
        EADDRINUSE => "address in use",
        EACCES => "permission denied",
        ESTOPPED => "server stopped",
        EFAIL => "failed",
        else => "unknown error",
    };
}

export fn smbd_config_init(c: ?*CConfig) void {
    (c orelse return).* = .{ .server_name = "SMBD", .workgroup = "WORKGROUP", .signing_required = true, .encrypt = false };
}

export fn smbd_nt_hash(password: ?[*:0]const u8, out: ?*[16]u8) c_int {
    const pw = password orelse return EINVAL;
    const o = out orelse return EINVAL;
    o.* = smbd.ntHash(gpa, std.mem.span(pw)) catch return ENOMEM;
    return OK;
}

export fn smbd_shares_add(list: ?*Shares, share: ?*const CShare) c_int {
    const l = list orelse return EINVAL;
    const sh = share orelse return EINVAL;
    const name = sh.name orelse return EINVAL;
    const path = sh.path orelse return EINVAL;
    const a = l.gpa;
    add: {
        const n = a.dupe(u8, std.mem.span(name)) catch break :add;
        const p = a.dupe(u8, std.mem.span(path)) catch {
            a.free(n);
            break :add;
        };
        const c = a.dupe(u8, if (sh.comment) |c| std.mem.span(c) else "") catch {
            a.free(n);
            a.free(p);
            break :add;
        };
        const s: smbd.Share = .{ .name = n, .path = p, .comment = c, .read_only = sh.read_only, .guest_ok = sh.guest_ok };
        l.list.append(a, s) catch {
            s.free(a);
            break :add;
        };
        return OK;
    }
    l.out_of_memory = true;
    return ENOMEM;
}

export fn smbd_new(host: ?*const CHost, cfg: ?*const CConfig) ?*Handle {
    const ho = host orelse return null;
    if (ho.list_shares == null or ho.nt_hash == null) return null;
    const c = config(cfg orelse return null) orelse return null;
    const h = gpa.create(Handle) catch return null;
    const io = acquireIo();
    h.* = .{ .srv = undefined, .host = ho.*, .io = io };
    h.srv = smbd.Server.init(gpa, io, .{ .ctx = h, .vtable = &vtable }, c) catch {
        releaseIo();
        gpa.destroy(h);
        return null;
    };
    return h;
}

export fn smbd_set_config(h: ?*Handle, cfg: ?*const CConfig) c_int {
    const s = h orelse return EINVAL;
    const c = config(cfg orelse return EINVAL) orelse return EINVAL;
    s.srv.setConfig(c) catch return ENOMEM;
    return OK;
}

export fn smbd_listen(h: ?*Handle, addr: ?[*:0]const u8, port: u16) c_int {
    const s = h orelse return EINVAL;
    if (s.stopped.load(.acquire)) return ESTOPPED;
    if (s.n_listeners == max_listeners) return EINVAL;
    const ip = Io.net.IpAddress.parse(if (addr) |a| std.mem.span(a) else "0.0.0.0", port) catch return EINVAL;
    const l = &s.listeners[s.n_listeners];
    l.* = ip.listen(s.io, .{ .reuse_address = true }) catch |e| return switch (e) {
        error.AddressInUse => EADDRINUSE,
        error.AccessDenied => EACCES,
        error.SystemResources => ENOMEM,
        else => EFAIL,
    };
    s.srv.start(l) catch {
        l.deinit(s.io);
        return EFAIL;
    };
    s.n_listeners += 1;
    return OK;
}

export fn smbd_port(h: ?*Handle) u16 {
    return (h orelse return 0).srv.smb_port;
}

export fn smbd_adopt_fd(h: ?*Handle, fd: c_int) c_int {
    const s = h orelse return EINVAL;
    if (fd < 0) return EINVAL;
    var storage: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(@TypeOf(storage));
    const peer: Io.net.IpAddress = if (std.c.getpeername(fd, @ptrCast(&storage), &len) == 0)
        Io.Threaded.addressFromPosix(@ptrCast(@alignCast(&storage)))
    else
        .{ .ip4 = .loopback(0) };
    s.srv.adopt(.{ .socket = .{ .handle = fd, .address = peer } }) catch |e| return switch (e) {
        error.OutOfMemory => ENOMEM,
        error.Stopped => ESTOPPED,
        else => EFAIL,
    };
    return OK;
}

export fn smbd_stop(h: ?*Handle) void {
    const s = h orelse return;
    if (s.stopped.swap(true, .acq_rel)) return;
    s.srv.stop();
}

export fn smbd_wait(h: ?*Handle) c_int {
    const s = h orelse return EINVAL;
    s.srv.wait() catch return EFAIL;
    return OK;
}

export fn smbd_free(h: ?*Handle) void {
    const s = h orelse return;
    smbd_stop(s);
    for (s.listeners[0..s.n_listeners]) |*l| l.deinit(s.io);
    s.srv.deinit();
    gpa.destroy(s);
    releaseIo();
}

export fn smbd_share_changed(h: ?*Handle, name: ?[*:0]const u8, kick: c_int) c_int {
    const s = h orelse return EINVAL;
    const n = name orelse return EINVAL;
    const k: smbd.Kick = switch (kick) {
        0 => .none,
        1 => .writable,
        2 => .guests,
        else => return EINVAL,
    };
    return @intCast(@min(s.srv.reconcileShare(std.mem.span(n), k), std.math.maxInt(c_int)));
}

export fn smbd_user_changed(h: ?*Handle, name: ?[*:0]const u8) c_int {
    const s = h orelse return EINVAL;
    const n = name orelse return EINVAL;
    return @intCast(@min(s.srv.reconcileUser(std.mem.span(n)), std.math.maxInt(c_int)));
}

export fn smbd_kick(h: ?*Handle, conn_id: u64) bool {
    return (h orelse return false).srv.kick(conn_id);
}

export fn smbd_get_stats(h: ?*Handle, out: ?*CStats) c_int {
    const s = h orelse return EINVAL;
    const o = out orelse return EINVAL;
    const st = &s.srv.stats;
    s.srv.lock();
    const now = s.srv.conns.items.len;
    s.srv.unlock();
    o.* = .{
        .connections_now = now,
        .connections_total = st.connections_total.load(.monotonic),
        .bytes_in = st.bytes_in.load(.monotonic),
        .bytes_out = st.bytes_out.load(.monotonic),
        .data_read = st.data_read.load(.monotonic),
        .data_written = st.data_written.load(.monotonic),
        .requests = st.requests.load(.monotonic),
        .logon_failures = st.logon_failures.load(.monotonic),
    };
    return OK;
}

export fn smbd_activity_json(h: ?*Handle) ?[*:0]u8 {
    const s = h orelse return null;
    var aw: Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    s.srv.writeActivity(gpa, &aw.writer) catch return null;
    const out = aw.toOwnedSliceSentinel(0) catch return null;
    return out.ptr;
}

export fn smbd_free_string(p: ?[*:0]u8) void {
    std.c.free(p);
}
