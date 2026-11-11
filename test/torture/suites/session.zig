//! SESSION_SETUP, LOGOFF, and signing (MS-SMB2 3.3.5.5, 3.3.5.6, 3.3.5.2.4).

const std = @import("std");
const proto = @import("proto");
const cl = @import("../client.zig");
const h = @import("../harness.zig");
const T = h.T;
const St = proto.Status;

pub const tests = [_]h.Test{
    .{ .name = "session.logon", .spec = "MS-SMB2 3.3.5.5", .run = logon },
    .{ .name = "session.bad-password", .spec = "MS-SMB2 3.3.5.5", .run = badPassword },
    .{ .name = "session.unknown-user", .spec = "MS-SMB2 3.3.5.5", .run = unknownUser },
    .{ .name = "session.logoff", .spec = "MS-SMB2 3.3.5.6", .run = logoff },
    .{ .name = "session.no-session", .spec = "MS-SMB2 3.3.5.2.9", .run = noSession },
    .{ .name = "session.foreign-session-id", .spec = "MS-SMB2 3.3.5.2.9", .run = foreignSessionId },
    .{ .name = "session.unsigned-request", .spec = "MS-SMB2 3.3.5.2.4", .run = unsignedRequest },
    .{ .name = "session.bad-signature", .spec = "MS-SMB2 3.3.5.2.4", .run = badSignature },
};

fn logon(t: *T) !void {
    const c = try t.negotiated();
    const res = try c.login(t.env.user, t.env.password);
    try t.expectStatus(St.success, res.status);
    try t.expect(c.session_id != 0, "session ID is zero", .{});
    try t.expect(res.session_flags & (proto.SessionFlags.is_guest | proto.SessionFlags.is_null) == 0, "session flags 0x{x} mark a guest", .{res.session_flags});
    try t.expect(res.signed, "the final response is not signed", .{});
    const r = try c.treeConnect(t.env.host, "IPC$");
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    try t.expect(r.signed(), "TREE_CONNECT response is not signed", .{});
}

fn badPassword(t: *T) !void {
    const c = try t.negotiated();
    const res = try c.login(t.env.user, "not the password");
    try t.expectStatus(St.logon_failure, res.status);
    try t.expect(!res.signed, "a failure response is signed", .{});
}

/// A wrong password and an unknown user must look alike.
fn unknownUser(t: *T) !void {
    const c = try t.negotiated();
    const res = try c.login("skynet", "x");
    try t.expectStatus(St.logon_failure, res.status);
}

fn logoff(t: *T) !void {
    const c = try t.session();
    const sid = c.session_id;
    const r = try c.logoff();
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    const again = try c.treeConnect(t.env.host, t.env.share);
    defer again.deinit();
    try t.expectEq(sid, c.session_id, "session ID");
    try t.expectStatus(St.user_session_deleted, again.status());
}

fn noSession(t: *T) !void {
    const c = try t.negotiated();
    const r = try c.treeConnect(t.env.host, t.env.share);
    defer r.deinit();
    try t.expectStatus(St.user_session_deleted, r.status());
}

/// Another connection's session ID names nothing here. (ECHO is exempt
/// from session checks, so the tests probe with TREE_CONNECT.)
fn foreignSessionId(t: *T) !void {
    const a = try t.session();
    const b = try t.negotiated();
    b.session_id = a.session_id;
    b.signing_key = a.signing_key;
    const r = try b.treeConnect(t.env.host, t.env.share);
    defer r.deinit();
    try t.expectStatus(St.user_session_deleted, r.status());
}

fn unsignedRequest(t: *T) !void {
    try t.only(.zsmbd); // signing is required by default
    const c = try t.session();
    const body = try cl.treeConnectBody(t.gpa, "\\\\x\\IPC$");
    defer t.gpa.free(body);
    const r = try c.call(.{ .command = @intFromEnum(proto.Command.tree_connect), .session_id = c.session_id, .sign = false, .body = body });
    defer r.deinit();
    try t.expectStatus(St.access_denied, r.status());
}

fn badSignature(t: *T) !void {
    const c = try t.session();
    const body = try cl.treeConnectBody(t.gpa, "\\\\x\\IPC$");
    defer t.gpa.free(body);
    const frame = try c.build(.{ .command = @intFromEnum(proto.Command.tree_connect), .session_id = c.session_id, .body = body });
    defer t.gpa.free(frame);
    frame[50] ^= 0x01;
    try c.sendRaw(frame);
    const r = try c.recv();
    defer r.deinit();
    try t.expectStatus(St.access_denied, r.status());
}
