//! TREE_CONNECT and TREE_DISCONNECT (MS-SMB2 3.3.5.7, 3.3.5.8).

const std = @import("std");
const proto = @import("proto");
const cl = @import("../client.zig");
const h = @import("../harness.zig");
const T = h.T;
const St = proto.Status;

pub const tests = [_]h.Test{
    .{ .name = "tcon.share", .spec = "MS-SMB2 3.3.5.7", .run = share },
    .{ .name = "tcon.case-insensitive", .spec = "MS-SMB2 3.3.5.7", .run = caseInsensitive },
    .{ .name = "tcon.ipc", .spec = "MS-SMB2 3.3.5.7", .run = ipc },
    .{ .name = "tcon.unknown-share", .spec = "MS-SMB2 3.3.5.7", .run = unknownShare },
    .{ .name = "tcon.no-share-name", .spec = "MS-SMB2 3.3.5.7", .run = noShareName },
    .{ .name = "tcon.distinct-ids", .spec = "MS-SMB2 3.3.5.7", .run = distinctIds },
    .{ .name = "tcon.disconnect", .spec = "MS-SMB2 3.3.5.8", .run = disconnect },
    .{ .name = "tcon.disconnect-twice", .spec = "MS-SMB2 3.3.5.8", .run = disconnectTwice },
};

/// The TREE_CONNECT response body's fixed part.
fn checkBody(t: *T, r: cl.Reply, share_type: u8) !void {
    const b = r.body();
    try t.expect(b.len >= 16, "response body is {d} bytes", .{b.len});
    try t.expectEq(@as(u16, 16), cl.get16(b, 0), "StructureSize");
    try t.expectEq(share_type, b[2], "share type");
    try t.expect(r.treeId() != 0, "tree ID is zero", .{});
}

fn share(t: *T) !void {
    const c = try t.session();
    const r = try c.treeConnect(t.env.host, t.env.share);
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    try checkBody(t, r, proto.ShareType.disk);
    try t.expect(r.signed(), "response is not signed", .{});
}

fn caseInsensitive(t: *T) !void {
    const c = try t.session();
    const upper = try std.ascii.allocUpperString(t.gpa, t.env.share);
    defer t.gpa.free(upper);
    const r = try c.treeConnect(t.env.host, upper);
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
}

fn ipc(t: *T) !void {
    const c = try t.session();
    const r = try c.treeConnect(t.env.host, "IPC$");
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    try checkBody(t, r, proto.ShareType.pipe);
}

fn unknownShare(t: *T) !void {
    const c = try t.session();
    const r = try c.treeConnect(t.env.host, "no-such-share");
    defer r.deinit();
    try t.expectStatus(St.bad_network_name, r.status());
}

fn noShareName(t: *T) !void {
    const c = try t.session();
    const unc = try std.fmt.allocPrint(t.gpa, "\\\\{s}", .{t.env.host});
    defer t.gpa.free(unc);
    const r = try c.treeConnectPath(unc);
    defer r.deinit();
    try t.expectStatus(St.bad_network_name, r.status());
}

fn distinctIds(t: *T) !void {
    const c = try t.session();
    const a = try c.treeConnect(t.env.host, t.env.share);
    defer a.deinit();
    const b = try c.treeConnect(t.env.host, t.env.share);
    defer b.deinit();
    try t.expectStatus(St.success, a.status());
    try t.expectStatus(St.success, b.status());
    try t.expect(a.treeId() != b.treeId(), "both connects got tree ID {d}", .{a.treeId()});
}

fn disconnect(t: *T) !void {
    const c = try t.session();
    const r = try c.treeConnect(t.env.host, t.env.share);
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    const d = try c.treeDisconnect(r.treeId());
    defer d.deinit();
    try t.expectStatus(St.success, d.status());
}

fn disconnectTwice(t: *T) !void {
    const c = try t.session();
    const r = try c.treeConnect(t.env.host, t.env.share);
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    const d = try c.treeDisconnect(r.treeId());
    defer d.deinit();
    try t.expectStatus(St.success, d.status());
    const again = try c.treeDisconnect(r.treeId());
    defer again.deinit();
    try t.expectStatus(St.network_name_deleted, again.status());
}
