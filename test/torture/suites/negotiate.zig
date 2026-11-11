//! NEGOTIATE: dialect and context handling (MS-SMB2 3.3.5.4).

const std = @import("std");
const proto = @import("proto");
const cl = @import("../client.zig");
const h = @import("../harness.zig");
const T = h.T;
const St = proto.Status;

pub const tests = [_]h.Test{
    .{ .name = "negotiate.basic", .spec = "MS-SMB2 3.3.5.4", .run = basic },
    .{ .name = "negotiate.picks-311", .spec = "MS-SMB2 3.3.5.4", .run = picks311 },
    .{ .name = "negotiate.no-311", .spec = "AGENTS.md: no older dialect", .run = no311 },
    .{ .name = "negotiate.no-dialects", .spec = "MS-SMB2 3.3.5.4", .run = noDialects },
    .{ .name = "negotiate.no-preauth-context", .spec = "MS-SMB2 3.3.5.4", .run = noPreauth },
    .{ .name = "negotiate.preauth-context-twice", .spec = "MS-SMB2 3.3.5.4", .run = preauthTwice },
    .{ .name = "negotiate.preauth-no-overlap", .spec = "MS-SMB2 3.3.5.4", .run = preauthNoOverlap },
    .{ .name = "negotiate.signing-no-overlap", .spec = "AGENTS.md: AES-CMAC only", .run = signingNoOverlap },
    .{ .name = "negotiate.repeated", .spec = "MS-SMB2 3.3.5.4", .run = repeated },
    .{ .name = "negotiate.smb1-upgrade", .spec = "MS-SMB2 3.3.5.3.1", .run = smb1Upgrade },
};

fn basic(t: *T) !void {
    const c = try t.dial();
    const r = try c.negotiate(.{});
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    try t.expectEq(@as(u16, @intFromEnum(proto.Command.negotiate)), r.command(), "command");
    try t.expectEq(@as(u64, 0), r.messageId(), "message ID");
    try t.expect(r.flags() & proto.Flags.server_to_redir != 0, "response flag not set", .{});
    try t.expect(r.credits() >= 1, "no credits granted", .{});
    const n = c.neg;
    try t.expectEq(proto.Dialect.smb311, n.dialect, "dialect");
    try t.expectEq(@as(?u16, 1), n.preauth_alg, "preauth hash (SHA-512)");
    try t.expectEq(@as(?u16, proto.SigningAlg.aes_cmac), n.signing_alg, "signing algorithm");
    try t.expect(n.cipher != null, "no cipher chosen though the client offered two", .{});
    try t.expect(n.security_mode & proto.SecurityMode.signing_enabled != 0, "signing not enabled", .{});
    try t.expect(n.capabilities & proto.Cap.large_mtu != 0, "no large MTU", .{});
    try t.expect(n.max_transact >= 65536 and n.max_read >= 65536 and n.max_write >= 65536, "maximum sizes below 64 KiB", .{});
    try t.expect(n.spnego, "security buffer is not SPNEGO", .{});
    try t.expect(!std.mem.allEqual(u8, &n.guid, 0), "server GUID is all zero", .{});
    if (t.env.profile == .zsmbd)
        try t.expect(n.security_mode & proto.SecurityMode.signing_required != 0, "signing not required by default", .{});
}

fn picks311(t: *T) !void {
    const c = try t.dial();
    const r = try c.negotiate(.{ .dialects = &.{ 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 } });
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    try t.expectEq(proto.Dialect.smb311, c.neg.dialect, "dialect");
}

fn no311(t: *T) !void {
    try t.only(.zsmbd);
    const c = try t.dial();
    const r = try c.negotiate(.{ .dialects = &.{ 0x0300, 0x0302 } });
    defer r.deinit();
    try t.expectStatus(St.not_supported, r.status());
    try t.expect(c.expectClosed(), "connection left open", .{});
}

fn noDialects(t: *T) !void {
    const c = try t.dial();
    const r = try c.negotiate(.{ .dialects = &.{} });
    defer r.deinit();
    try t.expectStatus(St.invalid_parameter, r.status());
}

fn noPreauth(t: *T) !void {
    const c = try t.dial();
    const r = try c.negotiate(.{ .preauth_algs = null });
    defer r.deinit();
    try t.expectStatus(St.invalid_parameter, r.status());
}

fn preauthTwice(t: *T) !void {
    const c = try t.dial();
    const r = try c.negotiate(.{ .preauth_twice = true });
    defer r.deinit();
    try t.expectStatus(St.invalid_parameter, r.status());
}

fn preauthNoOverlap(t: *T) !void {
    const c = try t.dial();
    const r = try c.negotiate(.{ .preauth_algs = &.{0x7777} });
    defer r.deinit();
    try t.expectStatus(St.no_preauth_integrity_hash_overlap, r.status());
}

fn signingNoOverlap(t: *T) !void {
    try t.only(.zsmbd);
    const c = try t.dial();
    const r = try c.negotiate(.{ .signing_algs = &.{proto.SigningAlg.hmac_sha256} });
    defer r.deinit();
    try t.expectStatus(St.no_signing_algorithm_overlap, r.status());
}

/// A second NEGOTIATE on a connection must end it.
fn repeated(t: *T) !void {
    const c = try t.negotiated();
    const frame = try c.negotiateFrame(.{ .message_id = null });
    defer t.gpa.free(frame);
    try c.sendRaw(frame);
    if (try c.recvOrClosed()) |r| {
        defer r.deinit();
        try t.expect(r.status() != St.success, "a second NEGOTIATE succeeded", .{});
        try t.expect(c.expectClosed(), "connection left open", .{});
    }
}

/// An SMB1 NEGOTIATE offering "SMB 2.???" is answered in SMB2 with the
/// wildcard dialect, and the client then negotiates for real.
fn smb1Upgrade(t: *T) !void {
    const c = try t.dial();
    var m = cl.Msg.init(t.gpa);
    defer m.deinit();
    try m.bytes(&proto.smb1_id);
    try m.u8_(0x72); // SMB_COM_NEGOTIATE
    try m.u32_(0); // Status
    try m.u8_(0x18); // Flags
    try m.u16_(0xc853); // Flags2
    try m.zeros(2 + 8 + 2 + 2 + 2 + 2 + 2); // PidHigh through Mid
    try m.u8_(0); // WordCount
    const dialects = "\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00";
    try m.u16_(dialects.len);
    try m.bytes(dialects);
    try c.sendRaw(m.items());
    const r = try c.recv();
    defer r.deinit();
    try t.expectStatus(St.success, r.status());
    try t.expectEq(@as(u16, @intFromEnum(proto.Command.negotiate)), r.command(), "command");
    try t.expectEq(proto.Dialect.wildcard, cl.get16(r.raw, cl.hdr + 4), "dialect");

    const r2 = try c.negotiate(.{ .message_id = 1 });
    defer r2.deinit();
    try t.expectStatus(St.success, r2.status());
    try t.expectEq(proto.Dialect.smb311, c.neg.dialect, "dialect after the upgrade");
}
