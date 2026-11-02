//! DCE/RPC over the \PIPE\srvsvc named pipe: just enough of MS-SRVS for
//! clients to list shares (NetrShareEnum, NetrShareGetInfo).

const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("../shared/wire.zig");
const Buf = wire.Buf;

pub const ShareEntry = struct {
    name: []const u8,
    comment: []const u8 = "",
    /// STYPE_DISKTREE = 0, STYPE_IPC | STYPE_SPECIAL = 0x80000003.
    kind: u32 = 0,
};

pub const stype_disktree: u32 = 0;
pub const stype_ipc_special: u32 = 0x80000003;

const PType = struct {
    const request: u8 = 0;
    const response: u8 = 2;
    const fault: u8 = 3;
    const bind: u8 = 11;
    const bind_ack: u8 = 12;
    const alter_context: u8 = 14;
    const alter_context_resp: u8 = 15;
};

const pfc_first: u8 = 0x01;
const pfc_last: u8 = 0x02;
const nca_s_op_rng_error: u32 = 0x1c010002;
const nca_s_proto_error: u32 = 0x1c01000b;

const werr_ok: u32 = 0;
const werr_invalid_level: u32 = 124;
const werr_net_name_not_found: u32 = 2310;

/// NDR transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.
const ndr_syntax = [_]u8{ 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 2, 0, 0, 0 };
/// srvsvc interface 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0.
const srvsvc_uuid = [_]u8{ 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 };
/// Bind time feature negotiation prefix 6cb71c2c-9812-4540.
const btfn_prefix = [_]u8{ 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45 };

/// Largest reassembled request stub; srvsvc requests are a few hundred bytes.
const max_request_stub = 64 * 1024;

pub const Pipe = struct {
    gpa: Allocator,
    /// Bytes received from the client not yet forming a complete PDU.
    in: std.ArrayList(u8) = .empty,
    /// Stub data of a fragmented request being reassembled.
    stub: std.ArrayList(u8) = .empty,
    /// Response bytes waiting to be READ by the client.
    out: std.ArrayList(u8) = .empty,
    max_xmit: u16 = 4280,
    bound: bool = false,

    pub fn init(gpa: Allocator) Pipe {
        return .{ .gpa = gpa };
    }

    pub fn deinit(p: *Pipe) void {
        p.in.deinit(p.gpa);
        p.stub.deinit(p.gpa);
        p.out.deinit(p.gpa);
    }

    /// Feed bytes written by the client; complete PDUs are processed and
    /// their responses queued for `read`.
    pub fn write(p: *Pipe, data: []const u8, shares: []const ShareEntry) !void {
        try p.in.appendSlice(p.gpa, data);
        while (p.in.items.len >= 16) {
            const frag_len = wire.get16(p.in.items, 8);
            // A rejected PDU is dropped, so the next write starts clean.
            errdefer p.in.clearRetainingCapacity();
            if (frag_len < 16) return error.Malformed;
            if (p.in.items.len < frag_len) break;
            try p.handlePdu(p.in.items[0..frag_len], shares);
            p.in.replaceRangeAssumeCapacity(0, frag_len, &.{});
        }
    }

    /// Copy queued response bytes into `buf`; returns bytes copied.
    pub fn read(p: *Pipe, buf: []u8) usize {
        const n = @min(buf.len, p.out.items.len);
        @memcpy(buf[0..n], p.out.items[0..n]);
        p.out.replaceRangeAssumeCapacity(0, n, &.{});
        return n;
    }

    pub fn pending(p: *const Pipe) usize {
        return p.out.items.len;
    }

    fn handlePdu(p: *Pipe, pdu: []const u8, shares: []const ShareEntry) !void {
        if (pdu[0] != 5 or pdu[4] & 0xf0 != 0x10) return error.Malformed; // v5, little-endian
        const ptype = pdu[2];
        const flags = pdu[3];
        const call_id = wire.get32(pdu, 12);
        switch (ptype) {
            PType.bind, PType.alter_context => try p.bind(pdu, call_id, ptype),
            PType.request => {
                if (pdu.len < 24) return error.Malformed;
                const auth_len = wire.get16(pdu, 10);
                const trailer: usize = if (auth_len > 0) @as(usize, auth_len) + 8 else 0;
                if (trailer > pdu.len - 24) return error.Malformed;
                const stub_end = pdu.len - trailer;
                if (flags & pfc_first != 0) p.stub.clearRetainingCapacity();
                // Fragments without PFC_LAST must not grow the stub forever.
                if (p.stub.items.len + (stub_end - 24) > max_request_stub) return error.Malformed;
                try p.stub.appendSlice(p.gpa, pdu[24..stub_end]);
                if (flags & pfc_last == 0) return;
                const ctx_id = wire.get16(pdu, 20);
                const opnum = wire.get16(pdu, 22);
                var resp = Buf.init(p.gpa);
                defer resp.deinit();
                const ok = switch (opnum) {
                    15 => netrShareEnum(&resp, p.stub.items, shares),
                    16 => netrShareGetInfo(&resp, p.stub.items, shares),
                    else => false,
                } catch false;
                if (ok) {
                    try p.respond(call_id, ctx_id, resp.items());
                } else {
                    try p.fault(call_id, ctx_id, if (opnum == 15 or opnum == 16) nca_s_proto_error else nca_s_op_rng_error);
                }
            },
            else => try p.fault(call_id, 0, nca_s_proto_error),
        }
    }

    fn header(b: *Buf, ptype: u8, flags: u8, call_id: u32) !void {
        try b.bytes(&.{ 5, 0, ptype, flags, 0x10, 0, 0, 0 });
        try b.u16_(0); // frag_length, patched later
        try b.u16_(0); // auth_length
        try b.u32_(call_id);
    }

    fn bind(p: *Pipe, pdu: []const u8, call_id: u32, ptype: u8) !void {
        if (pdu.len < 28) return error.Malformed;
        const max_recv = wire.get16(pdu, 18);
        const assoc = wire.get32(pdu, 20);
        if (max_recv >= 1024) p.max_xmit = @min(max_recv, 4280);
        const n_ctx = pdu[24];

        var b = Buf.init(p.gpa);
        defer b.deinit();
        try header(&b, if (ptype == PType.bind) PType.bind_ack else PType.alter_context_resp, pfc_first | pfc_last, call_id);
        try b.u16_(p.max_xmit);
        try b.u16_(p.max_xmit);
        try b.u32_(if (assoc != 0) assoc else 0x12345);
        if (ptype == PType.bind) {
            const port = "\\PIPE\\srvsvc\x00";
            try b.u16_(port.len);
            try b.bytes(port);
        } else {
            try b.u16_(0);
        }
        try b.alignTo(4);
        try b.u8_(n_ctx);
        try b.zeros(3);

        var off: usize = 28;
        var i: usize = 0;
        while (i < n_ctx) : (i += 1) {
            if (pdu.len < off + 4 + 20) return error.Malformed;
            const n_syn = pdu[off + 2];
            const abstract = pdu[off + 4 .. off + 24];
            var accepted = false;
            var btfn = false;
            var j: usize = 0;
            while (j < n_syn) : (j += 1) {
                const so = off + 24 + j * 20;
                if (pdu.len < so + 20) return error.Malformed;
                const syn = pdu[so .. so + 20];
                if (std.mem.eql(u8, syn, &ndr_syntax)) accepted = true;
                if (std.mem.eql(u8, syn[0..8], &btfn_prefix)) btfn = true;
            }
            const iface_ok = std.mem.eql(u8, abstract[0..16], &srvsvc_uuid);
            if (accepted and iface_ok) {
                try b.u16_(0); // acceptance
                try b.u16_(0);
                try b.bytes(&ndr_syntax);
                p.bound = true;
            } else if (btfn) {
                try b.u16_(3); // negotiate_ack
                try b.u16_(0);
                try b.zeros(20);
            } else {
                try b.u16_(2); // provider_rejection
                try b.u16_(if (iface_ok) 2 else 1); // transfer syntaxes / abstract syntax not supported
                try b.zeros(20);
            }
            off += 24 + @as(usize, n_syn) * 20;
        }
        b.set16(8, @intCast(b.len()));
        try p.out.appendSlice(p.gpa, b.items());
    }

    fn respond(p: *Pipe, call_id: u32, ctx_id: u16, stub: []const u8) !void {
        const max_stub = p.max_xmit - 24;
        var off: usize = 0;
        while (true) {
            const n = @min(max_stub, stub.len - off);
            var flags: u8 = 0;
            if (off == 0) flags |= pfc_first;
            if (off + n == stub.len) flags |= pfc_last;
            var b = Buf.init(p.gpa);
            defer b.deinit();
            try header(&b, PType.response, flags, call_id);
            try b.u32_(@intCast(stub.len - off)); // alloc_hint
            try b.u16_(ctx_id);
            try b.u8_(0); // cancel_count
            try b.u8_(0);
            try b.bytes(stub[off .. off + n]);
            b.set16(8, @intCast(b.len()));
            try p.out.appendSlice(p.gpa, b.items());
            off += n;
            if (off == stub.len) break;
        }
    }

    fn fault(p: *Pipe, call_id: u32, ctx_id: u16, code: u32) !void {
        var b = Buf.init(p.gpa);
        defer b.deinit();
        try header(&b, PType.fault, pfc_first | pfc_last, call_id);
        try b.u32_(0);
        try b.u16_(ctx_id);
        try b.u8_(0);
        try b.u8_(0);
        try b.u32_(code);
        try b.u32_(0);
        b.set16(8, @intCast(b.len()));
        try p.out.appendSlice(p.gpa, b.items());
    }
};

// ---------------------------------------------------------------- NDR helpers

const Ndr = struct {
    b: []const u8,
    pos: usize = 0,

    fn alignTo(r: *Ndr, a: usize) void {
        r.pos = std.mem.alignForward(usize, r.pos, a);
    }
    fn u32_(r: *Ndr) !u32 {
        r.alignTo(4);
        if (r.pos + 4 > r.b.len) return error.Malformed;
        defer r.pos += 4;
        return wire.get32(r.b, r.pos);
    }
    /// Conformant varying UTF-16 string; returns the raw UTF-16 bytes (without terminator).
    fn string(r: *Ndr) ![]const u8 {
        _ = try r.u32_(); // max_count
        _ = try r.u32_(); // offset
        const actual = try r.u32_();
        const len = @as(usize, actual) * 2;
        if (r.pos + len > r.b.len) return error.Malformed;
        var s = r.b[r.pos .. r.pos + len];
        r.pos += len;
        if (s.len >= 2 and wire.get16(s, s.len - 2) == 0) s = s[0 .. s.len - 2];
        return s;
    }
    fn uniqueString(r: *Ndr) !void {
        if (try r.u32_() != 0) _ = try r.string();
    }
};

/// Conformant varying string including the NUL terminator, 4-byte aligned.
fn putString(b: *Buf, base: usize, s: []const u8) !void {
    try b.alignFrom(base, 4);
    const n: u32 = @intCast(wire.utf16Len(s) / 2 + 1);
    try b.u32_(n);
    try b.u32_(0);
    try b.u32_(n);
    _ = try b.utf16(s);
    try b.u16_(0);
}

fn netrShareEnum(b: *Buf, stub: []const u8, shares: []const ShareEntry) !bool {
    var r: Ndr = .{ .b = stub };
    try r.uniqueString(); // ServerName
    const level = try r.u32_();
    const base = b.len();
    if (level != 0 and level != 1) {
        try b.u32_(level);
        try b.u32_(level);
        try b.u32_(0);
        try b.u32_(0); // TotalEntries
        try b.u32_(0); // ResumeHandle (null)
        try b.u32_(werr_invalid_level);
        return true;
    }
    const n: u32 = @intCast(shares.len);
    try b.u32_(level);
    try b.u32_(level); // union switch
    try b.u32_(0x00020000); // container referent
    try b.u32_(n); // EntriesRead
    try b.u32_(if (n > 0) 0x00020004 else 0); // Buffer referent
    if (n > 0) {
        try b.u32_(n); // array max_count
        var ref: u32 = 0x00020008;
        for (shares) |_| {
            try b.u32_(ref);
            ref += 4;
            if (level == 1) {
                // type is filled below via second pass
                try b.u32_(0);
                try b.u32_(ref);
                ref += 4;
            }
        }
        // Patch types (kept separate so referent ids stay sequential).
        if (level == 1) {
            const arr = base + 24;
            for (shares, 0..) |s, i| b.set32(arr + i * 12 + 4, s.kind);
        }
        for (shares) |s| {
            try putString(b, base, s.name);
            if (level == 1) try putString(b, base, s.comment);
        }
    }
    try b.alignFrom(base, 4);
    try b.u32_(n); // TotalEntries
    try b.u32_(0x00020100); // ResumeHandle referent
    try b.u32_(0);
    try b.u32_(werr_ok);
    return true;
}

fn netrShareGetInfo(b: *Buf, stub: []const u8, shares: []const ShareEntry) !bool {
    var r: Ndr = .{ .b = stub };
    try r.uniqueString(); // ServerName
    const name16 = try r.string();
    const level = try r.u32_();
    var name_buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&name_buf);
    const name = wire.utf16ToUtf8(fba.allocator(), name16) catch return false;

    const base = b.len();
    var found: ?ShareEntry = null;
    for (shares) |s| if (std.ascii.eqlIgnoreCase(s.name, name)) {
        found = s;
        break;
    };
    const supported = switch (level) {
        0, 1, 2, 501, 1005 => true,
        else => false,
    };
    try b.u32_(level);
    if (found == null or !supported) {
        try b.u32_(0);
        try b.u32_(if (!supported) werr_invalid_level else werr_net_name_not_found);
        return true;
    }
    const s = found.?;
    try b.u32_(0x00020000);
    switch (level) {
        0 => {
            try b.u32_(0x00020004);
            try putString(b, base, s.name);
        },
        1 => {
            try b.u32_(0x00020004);
            try b.u32_(s.kind);
            try b.u32_(0x00020008);
            try putString(b, base, s.name);
            try putString(b, base, s.comment);
        },
        2 => {
            try b.u32_(0x00020004); // netname
            try b.u32_(s.kind);
            try b.u32_(0x00020008); // remark
            try b.u32_(0); // permissions
            try b.u32_(0xFFFFFFFF); // max_uses
            try b.u32_(0); // current_uses
            try b.u32_(0x0002000c); // path
            try b.u32_(0); // passwd (null)
            try putString(b, base, s.name);
            try putString(b, base, s.comment);
            try putString(b, base, "C:\\");
        },
        501 => {
            try b.u32_(0x00020004);
            try b.u32_(s.kind);
            try b.u32_(0x00020008);
            try b.u32_(0); // flags
            try putString(b, base, s.name);
            try putString(b, base, s.comment);
        },
        1005 => try b.u32_(0), // shi1005_flags
        else => unreachable,
    }
    try b.alignFrom(base, 4);
    try b.u32_(werr_ok);
    return true;
}

// ---------------------------------------------------------------- tests

fn testBind(gpa: Allocator) ![]u8 {
    var b = Buf.init(gpa);
    errdefer b.deinit();
    try Pipe.header(&b, PType.bind, pfc_first | pfc_last, 1);
    try b.u16_(4280);
    try b.u16_(4280);
    try b.u32_(0);
    try b.u8_(2); // two contexts
    try b.zeros(3);
    // ctx 0: srvsvc / NDR
    try b.u16_(0);
    try b.u8_(1);
    try b.u8_(0);
    try b.bytes(&srvsvc_uuid);
    try b.bytes(&.{ 3, 0, 0, 0 });
    try b.bytes(&ndr_syntax);
    // ctx 1: srvsvc / bind time feature negotiation
    try b.u16_(1);
    try b.u8_(1);
    try b.u8_(0);
    try b.bytes(&srvsvc_uuid);
    try b.bytes(&.{ 3, 0, 0, 0 });
    try b.bytes(&btfn_prefix);
    try b.bytes(&.{ 0x03, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 });
    b.set16(8, @intCast(b.len()));
    return b.list.toOwnedSlice(gpa);
}

test "bind then NetrShareEnum level 1" {
    const gpa = std.testing.allocator;
    var p = Pipe.init(gpa);
    defer p.deinit();
    const shares = [_]ShareEntry{
        .{ .name = "public", .comment = "Public files" },
        .{ .name = "IPC$", .comment = "IPC Service", .kind = stype_ipc_special },
    };
    const bind_pdu = try testBind(gpa);
    defer gpa.free(bind_pdu);
    // Deliver the bind in two pieces to exercise reassembly.
    try p.write(bind_pdu[0..10], &shares);
    try std.testing.expectEqual(@as(usize, 0), p.pending());
    try p.write(bind_pdu[10..], &shares);
    var buf: [8192]u8 = undefined;
    var n = p.read(&buf);
    try std.testing.expect(n > 24);
    try std.testing.expectEqual(PType.bind_ack, buf[2]);
    try std.testing.expectEqual(@as(usize, n), wire.get16(&buf, 8));
    try std.testing.expect(p.bound);

    // NetrShareEnum request: ServerName "\\srv", level 1, null container, prefmax, null resume.
    var stub = Buf.init(gpa);
    defer stub.deinit();
    try stub.u32_(0x20000);
    try putString(&stub, 0, "\\\\srv");
    try stub.alignTo(4);
    try stub.u32_(1);
    try stub.u32_(1);
    try stub.u32_(0x20004);
    try stub.u32_(0);
    try stub.u32_(0);
    try stub.u32_(0xFFFFFFFF);
    try stub.u32_(0);
    var req = Buf.init(gpa);
    defer req.deinit();
    try Pipe.header(&req, PType.request, pfc_first | pfc_last, 2);
    try req.u32_(@intCast(stub.len()));
    try req.u16_(0);
    try req.u16_(15);
    try req.bytes(stub.items());
    req.set16(8, @intCast(req.len()));
    try p.write(req.items(), &shares);
    n = p.read(&buf);
    try std.testing.expectEqual(PType.response, buf[2]);
    const out = buf[24..n];
    try std.testing.expectEqual(@as(u32, 1), wire.get32(out, 0)); // level
    try std.testing.expectEqual(@as(u32, 2), wire.get32(out, 12)); // EntriesRead
    try std.testing.expectEqual(@as(u32, 2), wire.get32(out, 20)); // array count
    try std.testing.expectEqual(stype_ipc_special, wire.get32(out, 24 + 12 + 4));
    try std.testing.expectEqual(werr_ok, wire.get32(out, out.len - 4));
    // First deferred string is "public".
    const s0 = 24 + 2 * 12;
    try std.testing.expectEqual(@as(u32, 7), wire.get32(out, s0 + 8));
    const name = try wire.utf16ToUtf8(gpa, out[s0 + 12 .. s0 + 12 + 12]);
    defer gpa.free(name);
    try std.testing.expectEqualStrings("public", name);
}

test "NetrShareGetInfo unknown share" {
    const gpa = std.testing.allocator;
    var stub = Buf.init(gpa);
    defer stub.deinit();
    try stub.u32_(0);
    try putString(&stub, 0, "nope");
    try stub.alignTo(4);
    try stub.u32_(1);
    var out = Buf.init(gpa);
    defer out.deinit();
    try std.testing.expect(try netrShareGetInfo(&out, stub.items(), &.{.{ .name = "public" }}));
    try std.testing.expectEqual(werr_net_name_not_found, wire.get32(out.items(), 8));
}

test "fuzz: DCE/RPC pipe" {
    const gpa = std.testing.allocator;
    const bind = try testBind(gpa);
    defer gpa.free(bind);
    // A NetrShareEnum request after the bind.
    var stub = Buf.init(gpa);
    defer stub.deinit();
    try stub.u32_(0x20000);
    try putString(&stub, 0, "\\\\srv");
    try stub.alignTo(4);
    for ([_]u32{ 1, 1, 0x20004, 0, 0, 0xFFFFFFFF, 0 }) |v| try stub.u32_(v);
    var req = Buf.init(gpa);
    defer req.deinit();
    try req.bytes(bind);
    const start = req.len();
    try Pipe.header(&req, PType.request, pfc_first | pfc_last, 2);
    try req.u32_(@intCast(stub.len()));
    try req.u16_(0);
    try req.u16_(15);
    try req.bytes(stub.items());
    req.set16(start + 8, @intCast(req.len() - start));
    try @import("../shared/fuzz.zig").run({}, struct {
        fn one(_: void, in: []const u8) !void {
            var p = Pipe.init(std.testing.allocator);
            defer p.deinit();
            const shares = [_]ShareEntry{ .{ .name = "hal", .comment = "x" }, .{ .name = "IPC$", .kind = stype_ipc_special } };
            // Deliver in two pieces to exercise reassembly.
            const cut = in.len / 3;
            p.write(in[0..cut], &shares) catch return;
            p.write(in[cut..], &shares) catch return;
            var buf: [256]u8 = undefined;
            while (p.read(&buf) > 0) {}
        }
    }.one, &.{ bind, req.items() });
}
