//! libsmbd: the SMB 3.1.1 file server inside zsmbd, for embedding. It knows
//! connections, sessions, and files; the host (`Host`) supplies the shares
//! and users and receives the log, so libsmbd stores nothing. Its code is
//! `smb/` and `shared/`, and never `store/`, `policy/`, `web/`, or
//! `control/`. The guide is smb/README.md.

const server = @import("smb/server.zig");
const host = @import("smb/host.zig");

pub const Server = server.Server;
pub const Config = server.Config;
pub const Stats = server.Stats;
pub const Event = server.Event;
pub const Host = host.Host;
pub const Share = host.Share;
pub const Kick = host.Kick;
pub const Level = host.Level;
pub const Error = host.Error;
pub const freeShares = host.freeShares;
/// NT hash of a password, as `Host.ntHash` returns it.
pub const ntHash = @import("shared/crypto.zig").ntHash;
/// Whether this build uses AES instructions; without them (as for the
/// generic aarch64 and x86_64 CPUs) signing and encryption are far slower.
/// Build for a CPU with them (`-Dcpu`) where it has them.
pub const hardware_aes = @import("std").crypto.core.aes.has_hardware_support;

test {
    _ = @import("smb/rpc.zig");
    _ = @import("smb/auth/ntlm.zig");
    _ = @import("smb/auth/spnego.zig");
    _ = @import("smb/vfs.zig");
    _ = @import("smb/files.zig");
    _ = @import("smb/conn.zig");
    _ = @import("smb/handshake.zig");
    _ = @import("smb/server.zig");
    _ = @import("shared/crypto.zig");
    _ = @import("shared/wire.zig");
    _ = @import("shared/wire_fuzz.zig");
}
