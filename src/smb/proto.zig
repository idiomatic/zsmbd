//! SMB2/3 protocol constants (MS-SMB2, MS-FSCC, MS-ERREF).

pub const header_size = 64;
pub const protocol_id = [4]u8{ 0xFE, 'S', 'M', 'B' };
pub const transform_id = [4]u8{ 0xFD, 'S', 'M', 'B' };
pub const smb1_id = [4]u8{ 0xFF, 'S', 'M', 'B' };

pub const Command = enum(u16) {
    negotiate = 0,
    session_setup = 1,
    logoff = 2,
    tree_connect = 3,
    tree_disconnect = 4,
    create = 5,
    close = 6,
    flush = 7,
    read = 8,
    write = 9,
    lock = 10,
    ioctl = 11,
    cancel = 12,
    echo = 13,
    query_directory = 14,
    change_notify = 15,
    query_info = 16,
    set_info = 17,
    oplock_break = 18,
    _,
};

pub const Dialect = struct {
    pub const smb311: u16 = 0x0311;
    pub const wildcard: u16 = 0x02FF;
};

pub const Flags = struct {
    pub const server_to_redir: u32 = 0x00000001;
    pub const async_command: u32 = 0x00000002;
    pub const related_operations: u32 = 0x00000004;
    pub const signed: u32 = 0x00000008;
    pub const priority_mask: u32 = 0x00000070;
    pub const dfs_operations: u32 = 0x10000000;
    pub const replay_operation: u32 = 0x20000000;
};

pub const SecurityMode = struct {
    pub const signing_enabled: u16 = 0x0001;
    pub const signing_required: u16 = 0x0002;
};

pub const Cap = struct {
    pub const dfs: u32 = 0x01;
    pub const leasing: u32 = 0x02;
    pub const large_mtu: u32 = 0x04;
    pub const multi_channel: u32 = 0x08;
    pub const persistent_handles: u32 = 0x10;
    pub const directory_leasing: u32 = 0x20;
    pub const encryption: u32 = 0x40;
};

pub const NegCtx = struct {
    pub const preauth_integrity: u16 = 0x0001;
    pub const encryption: u16 = 0x0002;
    pub const compression: u16 = 0x0003;
    pub const netname: u16 = 0x0005;
    pub const transport: u16 = 0x0006;
    pub const rdma_transform: u16 = 0x0007;
    pub const signing: u16 = 0x0008;
};

pub const Cipher = struct {
    pub const aes128_ccm: u16 = 0x0001;
    pub const aes128_gcm: u16 = 0x0002;
    pub const aes256_ccm: u16 = 0x0003;
    pub const aes256_gcm: u16 = 0x0004;
};

pub const SigningAlg = struct {
    pub const hmac_sha256: u16 = 0;
    pub const aes_cmac: u16 = 1;
    pub const aes_gmac: u16 = 2;
};

pub const SessionFlags = struct {
    pub const is_guest: u16 = 0x0001;
    pub const is_null: u16 = 0x0002;
    pub const encrypt_data: u16 = 0x0004;
};

pub const ShareType = struct {
    pub const disk: u8 = 1;
    pub const pipe: u8 = 2;
    pub const print: u8 = 3;
};

pub const ShareFlags = struct {
    pub const manual_caching: u32 = 0x0000;
    pub const no_caching: u32 = 0x0030;
    pub const encrypt_data: u32 = 0x8000;
    pub const access_based_directory_enum: u32 = 0x0800;
};

pub const Access = struct {
    pub const read_data: u32 = 0x00000001;
    pub const write_data: u32 = 0x00000002;
    pub const append_data: u32 = 0x00000004;
    pub const read_ea: u32 = 0x00000008;
    pub const write_ea: u32 = 0x00000010;
    pub const execute: u32 = 0x00000020;
    pub const delete_child: u32 = 0x00000040;
    pub const read_attributes: u32 = 0x00000080;
    pub const write_attributes: u32 = 0x00000100;
    pub const delete: u32 = 0x00010000;
    pub const read_control: u32 = 0x00020000;
    pub const write_dac: u32 = 0x00040000;
    pub const write_owner: u32 = 0x00080000;
    pub const synchronize: u32 = 0x00100000;
    pub const access_system_security: u32 = 0x01000000;
    pub const maximum_allowed: u32 = 0x02000000;
    pub const generic_all: u32 = 0x10000000;
    pub const generic_execute: u32 = 0x20000000;
    pub const generic_write: u32 = 0x40000000;
    pub const generic_read: u32 = 0x80000000;

    pub const file_all: u32 = 0x001F01FF;
    pub const file_generic_read: u32 = 0x00120089;
    pub const file_generic_write: u32 = 0x00120116;
    pub const file_generic_execute: u32 = 0x001200A0;
    /// Rights that modify the file system.
    pub const any_write: u32 = write_data | append_data | write_ea | write_attributes | delete | delete_child | write_dac | write_owner;
    pub const read_only_max: u32 = file_generic_read | file_generic_execute;
};

pub const ShareAccess = struct {
    pub const read: u32 = 1;
    pub const write: u32 = 2;
    pub const delete: u32 = 4;
};

pub const Disposition = struct {
    pub const supersede: u32 = 0;
    pub const open: u32 = 1;
    pub const create: u32 = 2;
    pub const open_if: u32 = 3;
    pub const overwrite: u32 = 4;
    pub const overwrite_if: u32 = 5;
};

pub const CreateAction = struct {
    pub const superseded: u32 = 0;
    pub const opened: u32 = 1;
    pub const created: u32 = 2;
    pub const overwritten: u32 = 3;
};

pub const CreateOptions = struct {
    pub const directory_file: u32 = 0x00000001;
    pub const write_through: u32 = 0x00000002;
    pub const non_directory_file: u32 = 0x00000040;
    pub const delete_on_close: u32 = 0x00001000;
    pub const open_by_file_id: u32 = 0x00002000;
    pub const open_reparse_point: u32 = 0x00200000;
};

pub const Attr = struct {
    pub const readonly: u32 = 0x00000001;
    pub const hidden: u32 = 0x00000002;
    pub const system: u32 = 0x00000004;
    pub const directory: u32 = 0x00000010;
    pub const archive: u32 = 0x00000020;
    pub const normal: u32 = 0x00000080;
    pub const temporary: u32 = 0x00000100;
    pub const sparse_file: u32 = 0x00000200;
    pub const reparse_point: u32 = 0x00000400;
};

pub const InfoType = struct {
    pub const file: u8 = 1;
    pub const filesystem: u8 = 2;
    pub const security: u8 = 3;
    pub const quota: u8 = 4;
};

/// FILE_INFORMATION_CLASS values (MS-FSCC 2.4).
pub const FileInfo = struct {
    pub const directory: u8 = 1;
    pub const full_directory: u8 = 2;
    pub const both_directory: u8 = 3;
    pub const basic: u8 = 4;
    pub const standard: u8 = 5;
    pub const internal: u8 = 6;
    pub const ea: u8 = 7;
    pub const access: u8 = 8;
    pub const name: u8 = 9;
    pub const rename: u8 = 10;
    pub const link: u8 = 11;
    pub const names: u8 = 12;
    pub const disposition: u8 = 13;
    pub const position: u8 = 14;
    pub const full_ea: u8 = 15;
    pub const mode: u8 = 16;
    pub const alignment: u8 = 17;
    pub const all: u8 = 18;
    pub const allocation: u8 = 19;
    pub const end_of_file: u8 = 20;
    pub const alternate_name: u8 = 21;
    pub const stream: u8 = 22;
    pub const pipe: u8 = 23;
    pub const pipe_local: u8 = 24;
    pub const compression: u8 = 28;
    pub const network_open: u8 = 34;
    pub const attribute_tag: u8 = 35;
    pub const id_both_directory: u8 = 37;
    pub const id_full_directory: u8 = 38;
    pub const valid_data_length: u8 = 39;
    pub const normalized_name: u8 = 48;
    pub const id_information: u8 = 59;
    pub const id_extd_directory: u8 = 60;
    pub const disposition_ex: u8 = 64;
    pub const rename_ex: u8 = 65;
};

pub const FsInfo = struct {
    pub const volume: u8 = 1;
    pub const label: u8 = 2;
    pub const size: u8 = 3;
    pub const device: u8 = 4;
    pub const attribute: u8 = 5;
    pub const control: u8 = 6;
    pub const full_size: u8 = 7;
    pub const object_id: u8 = 8;
    pub const sector_size: u8 = 11;
};

pub const Fsctl = struct {
    pub const dfs_get_referrals: u32 = 0x00060194;
    pub const dfs_get_referrals_ex: u32 = 0x000601B0;
    pub const pipe_peek: u32 = 0x0011400C;
    pub const pipe_wait: u32 = 0x00110018;
    pub const pipe_transceive: u32 = 0x0011C017;
    pub const srv_copychunk: u32 = 0x001440F2;
    pub const srv_copychunk_write: u32 = 0x001480F2;
    pub const srv_enumerate_snapshots: u32 = 0x00144064;
    pub const srv_request_resume_key: u32 = 0x00140078;
    pub const srv_read_hash: u32 = 0x001441BB;
    pub const lmr_request_resiliency: u32 = 0x001401D4;
    pub const query_network_interface_info: u32 = 0x001401FC;
    pub const set_reparse_point: u32 = 0x000900A4;
    pub const get_reparse_point: u32 = 0x000900A8;
    pub const file_level_trim: u32 = 0x00098208;
    pub const validate_negotiate_info: u32 = 0x00140204;
    pub const set_sparse: u32 = 0x000900C4;
    pub const set_zero_data: u32 = 0x000980C8;
    pub const query_allocated_ranges: u32 = 0x000940CF;
    pub const create_or_get_object_id: u32 = 0x000900C0;
    pub const get_compression: u32 = 0x0009003C;
    pub const set_compression: u32 = 0x0009C040;
    pub const get_integrity_information: u32 = 0x0009027C;
};

pub const QueryDirFlags = struct {
    pub const restart_scans: u8 = 0x01;
    pub const return_single_entry: u8 = 0x02;
    pub const index_specified: u8 = 0x04;
    pub const reopen: u8 = 0x10;
};

pub const LockFlags = struct {
    pub const shared: u32 = 0x01;
    pub const exclusive: u32 = 0x02;
    pub const unlock: u32 = 0x04;
    pub const fail_immediately: u32 = 0x10;
};

/// NTSTATUS values.
pub const Status = struct {
    pub const success: u32 = 0x00000000;
    pub const pending: u32 = 0x00000103;
    pub const notify_cleanup: u32 = 0x0000010B;
    pub const notify_enum_dir: u32 = 0x0000010C;
    pub const buffer_overflow: u32 = 0x80000005;
    pub const no_more_files: u32 = 0x80000006;
    pub const not_implemented: u32 = 0xC0000002;
    pub const invalid_info_class: u32 = 0xC0000003;
    pub const info_length_mismatch: u32 = 0xC0000004;
    pub const invalid_handle: u32 = 0xC0000008;
    pub const invalid_parameter: u32 = 0xC000000D;
    pub const no_such_device: u32 = 0xC000000E;
    pub const no_such_file: u32 = 0xC000000F;
    pub const invalid_device_request: u32 = 0xC0000010;
    pub const end_of_file: u32 = 0xC0000011;
    pub const more_processing_required: u32 = 0xC0000016;
    pub const no_memory: u32 = 0xC0000017;
    pub const access_denied: u32 = 0xC0000022;
    pub const buffer_too_small: u32 = 0xC0000023;
    pub const object_name_invalid: u32 = 0xC0000033;
    pub const object_name_not_found: u32 = 0xC0000034;
    pub const object_name_collision: u32 = 0xC0000035;
    pub const object_path_invalid: u32 = 0xC0000039;
    pub const object_path_not_found: u32 = 0xC000003A;
    pub const object_path_syntax_bad: u32 = 0xC000003B;
    pub const sharing_violation: u32 = 0xC0000043;
    pub const eas_not_supported: u32 = 0xC000004F;
    pub const no_eas_on_file: u32 = 0xC0000052;
    pub const file_lock_conflict: u32 = 0xC0000054;
    pub const lock_not_granted: u32 = 0xC0000055;
    pub const delete_pending: u32 = 0xC0000056;
    pub const privilege_not_held: u32 = 0xC0000061;
    pub const logon_failure: u32 = 0xC000006D;
    pub const range_not_locked: u32 = 0xC000007E;
    pub const disk_full: u32 = 0xC000007F;
    pub const insufficient_resources: u32 = 0xC000009A;
    pub const media_write_protected: u32 = 0xC00000A2;
    pub const pipe_disconnected: u32 = 0xC00000B0;
    pub const file_is_a_directory: u32 = 0xC00000BA;
    pub const not_supported: u32 = 0xC00000BB;
    pub const network_name_deleted: u32 = 0xC00000C9;
    pub const network_access_denied: u32 = 0xC00000CA;
    pub const bad_network_name: u32 = 0xC00000CC;
    pub const request_not_accepted: u32 = 0xC00000D0;
    pub const internal_error: u32 = 0xC00000E5;
    pub const unexpected_io_error: u32 = 0xC00000E9;
    pub const directory_not_empty: u32 = 0xC0000101;
    pub const not_a_directory: u32 = 0xC0000103;
    pub const name_too_long: u32 = 0xC0000106;
    pub const too_many_opened_files: u32 = 0xC000011F;
    pub const cancelled: u32 = 0xC0000120;
    pub const cannot_delete: u32 = 0xC0000121;
    pub const file_closed: u32 = 0xC0000128;
    pub const fs_driver_required: u32 = 0xC000019C;
    pub const user_session_deleted: u32 = 0xC0000203;
    pub const not_found: u32 = 0xC0000225;
    pub const not_a_reparse_point: u32 = 0xC0000275;
    pub const network_session_expired: u32 = 0xC000035C;

    pub fn name(s: u32) []const u8 {
        return switch (s) {
            success => "SUCCESS",
            pending => "PENDING",
            buffer_overflow => "BUFFER_OVERFLOW",
            no_more_files => "NO_MORE_FILES",
            not_implemented => "NOT_IMPLEMENTED",
            invalid_info_class => "INVALID_INFO_CLASS",
            info_length_mismatch => "INFO_LENGTH_MISMATCH",
            invalid_handle => "INVALID_HANDLE",
            invalid_parameter => "INVALID_PARAMETER",
            no_such_file => "NO_SUCH_FILE",
            invalid_device_request => "INVALID_DEVICE_REQUEST",
            end_of_file => "END_OF_FILE",
            more_processing_required => "MORE_PROCESSING_REQUIRED",
            access_denied => "ACCESS_DENIED",
            buffer_too_small => "BUFFER_TOO_SMALL",
            object_name_invalid => "OBJECT_NAME_INVALID",
            object_name_not_found => "OBJECT_NAME_NOT_FOUND",
            object_name_collision => "OBJECT_NAME_COLLISION",
            object_path_not_found => "OBJECT_PATH_NOT_FOUND",
            sharing_violation => "SHARING_VIOLATION",
            delete_pending => "DELETE_PENDING",
            logon_failure => "LOGON_FAILURE",
            disk_full => "DISK_FULL",
            file_is_a_directory => "FILE_IS_A_DIRECTORY",
            not_supported => "NOT_SUPPORTED",
            bad_network_name => "BAD_NETWORK_NAME",
            directory_not_empty => "DIRECTORY_NOT_EMPTY",
            not_a_directory => "NOT_A_DIRECTORY",
            cancelled => "CANCELLED",
            cannot_delete => "CANNOT_DELETE",
            fs_driver_required => "FS_DRIVER_REQUIRED",
            user_session_deleted => "USER_SESSION_DELETED",
            not_found => "NOT_FOUND",
            lock_not_granted => "LOCK_NOT_GRANTED",
            file_lock_conflict => "FILE_LOCK_CONFLICT",
            media_write_protected => "MEDIA_WRITE_PROTECTED",
            else => "STATUS",
        };
    }
};

/// Windows epoch (1601-01-01) offset in 100ns intervals from the Unix epoch.
pub const nt_epoch_delta: u64 = 116444736000000000;

pub fn unixToNt(sec: i64, nsec: i64) u64 {
    const t: i128 = @as(i128, sec) * 10_000_000 + @divTrunc(@as(i128, nsec), 100) + nt_epoch_delta;
    if (t < 0) return 0;
    return @intCast(t);
}

pub fn ntToUnix(nt: u64) struct { sec: i64, nsec: i64 } {
    const rel: i128 = @as(i128, nt) - nt_epoch_delta;
    return .{ .sec = @intCast(@divFloor(rel, 10_000_000)), .nsec = @intCast(@mod(rel, 10_000_000) * 100) };
}
