const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sqlite_prefix = b.option([]const u8, "sqlite-prefix", "Installation prefix of libsqlite3 (contains lib/)");

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    if (sqlite_prefix) |p| mod.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ p, "lib" }) });
    mod.linkSystemLibrary("sqlite3", .{});

    // The version has one source, build.zig.zon; the code reads it as
    // @import("build_options").version.
    const options = b.addOptions();
    options.addOption([]const u8, "version", @import("build.zig.zon").version);
    mod.addOptions("build_options", options);

    // NT hash compiled to WebAssembly for the admin web page, embedded in the
    // binary as the "nthash_wasm" module (`bytes`).
    const wasm = b.addExecutable(.{
        .name = "nthash",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/nthash_wasm.zig"),
            .target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
            .optimize = .ReleaseSmall,
        }),
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    const wasm_files = b.addWriteFiles();
    _ = wasm_files.addCopyFile(wasm.getEmittedBin(), "nthash.wasm");
    const wasm_mod = b.createModule(.{
        .root_source_file = wasm_files.add("nthash_embed.zig", "pub const bytes = @embedFile(\"nthash.wasm\");\n"),
    });
    mod.addImport("nthash_wasm", wasm_mod);

    const exe = b.addExecutable(.{ .name = "zsmbd", .root_module = mod });
    // On Linux aarch64 Zig can pick an older glibc than the system's, and
    // the linker then rejects the newer libc symbols that libsqlite3 uses.
    exe.linker_allow_shlib_undefined = true;
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run zsmbd");
    run_step.dependOn(&run_cmd.step);

    // libsmbd, the SMB server for embedding: smb/ and shared/ only, so it
    // links neither SQLite nor anything else of zsmbd's.
    const smbd = b.addModule("smbd", .{
        .root_source_file = b.path("src/smbd.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const tests = b.addTest(.{ .root_module = mod });
    tests.linker_allow_shlib_undefined = true;
    const smbd_tests = b.addTest(.{ .root_module = smbd });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(&b.addRunArtifact(smbd_tests).step);

    // Compile-only check for other targets (no linking, so no sqlite needed):
    //   zig build check -Dtarget=x86_64-linux-gnu
    const check_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    check_mod.addImport("nthash_wasm", wasm_mod);
    check_mod.addOptions("build_options", options);
    const check_obj = b.addExecutable(.{ .name = "zsmbd-check", .root_module = check_mod });
    const check_step = b.step("check", "Type-check without linking");
    check_step.dependOn(&check_obj.step);
    const check_tests = b.addTest(.{ .root_module = check_mod });
    check_step.dependOn(&check_tests.step);
    check_step.dependOn(&b.addTest(.{ .root_module = smbd }).step);
}
