#!/bin/sh
# Builds one release archive, dist/zsmbd-VERSION-NAME.tar.gz: zsmbd,
# libsmbd (static and shared, with smbd.h), and the README, license, and
# changelog. NAME names the platform; any further arguments go to
# `zig build` (such as -Dtarget=...). Run from the repository root.
set -eu
name=$1
shift
version=$(sed -n 's/^ *\.version = "\(.*\)",$/\1/p' build.zig.zon)
dir=zsmbd-$version-$name
rm -rf "dist/$dir" "dist/$dir.tar.gz"
zig build -Doptimize=ReleaseSafe --prefix "dist/$dir" "$@"
zig build lib -Doptimize=ReleaseSafe --prefix "dist/$dir" "$@"
cp README.md LICENSE CHANGELOG.md "dist/$dir/"
tar -C dist -czf "dist/$dir.tar.gz" "$dir"
echo "dist/$dir.tar.gz"
