#!/bin/sh
# Builds the two release archives of one platform, in dist/:
#   zsmbd-VERSION-NAME.tar.gz      the server: bin/zsmbd and its docs
#   zsmbd-dev-VERSION-NAME.tar.gz  libsmbd for embedding: lib/ (static
#                                  and shared), include/smbd.h, its guide
# NAME names the platform; any further arguments go to `zig build` (such
# as -Dtarget=...). Each archive is smoke-tested on the building host:
# zsmbd --version, and test/c/smoke.c built with the system C compiler
# ($CC, else cc) against the packaged libsmbd.a, as an embedder would.
# Run from the repository root.
set -eu
name=$1
shift
version=$(sed -n 's/^ *\.version = "\(.*\)",$/\1/p' build.zig.zon)
stage=dist/stage-$name
srv=zsmbd-$version-$name
dev=zsmbd-dev-$version-$name
rm -rf "$stage" "dist/$srv" "dist/$dev" "dist/$srv.tar.gz" "dist/$dev.tar.gz"
zig build -Doptimize=ReleaseSafe --prefix "$stage" "$@"
zig build lib -Doptimize=ReleaseSafe --prefix "$stage" "$@"

mkdir -p "dist/$srv/bin" "dist/$dev"
cp "$stage/bin/zsmbd" "dist/$srv/bin/"
cp README.md LICENSE CHANGELOG.md "dist/$srv/"
cp -RP "$stage/lib" "$stage/include" "dist/$dev/"
cp src/smb/README.md "dist/$dev/README.md"
cp LICENSE CHANGELOG.md "dist/$dev/"

"dist/$srv/bin/zsmbd" --version
"${CC:-cc}" -std=c11 -D_DEFAULT_SOURCE -I"dist/$dev/include" test/c/smoke.c \
    "dist/$dev/lib/libsmbd.a" -o "$stage/smoke"
"$stage/smoke"
echo "libsmbd smoke test passed"

tar -C dist -czf "dist/$srv.tar.gz" "$srv"
tar -C dist -czf "dist/$dev.tar.gz" "$dev"
rm -rf "$stage"
echo "dist/$srv.tar.gz"
echo "dist/$dev.tar.gz"
