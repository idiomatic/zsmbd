# Interoperability tests

[run.sh](run.sh) starts a real `zsmbd` and drives it with Linux's own SMB
clients. It is POSIX `sh`, runs as root on Fedora or Alpine, and CI runs it
on both, x86_64 and aarch64, after the unit tests:

```bash
zig build
sh test/interop/run.sh            # or: ... PATH/TO/zsmbd
```

Needs `smbclient`, `cifs-utils`, `rsync`, `git`, `diff`, `flock`, and
optionally `python3` (the `fcntl` lock test).

| Group | Client | Covers |
|---|---|---|
| signing required | `smbclient` | 100 MiB round trip, rename and case-insensitive lookup, 100 small files, Unicode and 200-character names, wrong password, read-only share, guest warning and refusal, 100 parallel sessions, secrets masked in argv |
| kernel CIFS | `mount -t cifs` | dialect 3.1.1, `cp -a`, `rsync`, `git clone`, `dd`, `truncate`, `touch`, `ls -l`, `df`, directory rename, `rm -rf` of a clone, `flock`, `fcntl` locks |
| control socket | CLI against the mount | `readonly` denies writes, a bare `readwrite` keeps the old view, `readwrite --kick` picks up the change, `web stop` and `start`, `nopasswd` drops the client |
| encryption required | `smbclient` | traffic is encrypted, 20 parallel sessions |
| signing off | `smbclient` | guests read a guest share, are refused elsewhere, and get no warning |

The kernel tests mount CIFS, so they need root, the host's `cifs` kernel
module, and a privileged container (`--privileged`, or `--cap-add ALL` for
Apple's `container`). Without them the group is skipped, or fails when
`INTEROP_REQUIRE_KERNEL=1`, as in CI.

Output is one `PASS` or `FAIL` line per test with the tail of its output,
then a summary; the server log is printed after a failure. The exit status
is 1 on any failure.

Each test here fails on the code before the fixes it covers: `ls -l` and
`rm -rf` on a kernel mount, the guest warning, and `--kick`.

Windows and macOS clients are tested by hand and are not covered here.
