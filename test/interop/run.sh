#!/bin/sh
# Interoperability tests: real Linux SMB clients against a running zsmbd.
# See README.md in this directory. Run as root on Fedora or Alpine:
#
#     test/interop/run.sh [PATH/TO/zsmbd]
#
# The kernel-client tests are skipped when this host can't mount CIFS;
# INTEROP_REQUIRE_KERNEL=1 makes that a failure instead.

set -u
BIN=${1:-./zig-out/bin/zsmbd}
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
W=$(mktemp -d)
PORT=4450
PW='correct horse battery staple'
SP=
npass=0
nfail=0
nskip=0

Z() { "$BIN" --db "$W/z.db" "$@"; }

cleanup() {
    umount "$W/mnt" 2>/dev/null
    [ -n "$SP" ] && kill "$SP" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

# t NAME FUNCTION: runs FUNCTION, reports PASS or FAIL with its output tail.
t() {
    name=$1
    shift
    if "$@" >"$W/out.$name" 2>&1; then
        npass=$((npass + 1))
        echo "PASS $name"
    else
        nfail=$((nfail + 1))
        echo "FAIL $name"
        tail -n 6 "$W/out.$name" | sed 's/^/     | /'
    fi
}

# sc SHARE COMMANDS [OPTION]: smbclient signed in as hal.
sc() {
    smbclient "//127.0.0.1/$1" -p $PORT -U "hal%$PW" -m SMB3_11 \
        --option="${3:-client smb encrypt=default}" -c "$2"
}

# anon SHARE COMMANDS: smbclient with no sign-in.
anon() {
    smbclient "//127.0.0.1/$1" -p $PORT -N -m SMB3_11 -c "$2"
}

start_server() {
    # Not through Z: $! must be zsmbd itself, to be killed and inspected.
    "$BIN" --db "$W/z.db" serve --smb "127.0.0.1:$PORT" --web 127.0.0.1:8445 \
        --web-user ops:SECRETPW >"$W/server.log" 2>&1 &
    SP=$!
    n=0
    until grep -q "control socket" "$W/server.log" 2>/dev/null; do
        n=$((n + 1))
        if [ $n -gt 100 ] || ! kill -0 "$SP" 2>/dev/null; then
            echo "zsmbd did not start:"
            cat "$W/server.log"
            exit 1
        fi
        sleep 0.1
    done
}

stop_server() {
    kill "$SP" 2>/dev/null
    wait "$SP" 2>/dev/null
    SP=
    rm -f "$W/z.db.sock"
}

# ---------------------------------------------------------------- tests

big_file() {
    cd "$W/local" || return 1
    sc data "put big.bin; get big.bin big.back" && cmp big.bin big.back
}

basic_operations() {
    cd "$W/local" || return 1
    sc data "put tiny.txt; mkdir d; rename tiny.txt t2.txt; ls T2.TXT; del t2.txt; rmdir d" |
        grep -q ' t2.txt ' && [ ! -e "$W/data/d" ] && [ ! -e "$W/data/t2.txt" ]
}

many_small_files() {
    cd "$W/local" || return 1
    sc data "prompt OFF; mput s*.txt" >/dev/null &&
        [ "$(ls "$W/data" | grep -c '^s[0-9]*\.txt$')" -eq 100 ]
}

unicode_and_long_names() {
    cd "$W/local" || return 1
    long=$(printf 'x%.0s' $(seq 1 200))
    echo u >'ünï-日本語-😀.txt'
    echo l >"$long.txt"
    sc data "put ünï-日本語-😀.txt; put $long.txt; mkdir \"dir ünï\"; rename ünï-日本語-😀.txt \"dir ünï\\moved.txt\"" >/dev/null &&
        [ -f "$W/data/dir ünï/moved.txt" ] && [ -f "$W/data/$long.txt" ]
}

wrong_password_refused() {
    out=$(smbclient //127.0.0.1/data -p $PORT -U 'hal%wrong' -m SMB3_11 -c ls 2>&1)
    echo "$out"
    echo "$out" | grep -q NT_STATUS_LOGON_FAILURE
}

read_only_share_denies_writes() {
    cd "$W/local" || return 1
    out=$(sc rodata "put tiny.txt x" 2>&1)
    echo "$out"
    echo "$out" | grep -q NT_STATUS_ACCESS_DENIED && [ ! -e "$W/ro/x" ]
}

guest_warning_logged() {
    grep -q "share pub allows guests, but signing is required" "$W/server.log"
}

guests_refused_while_signing_required() {
    out=$(anon pub "get g.txt $W/local/g.out" 2>&1)
    echo "$out"
    [ ! -e "$W/local/g.out" ]
}

parallel_sessions() { # COUNT [enc]
    n=$1
    if [ "${2:-}" = enc ]; then opt='client smb encrypt=required'; else opt='client smb encrypt=default'; fi
    rm -rf "$W/par"
    mkdir -p "$W/par"
    pids=
    i=1
    while [ "$i" -le "$n" ]; do
        (
            cd "$W/par" || exit 1
            echo "$i" >"p$i"
            timeout 90 smbclient //127.0.0.1/data -p $PORT -U "hal%$PW" -m SMB3_11 \
                --option="$opt" -c "put p$i par$i; get par$i back$i" >/dev/null 2>&1
            echo $? >"rc$i"
        ) &
        pids="$pids $!"
        i=$((i + 1))
    done
    # shellcheck disable=SC2086
    wait $pids
    bad=0
    i=1
    while [ "$i" -le "$n" ]; do
        if [ "$(cat "$W/par/rc$i")" != 0 ] || ! cmp -s "$W/par/p$i" "$W/par/back$i"; then bad=$((bad + 1)); fi
        i=$((i + 1))
    done
    echo "$bad of $n sessions failed"
    [ "$bad" -eq 0 ]
}

parallel_100() { parallel_sessions 100; }
parallel_20_encrypted() { parallel_sessions 20 enc; }

argv_secrets_masked() {
    cmdline=$(tr '\0' ' ' <"/proc/$SP/cmdline")
    echo "$cmdline"
    ! echo "$cmdline" | grep -q SECRETPW && echo "$cmdline" | grep -q 'ops:XXXXXXXX'
}

encryption_in_use() {
    cd "$W/local" || return 1
    out=$(smbclient //127.0.0.1/data -p $PORT -U "hal%$PW" -m SMB3_11 -d 10 -c ls 2>&1)
    echo "$out" | grep -c 'Encrypted SMB2 message'
    echo "$out" | grep -q 'smb2_signing_encrypt_pdu: Encrypted SMB2 message'
}

guest_reads_when_signing_off() {
    anon pub "get g.txt $W/local/g.out" >/dev/null 2>&1 && [ "$(cat "$W/local/g.out")" = hi ]
}

guest_refused_on_other_shares() {
    out=$(anon data ls 2>&1)
    echo "$out"
    echo "$out" | grep -q NT_STATUS_ACCESS_DENIED
}

no_guest_warning_when_signing_off() {
    ! grep -q "allows guests" "$W/server.log"
}

# ---- kernel client (needs mount privileges)

M="$W/mnt"

kernel_mount() {
    mount -t cifs //127.0.0.1/data "$M" -o "port=$PORT,vers=3.1.1,username=hal,password=$PW"
}

kernel_dialect() {
    grep -q 'Dialect 0x311' /proc/fs/cifs/DebugData
}

kernel_cp_a() {
    mkdir -p "$W/src/a/b"
    i=1
    while [ $i -le 50 ]; do echo "$i" >"$W/src/a/b/f$i"; i=$((i + 1)); done
    head -c 5000000 /dev/urandom >"$W/src/a/big"
    cp -a "$W/src/a" "$M/cp" && diff -r "$W/src/a" "$M/cp"
}

kernel_rsync() {
    rsync -a "$W/src/a/" "$M/rs/" && diff -r "$W/src/a" "$M/rs"
}

kernel_git_clone() {
    r="$W/repo"
    git init -q "$r" && echo x >"$r/f" && git -C "$r" add f &&
        git -C "$r" -c user.name=a -c user.email=a@b commit -qm x &&
        git clone -q "$r" "$M/gitc" && [ -z "$(git -C "$M/gitc" status --porcelain)" ] &&
        git -C "$M/gitc" fsck
}

kernel_dd() {
    dd if=/dev/urandom of="$M/big" bs=1M count=200 &&
        dd if=/dev/urandom of="$M/small" bs=512 count=4000 &&
        dd if="$M/big" of=/dev/null bs=1M && dd if="$M/small" of=/dev/null bs=100
}

kernel_truncate_touch() {
    truncate -s 10M "$M/tr" && [ "$(stat -c %s "$M/tr")" = 10485760 ] &&
        truncate -s 100 "$M/tr" && [ "$(stat -c %s "$M/tr")" = 100 ] &&
        touch -d '2020-01-02 03:04:05' "$M/tt" &&
        [ "$(stat -c %y "$M/tt" | cut -c1-19)" = '2020-01-02 03:04:05' ]
}

# The kernel lists extended attributes for ls -l; an error status other
# than "none" once made every entry fail with EIO, which ls reports on
# stderr and still exits 0.
kernel_ls_l_and_df() {
    err=$( (ls -l "$M/cp" >/dev/null; ls -ld "$M/cp/big" >/dev/null) 2>&1)
    echo "$err"
    [ -z "$err" ] && df "$M"
}

kernel_rename_dir() {
    mkdir "$M/d1" && touch "$M/d1/f" && mv "$M/d1" "$M/d2" && [ -e "$M/d2/f" ]
}

# git trees once left a directory behind (a leaked rmdir handle).
kernel_rm_rf_after_clone() {
    n=1
    while [ $n -le 4 ]; do
        git clone -q "$W/repo" "$M/g$n" && rm -rf "${M:?}/g$n" || return 1
        n=$((n + 1))
    done
    rm -rf "${M:?}/cp" "${M:?}/rs" "${M:?}/gitc"
}

kernel_flock() {
    ( exec 9>"$M/lock" && flock -n 9 ) &&
        ( exec 9>"$M/lock2" && flock -n 9 && ( exec 8>"$M/lock2" && ! flock -n 8 ) )
}

kernel_fcntl_lock() {
    cat >"$W/lock.py" <<'PY'
import fcntl, os, sys
f = open(sys.argv[1], "w")
fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
pid = os.fork()
if pid == 0:
    g = open(sys.argv[1], "w")
    try:
        fcntl.lockf(g, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os._exit(1)
    except OSError:
        os._exit(0)
_, st = os.waitpid(pid, 0)
sys.exit(os.WEXITSTATUS(st))
PY
    python3 "$W/lock.py" "$M/plock"
}

# Control socket, with a client mounted: tightening drops it; relaxing
# alone leaves it on the old rules; --kick makes it reconnect.
control_readonly_denies() {
    Z share readonly data >/dev/null && sleep 1 && ! touch "$M/ro1"
}

control_relax_keeps_old_view() {
    Z share readwrite data >/dev/null && sleep 1 && ! touch "$M/ro2"
}

control_kick_picks_up_change() {
    Z share readwrite --kick data >/dev/null && sleep 1 && touch "$M/rw1"
}

control_nopasswd_drops_client() {
    printf '\n' | Z user nopasswd hal >/dev/null 2>&1 && sleep 1 && ! ls "$M" >/dev/null 2>&1
}

control_web_stop_start() {
    Z web stop | grep -q stopped && Z web start 127.0.0.1:8446 | grep -q 8446
}

# ---------------------------------------------------------------- run

mkdir -p "$W/data" "$W/ro" "$W/pub" "$W/mnt" "$W/local"
echo hello >"$W/ro/r.txt"
echo hi >"$W/pub/g.txt"

Z share add data "$W/data" >/dev/null
Z share add rodata "$W/ro" >/dev/null
Z share readonly rodata >/dev/null
Z share add pub "$W/pub" >/dev/null
Z share guest pub >/dev/null
Z user add hal >/dev/null 2>&1
printf '%s\n' "$PW" | Z user passwd hal >/dev/null 2>&1
start_server

cd "$W/local" || exit 1
echo tiny >tiny.txt
head -c 104857600 /dev/urandom >big.bin
i=1
while [ $i -le 100 ]; do echo "$i" >"s$i.txt"; i=$((i + 1)); done

echo "== smbclient (signing required)"
t big-file big_file
t basic-operations basic_operations
t many-small-files many_small_files
t unicode-and-long-names unicode_and_long_names
t wrong-password-refused wrong_password_refused
t read-only-share-denies-writes read_only_share_denies_writes
t guest-warning-logged guest_warning_logged
t guests-refused-while-signing-required guests_refused_while_signing_required
t parallel-100-sessions parallel_100
t argv-secrets-masked argv_secrets_masked

echo "== kernel CIFS client"
# skip_kernel WHY: a skip, or a failure when the kernel tests are required.
skip_kernel() {
    if [ -n "${INTEROP_REQUIRE_KERNEL:-}" ]; then
        nfail=$((nfail + 1))
        echo "FAIL kernel client: $1"
    else
        nskip=$((nskip + 1))
        echo "SKIP kernel client: $1"
    fi
}

modprobe cifs 2>/dev/null
if ! grep -qw cifs /proc/filesystems || ! command -v mount.cifs >/dev/null; then
    skip_kernel "no CIFS support here (need root, the cifs module, and cifs-utils)"
elif ! kernel_mount >"$W/out.mount" 2>&1; then
    skip_kernel "mount failed: $(cat "$W/out.mount")"
else
    t kernel-dialect-3.1.1 kernel_dialect
    t kernel-cp-a kernel_cp_a
    t kernel-rsync kernel_rsync
    t kernel-git-clone kernel_git_clone
    t kernel-dd kernel_dd
    t kernel-truncate-touch kernel_truncate_touch
    t kernel-ls-l-and-df kernel_ls_l_and_df
    t kernel-rename-dir kernel_rename_dir
    t kernel-rm-rf-after-clone kernel_rm_rf_after_clone
    t kernel-flock kernel_flock
    if command -v python3 >/dev/null; then
        t kernel-fcntl-lock kernel_fcntl_lock
    else
        nskip=$((nskip + 1))
        echo "SKIP kernel-fcntl-lock: no python3"
    fi
    echo "== control socket, kernel client mounted"
    t control-readonly-denies control_readonly_denies
    t control-relax-keeps-old-view control_relax_keeps_old_view
    t control-kick-picks-up-change control_kick_picks_up_change
    t control-web-stop-start control_web_stop_start
    t control-nopasswd-drops-client control_nopasswd_drops_client
    umount "$M" 2>/dev/null
fi

echo "== smbclient (encryption required)"
stop_server
printf '%s\n' "$PW" | Z user passwd hal >/dev/null 2>&1
Z set encrypt yes >/dev/null
start_server
t encryption-in-use encryption_in_use
t parallel-20-encrypted parallel_20_encrypted

echo "== smbclient (signing off, guests)"
stop_server
Z set encrypt no >/dev/null
Z set signing_required no >/dev/null
start_server
t guest-reads-when-signing-off guest_reads_when_signing_off
t guest-refused-on-other-shares guest_refused_on_other_shares
t no-guest-warning-when-signing-off no_guest_warning_when_signing_off

echo
echo "$npass passed, $nfail failed, $nskip skipped"
if [ "$nfail" -gt 0 ]; then
    echo "--- server log"
    tail -n 30 "$W/server.log"
    exit 1
fi
