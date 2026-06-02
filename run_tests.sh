#!/usr/bin/env bash
# Smoke tests for ft_nmap. Run with: sudo make test
# Argument-validation cases assert the exit code; live cases only check that
# a scan runs to completion without crashing (segfault, abort, double free).

set -u
BIN=./ft_nmap

if [ "$(id -u)" -ne 0 ]; then
    echo "ft_nmap needs root for raw sockets. Re-run: sudo make test"
    exit 1
fi

pass=0
fail=0

# check <description> <expected_exit> <cmd...>
check() {
    desc="$1"
    exp="$2"
    shift 2
    "$@" >/dev/null 2>&1
    got=$?
    if [ "$got" -eq "$exp" ]; then
        echo "PASS  $desc"
        pass=$((pass + 1))
    else
        echo "FAIL  $desc (got exit $got, wanted $exp)"
        fail=$((fail + 1))
    fi
}

echo "== argument validation =="
check "--help exits 0"                0 $BIN --help
check "no target errors"              1 $BIN --ports 80
check "port 0 invalid"                1 $BIN --ip 127.0.0.1 --ports 0
check "port -1 invalid"               1 $BIN --ip 127.0.0.1 --ports -1
check "port 65536 invalid"            1 $BIN --ip 127.0.0.1 --ports 65536
check "range 10-5 invalid"            1 $BIN --ip 127.0.0.1 --ports 10-5
check "over 1024 ports invalid"       1 $BIN --ip 127.0.0.1 --ports 1-1025
check "speedup 251 invalid"           1 $BIN --ip 127.0.0.1 --speedup 251
check "speedup -1 invalid"            1 $BIN --ip 127.0.0.1 --speedup -1
check "unknown scan type invalid"     1 $BIN --ip 127.0.0.1 --scan INVALID
check "bad hostname exits cleanly"    0 $BIN --ip notahost.invalid --ports 80

echo "== live scans (no crash) =="
check "SYN scan"                      0 $BIN --ip 127.0.0.1 --ports 20-30 --scan SYN
check "all scan types"               0 $BIN --ip 127.0.0.1 --ports 79-81
check "ACK,UDP scans"                0 $BIN --ip 127.0.0.1 --ports 53-55 --scan ACK,UDP
check "max ports, max threads"       0 $BIN --ip 127.0.0.1 --ports 1-1024 --speedup 250 --scan SYN

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
