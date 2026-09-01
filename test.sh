#!/usr/bin/env bash
# Diagnostic report for ft_nmap. Verbose on purpose: run it, paste the output.
#
#   sudo ./test.sh              full report
#   sudo ./test.sh --no-net     skip the scanme.nmap.org comparison
#
# This does not replace run_tests.sh (the pass/fail smoke suite); it runs it as
# one of its sections and adds the correctness checks that suite does not make.

set -u

BIN=./ft_nmap
SKIP_NET=0
[ "${1:-}" = "--no-net" ] && SKIP_NET=1

pass=0; fail=0; skip=0
LISTENER_PID=""

cleanup() { [ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null; }
trap cleanup EXIT

banner() { echo; echo "================================================================"; echo "$1"; echo "================================================================"; }
ok()     { echo "  PASS  $1"; pass=$((pass+1)); }
no()     { echo "  FAIL  $1"; fail=$((fail+1)); }
sk()     { echo "  SKIP  $1"; skip=$((skip+1)); }

# conclusion_for <port> <output-file>  -> prints the Conclusion column
conclusion_for() { awk -v p="$1" '$1==p {print $NF}' "$2" | head -1; }

if [ "$(id -u)" -ne 0 ]; then
    echo "The raw scans need root. Re-run: sudo ./test.sh"
    exit 1
fi

# the non-root user who invoked sudo, for the unprivileged tests
REAL_USER="${SUDO_USER:-}"

banner "0. ENVIRONMENT"
echo "date        : $(date -Is)"
echo "uname       : $(uname -srm)"
echo "compiler    : $(cc --version 2>/dev/null | head -1)"
echo "libpcap     : $(pkg-config --modversion libpcap 2>/dev/null || dpkg-query -W -f='${Version}' libpcap-dev 2>/dev/null || echo unknown)"
echo "git HEAD    : $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null)"
echo "git dirty   : $(git status --porcelain 2>/dev/null | wc -l) file(s) modified"
echo "nmap        : $(command -v nmap || echo MISSING)"
echo "docker      : $(command -v docker || echo MISSING)"
echo "sudo user   : ${REAL_USER:-<none>}"

banner "1. CLEAN BUILD (-Wall -Wextra -Werror)"
make fclean >/dev/null 2>&1
build_log=$(make 2>&1)
build_rc=$?
echo "$build_log"
warn_count=$(echo "$build_log" | grep -ci 'warning:' || true)
if [ "$build_rc" -eq 0 ] && [ "$warn_count" -eq 0 ]; then
    ok "builds with zero warnings"
else
    no "build rc=$build_rc, warnings=$warn_count"
fi

banner "2. EXISTING SMOKE SUITE (run_tests.sh)"
if [ -x ./run_tests.sh ]; then
    ./run_tests.sh
    [ $? -eq 0 ] && ok "run_tests.sh all green" || no "run_tests.sh reported failures"
else
    sk "run_tests.sh not executable"
fi

banner "3. CORRECTNESS ON A LOCAL LISTENER"
# The only target we fully control: one port with a real listener, one without.
POPEN=39999
PSHUT=39998
python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$POPEN)); s.listen(8)
time.sleep(600)
" &
LISTENER_PID=$!
sleep 1.5

if ss -ltn 2>/dev/null | grep -q ":$POPEN"; then
    echo "listener confirmed up on 127.0.0.1:$POPEN"
    ss -ltn | grep ":$POPEN"
    echo
    out=$(mktemp)
    $BIN --ip 127.0.0.1 --ports $PSHUT,$POPEN --scan SYN 2>&1 | tee "$out"
    echo
    got_open=$(conclusion_for $POPEN "$out")
    got_shut=$(conclusion_for $PSHUT "$out")
    [ "$got_open" = "Open" ]   && ok "port $POPEN with a listener reports Open"   || no "port $POPEN reported '$got_open', wanted Open"
    [ "$got_shut" = "Closed" ] && ok "port $PSHUT with no listener reports Closed" || no "port $PSHUT reported '$got_shut', wanted Closed"
    rm -f "$out"

    echo
    echo "--- same two ports, all six scan types ---"
    $BIN --ip 127.0.0.1 --ports $PSHUT,$POPEN 2>&1 | grep -E "^($PSHUT|$POPEN|Port)"
else
    sk "could not start a local listener on $POPEN"
fi

banner "4. COMPARISON AGAINST REAL NMAP (scanme.nmap.org)"
if [ "$SKIP_NET" -eq 1 ]; then
    sk "network section disabled with --no-net"
elif ! command -v nmap >/dev/null; then
    sk "nmap not installed, nothing to compare against"
elif ! getent hosts scanme.nmap.org >/dev/null 2>&1; then
    sk "cannot resolve scanme.nmap.org, no network"
else
    echo "scanme.nmap.org exists to be scanned legally. Ports 22,80,443."
    echo
    echo "--- real nmap ---"
    nmap -sS -p 22,80,443 scanme.nmap.org 2>&1 | grep -E "^(PORT|22|80|443)"
    echo
    echo "--- ft_nmap ---"
    fo=$(mktemp)
    $BIN --ip scanme.nmap.org --ports 22,80,443 --scan SYN 2>&1 | tee "$fo" | grep -E "^(Port|22|80|443)"
    echo
    for p in 22 80 443; do
        want=$(nmap -sS -p $p scanme.nmap.org 2>/dev/null | awk -v pp="$p/tcp" '$1==pp {print $2}')
        got=$(conclusion_for $p "$fo")
        case "$want:$got" in
            open:Open|closed:Closed|filtered:Filtered) ok "port $p agrees with nmap ($want)" ;;
            :*) sk "port $p: nmap gave no verdict" ;;
            *)  no "port $p: nmap said '$want', ft_nmap said '$got'" ;;
        esac
    done
    rm -f "$fo"
fi

banner "5. PRIVILEGE SPLIT"
if [ -n "$REAL_USER" ]; then
    echo "--- raw scan as $REAL_USER (must refuse, exit 1) ---"
    sudo -u "$REAL_USER" $BIN --ip 127.0.0.1 --ports 80 --scan SYN 2>&1 | head -2
    rc=${PIPESTATUS[0]}
    [ "$rc" -eq 1 ] && ok "non-root SYN refused (exit 1)" || no "non-root SYN exit $rc, wanted 1"

    echo
    echo "--- UDP scan as $REAL_USER (must work, exit 0) ---"
    sudo -u "$REAL_USER" $BIN --ip 127.0.0.1 --ports 53 --scan UDP 2>&1 | grep -E "^(53|Port)"
    rc=${PIPESTATUS[0]}
    [ "$rc" -eq 0 ] && ok "non-root UDP scan works (exit 0)" || no "non-root UDP exit $rc, wanted 0"
else
    sk "no SUDO_USER, cannot test the non-root paths"
fi

banner "6. REGRESSION: root without CAP_NET_RAW"
# This case used to print 'Port 0 / Unassigned' from uninitialised stack memory
# and still exit 0. Needs docker: you cannot drop a capability from a root shell.
if ! command -v docker >/dev/null; then
    sk "docker not installed"
elif ! docker info >/dev/null 2>&1; then
    sk "docker daemon not reachable"
else
    docker build -q -t ft_nmap_test . >/dev/null 2>&1
    ro=$(mktemp)
    docker run --rm --cap-drop=ALL --entrypoint bash ft_nmap_test \
        -c "./ft_nmap --ip 127.0.0.1 --ports 80,443 --scan SYN 2>/dev/null; echo RC=\$?" >"$ro" 2>&1
    cat "$ro" | grep -E "^(80|443|Port|RC=)"
    rc=$(grep -o 'RC=[0-9]*' "$ro" | cut -d= -f2)
    grep -qE '^0 +Unassigned' "$ro" && no "still printing port 0 from uninitialised memory" \
                                    || ok "real port numbers printed, no stack garbage"
    [ "${rc:-0}" -ne 0 ] && ok "reports failure (exit $rc) instead of false success" \
                          || no "exit $rc, wanted non-zero when no worker could run"
    rm -f "$ro"
fi

banner "SUMMARY"
echo "  passed : $pass"
echo "  failed : $fail"
echo "  skipped: $skip"
echo
[ "$fail" -eq 0 ] && echo "ALL GOOD" || echo "$fail CHECK(S) FAILED"
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
