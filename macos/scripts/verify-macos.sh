#!/bin/bash
#
# ProcSocks macOS 端到端验证
#
#   sudo bash scripts/verify-macos.sh
#
# 设计要点：**不假设本机能直连外网**。
#
# 这类机器往往正是因为没有直连才需要 SOCKS 代理，所以「比较出口 IP 是否变化」
# 这种判据在这里根本不成立（直连压根不通）。改成看两个可靠得多的信号：
#
#   1. 代理自己打的决策日志（attributed connection ... decision=proxy|direct）
#   2. 「只能经代理到达」和「能直连到达」两个目标各自的表现
#
# 两项探针：
#   PROXY_PROBE_URL   只能经代理到达（默认 https://api.ipify.org）
#   DIRECT_PROBE_URL  可以直连到达（默认 http://example.com/，走 80）
#
# 它会验证：
#   T1  普通用户进程的连接被拦到、命中路径规则、经上游 SOCKS5 成功取回内容
#   T2  代理自身的出站被 pf 豁免（root 的连接根本不会出现在归属日志里）
#   T3  回环目标不被拦截（连本机 7890 不会绕回自己形成死循环）
#   T4  不匹配规则的进程走直连回退（日志里出现 decision=direct）
#   T5  正常退出后 pf 完全还原
#   T6  ★ 被 SIGKILL 之后，死人开关能自动撤掉 pf 规则（防止把自己关在门外）
#   T7  IPv6 透明代理（默认开启时必须通过）
#
# 手工兜底（万一）：  sudo pfctl -d && sudo pfctl -f /etc/pf.conf
#
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${PROCSOCKS_BIN:-$PROJECT_DIR/target/release/procsocks}"
CONFIG="${PROCSOCKS_CONFIG:-$PROJECT_DIR/procsocks.local.json}"
PFCTL=/sbin/pfctl
SYSCTL=/usr/sbin/sysctl
CURL=/usr/bin/curl
PROXY_PID=""
FAILURES=0

# Fail before installing traps or writing reports: a failed preflight must never
# reset the machine's firewall or forwarding settings.
[ "$(id -u)" -eq 0 ] || { printf '%s\n' '请用 sudo 运行'; exit 1; }
[ -x "$BIN" ] || { printf '%s\n' "$BIN 不存在；先跑 cargo build --release"; exit 1; }
[ -f "$CONFIG" ] || { printf '%s\n' "$CONFIG 不存在；先创建本地配置并设置上游 SOCKS5"; exit 1; }
WORK=$(mktemp -d "${VERIFY_WORK:-${TMPDIR:-/tmp}}/procsocks-verify.XXXXXX") || exit 1
chmod 700 "$WORK"
PROXY_LOG="$WORK/procsocks.log"
REPORT="$WORK/report.txt"
PROXY_PROBE_URL="${PROXY_PROBE_URL:-https://api.ipify.org}"
DIRECT_PROBE_URL="${DIRECT_PROBE_URL:-http://example.com/}"
IPV6_PROBE_URL="${IPV6_PROBE_URL:-https://api64.ipify.org}"
: > "$REPORT"

say() { printf '%s\n' "$*" | tee -a "$REPORT"; }
head2() { printf '\n===== %s =====\n' "$*" | tee -a "$REPORT"; }
die() { say "错误: $*"; exit 1; }

# 统计代理日志里的信号。grep -c 没匹配时退出码是 1，这里统一成数字输出。
count_in_log() {
    local n
    n=$(grep -Ec "$1" "$PROXY_LOG" 2>/dev/null)
    printf '%s' "${n:-0}"
}

# Count only the probe's own PID. Unrelated applications can create connections
# during a test; their traffic must never make an un-intercepted probe pass.
count_for_probe() {
    local pid n
    pid=$(sed -n 's/^PROCSOCKS_PROBE_PID=//p' "$1" | head -1)
    [ -n "$pid" ] || { printf 0; return; }
    n=$(grep 'attributed connection' "$PROXY_LOG" | grep -E "pid=$pid([[:space:]]|$)" | grep -Ec "${2:-.}")
    printf '%s' "${n:-0}"
}

state_restored() {
    local suffix="$1" current_pf
    [ "$("$SYSCTL" -n net.inet.ip.forwarding)" = "$FWD_BEFORE" ] || return 1
    current_pf=$("$PFCTL" -s info 2>/dev/null | awk '/^Status/{print $2}')
    [ "$current_pf" = "$PF_STATUS" ] || return 1
    "$PFCTL" -sn >"$WORK/nat.$suffix" 2>/dev/null || return 1
    "$PFCTL" -sr >"$WORK/filter.$suffix" 2>/dev/null || return 1
    "$PFCTL" -s References >"$WORK/references.$suffix" 2>/dev/null || return 1
    # A disabled filter's inactive rule contents do not affect the network.
    # When pf was enabled, compare its active main rules as well as the mode.
    if [ "$PF_STATUS" = Enabled ]; then
        cmp -s "$WORK/nat.before" "$WORK/nat.$suffix" || return 1
        cmp -s "$WORK/filter.before" "$WORK/filter.$suffix" || return 1
    fi
    cmp -s "$WORK/references.before" "$WORK/references.$suffix"
}

# 以普通用户身份跑 curl，显式绕开一切代理环境变量与系统代理设置。
user_curl() {
    /usr/bin/sudo -u "$REAL_USER" /bin/sh -c '
        printf "PROCSOCKS_PROBE_PID=%s\n" "$$" >&2
        exec /usr/bin/curl -fsS --noproxy "*" --max-time 25 "$@"
    ' sh "$@"
}

# 经指定的 SOCKS 代理跑 curl。**不能**带 --noproxy ——
# `--noproxy '*'` 会把显式的 -x 也一并禁用掉，等于没走代理。
user_curl_via() {
    local proxy="$1"
    shift
    /usr/bin/sudo -u "$REAL_USER" /bin/sh -c '
        printf "PROCSOCKS_PROBE_PID=%s\n" "$$" >&2
        exec /usr/bin/curl -fsS --noproxy "" --max-time 25 "$@"
    ' sh -x "$proxy" "$@"
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill -TERM "$PROXY_PID" 2>/dev/null
        for _ in $(seq 1 100); do
            kill -0 "$PROXY_PID" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$PROXY_PID" 2>/dev/null; then
            kill -9 "$PROXY_PID" 2>/dev/null
        fi
        wait "$PROXY_PID" 2>/dev/null || true
        say "已停止 procsocks"
    fi
    # The watchdog restores the captured state. Never force forwarding=0 or
    # reload /etc/pf.conf here: doing that could hide a failed cleanup test.
    say ""
    say "报告: $REPORT"
    say "代理日志: $PROXY_LOG"
    exit $rc
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

REAL_USER="${SUDO_USER:-$(/usr/bin/stat -f %Su /dev/console)}"
[ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ] || die "无法确定测试用的普通用户"

# Keep the user's configuration intact. Test only curl and the probe ports;
# reuse the actual upstream, timeouts, and IPv6 setting from the local config.
ORIGINAL_CONFIG="$CONFIG"
CONFIG="$WORK/test-config.json"
PROBE_SETTINGS=$(/usr/bin/python3 - "$ORIGINAL_CONFIG" "$CONFIG" "$PROXY_PROBE_URL" "$DIRECT_PROBE_URL" "$IPV6_PROBE_URL" <<'PY'
import json, sys, urllib.parse
with open(sys.argv[1]) as source:
    config = json.load(source)
config['processPatterns'] = [r'^/usr/bin/curl$']
config['bypassPatterns'] = ['procsocks', r'^/usr/bin/ssh$', r'^/usr/sbin/sshd$']
ports = set()
for url in sys.argv[3:]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('probes must use HTTP or HTTPS URLs')
    ports.add(parsed.port or (443 if parsed.scheme == 'https' else 80))
upstream = config['upstream']
ports.add(upstream['port'])
config['redirectPorts'] = ','.join(map(str, sorted(ports)))
with open(sys.argv[2], 'w') as output:
    json.dump(config, output)
host = upstream['host']
if ':' in host:
    host = '[' + host + ']'
credentials = ''
if upstream.get('username') is not None:
    credentials = urllib.parse.quote(upstream['username'], safe='') + ':' + urllib.parse.quote(upstream['password'], safe='') + '@'
print('socks5h://' + credentials + host + ':' + str(upstream['port']))
print('yes' if config.get('redirectIpv6', True) else 'no')
PY
) || die "无法生成验收配置"
chmod 600 "$CONFIG"
LOOPBACK_PROXY="${LOOPBACK_PROXY:-$(printf '%s\n' "$PROBE_SETTINGS" | head -1)}"
TEST_IPV6=$(printf '%s\n' "$PROBE_SETTINGS" | tail -1)
unset PROBE_SETTINGS
"$BIN" --config "$CONFIG" check >"$WORK/check.log" 2>&1 || die "验收配置未通过 check；见 $WORK/check.log"

head2 "ProcSocks macOS 端到端验证"
say "时间:       $(date '+%Y-%m-%d %H:%M:%S')"
say "系统:       $(sw_vers -productVersion) ($(uname -m))"
say "二进制:     $BIN"
say "源配置:     ${ORIGINAL_CONFIG}（保持不变）"
say "验收配置:   ${CONFIG}（只匹配 curl，并限制为探针端口）"
say "测试用户:   $REAL_USER"
say "代理探针:   $PROXY_PROBE_URL   （只能经代理到达）"
say "直连探针:   $DIRECT_PROBE_URL  （可以直连到达）"

head2 "将要载入的 pf 规则集"
"$BIN" --config "$CONFIG" driver ruleset | tee -a "$REPORT"

# 这是全机每一条被接管连接的固定开销。`redirectPorts: "all"` 时它直接决定
# 网络手感，所以每次都量一下，别让它悄悄劣化。
head2 "连接归属查询耗时（决定每条新连接的额外延迟）"
"$BIN" bench-libproc --iterations 200 | tee -a "$REPORT"

# 0. 前提：直连探针必须真的能直连，否则后面 T2/T4 无从判断。
head2 "0. 前提检查：直连探针是否可达"
BASELINE=$(user_curl -o /dev/null -w '%{http_code}' "$DIRECT_PROBE_URL" 2>"$WORK/baseline.err")
say "直连 $DIRECT_PROBE_URL -> HTTP ${BASELINE:-<失败>}"
if [ "$BASELINE" != "200" ] && [ "$BASELINE" != "301" ] && [ "$BASELINE" != "302" ]; then
    say "curl stderr: $(head -2 "$WORK/baseline.err")"
    say ""
    say "这台机器连 $DIRECT_PROBE_URL 都直连不通，T2/T4 无法判断。"
    say "换个能直连的目标重跑，例如："
    say "  DIRECT_PROBE_URL=http://www.baidu.com/ sudo bash $0"
    exit 3
fi
say "直连可达，可以继续。"

PF_STATUS=$("$PFCTL" -s info 2>/dev/null | awk '/^Status/{print $2}')
FWD_BEFORE=$("$SYSCTL" -n net.inet.ip.forwarding 2>/dev/null || echo 0)
"$PFCTL" -sn >"$WORK/nat.before" 2>"$WORK/pf.err" || die "无法记录 pf NAT 规则"
"$PFCTL" -sr >"$WORK/filter.before" 2>"$WORK/pf.err" || die "无法记录 pf 过滤规则"
"$PFCTL" -s References >"$WORK/references.before" 2>"$WORK/pf.err" || die "无法记录 pf enable 引用"
say "进入时 pf=$PF_STATUS  ip.forwarding=$FWD_BEFORE"

# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------
head2 "1. 启动 procsocks"
: > "$PROXY_LOG"
# Readiness and attribution are part of the acceptance evidence. Do not let
# an inherited RUST_LOG (including an empty value) disable those records.
RUST_LOG=procsocks=info "$BIN" --config "$CONFIG" run >>"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
say "pid=$PROXY_PID"

READY=0
for _ in $(seq 1 100); do
    grep -q "pf 透明重定向已启用" "$PROXY_LOG" 2>/dev/null && READY=1 && break
    kill -0 "$PROXY_PID" 2>/dev/null || break
    sleep 0.1
done
if [ "$READY" != "1" ]; then
    say "代理没能进入就绪状态，日志："
    sed 's/^/    /' "$PROXY_LOG" | tee -a "$REPORT"
    exit 4
fi
say "就绪。"

# ---------------------------------------------------------------------------
# T3：先拿一个参考出口 IP（显式走本机 SOCKS 代理，回环目标是必须不被拦截的）
# ---------------------------------------------------------------------------
head2 "T3 回环目标不被拦截（显式连接上游 SOCKS5）"
IP_T3=$(user_curl_via "$LOOPBACK_PROXY" "$PROXY_PROBE_URL" 2>"$WORK/t3.err")
T3_RC=$?
T3_HITS=$(count_for_probe "$WORK/t3.err")
say "出口 IP: ${IP_T3:-<失败>} (curl 退出码 $T3_RC)"
if [ -z "$IP_T3" ]; then
    say "curl stderr: $(head -2 "$WORK/t3.err")"
fi

# ---------------------------------------------------------------------------
# T1：普通用户的透明代理路径
# ---------------------------------------------------------------------------
head2 "T1 普通用户进程 -> 透明拦截 -> 上游 SOCKS5"
IP_T1=$(user_curl -4 "$PROXY_PROBE_URL" 2>"$WORK/t1.err")
T1_RC=$?
sleep 0.4
T1_HITS=$(count_for_probe "$WORK/t1.err")
T1_PROXIED=$(count_for_probe "$WORK/t1.err" 'decision="?proxy"?([[:space:]]|$)')

say "出口 IP:            ${IP_T1:-<失败>}"
say "被接管的连接数:     $T1_HITS"
say "其中 decision=proxy: $T1_PROXIED"
if [ -z "$IP_T1" ]; then
    say "curl stderr: $(head -2 "$WORK/t1.err")"
fi

# ---------------------------------------------------------------------------
# T2：root 的出站必须被豁免
# ---------------------------------------------------------------------------
head2 "T2 root 出站被 pf 豁免"
HTTP_T2=$(/bin/sh -c '
    printf "PROCSOCKS_PROBE_PID=%s\n" "$$" >&2
    exec /usr/bin/curl -fsS --noproxy "*" -o /dev/null -w "%{http_code}" --max-time 25 "$@"
' sh "$DIRECT_PROBE_URL" 2>"$WORK/t2.err")
sleep 0.4
T2_HITS=$(count_for_probe "$WORK/t2.err")
say "直连探针 HTTP:      ${HTTP_T2:-<失败>}"
say "被接管的连接数:     $T2_HITS   (期望 0 —— root 不该出现在归属日志里)"

# ---------------------------------------------------------------------------
# T4：不匹配规则的进程走直连回退
# ---------------------------------------------------------------------------
head2 "T4 不匹配规则的进程 -> 直连回退"
HTTP_T4=$(/usr/bin/sudo -u "$REAL_USER" /usr/bin/python3 - "$DIRECT_PROBE_URL" 2>"$WORK/t4.err" <<'PY'
import os, ssl, sys, urllib.request

print('PROCSOCKS_PROBE_PID=' + str(os.getpid()), file=sys.stderr)

# 显式禁用代理：urllib 默认会读 macOS 的系统代理设置，那会让这个用例失去意义。
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
)
try:
    with opener.open(sys.argv[1], timeout=25) as response:
        print(response.status)
except Exception as exc:  # noqa: BLE001 - 探针，任何异常都只用于报告
    print(f"ERROR {exc}", file=sys.stderr)
    print("000")
PY
)
sleep 0.4
T4_HITS=$(count_for_probe "$WORK/t4.err")
T4_DIRECT=$(count_for_probe "$WORK/t4.err" 'decision="?direct"?([[:space:]]|$)')
say "直连探针 HTTP:      ${HTTP_T4:-<失败>}"
say "被接管的连接数:     $T4_HITS   (期望 >=1 —— python3 会被拦到再放行)"
say "其中 decision=direct: $T4_DIRECT"

head2 "T7 IPv6 透明代理"
IP_T7=""
T7_RC=0
T7_PROXIED=0
if [ "$TEST_IPV6" = yes ]; then
    IP_T7=$(user_curl -6 "$IPV6_PROBE_URL" 2>"$WORK/t7.err")
    T7_RC=$?
    sleep 0.4
    T7_PROXIED=$(count_for_probe "$WORK/t7.err" 'decision="?proxy"?([[:space:]]|$)')
    say "IPv6 探针: ${IPV6_PROBE_URL}，curl=${T7_RC}，proxy=$T7_PROXIED"
    [ "$T7_RC" -eq 0 ] || say "curl stderr: $(head -2 "$WORK/t7.err")"
else
    say "源配置关闭了 redirectIpv6，IPv6 不在本次验收范围内。"
fi

# ---------------------------------------------------------------------------
# 决策日志
# ---------------------------------------------------------------------------
head2 "2. 代理的决策日志"
grep "attributed connection" "$PROXY_LOG" | tail -20 | tee -a "$REPORT" || say "（没有决策日志）"
say ""
say "累计: proxy=$(count_in_log 'decision="?proxy"?([[:space:]]|$)')  direct=$(count_in_log 'decision="?direct"?([[:space:]]|$)')"

# ---------------------------------------------------------------------------
# T5：正常退出后还原
# ---------------------------------------------------------------------------
head2 "T5 正常退出后 pf 是否还原"
kill -TERM "$PROXY_PID" 2>/dev/null
for _ in $(seq 1 50); do kill -0 "$PROXY_PID" 2>/dev/null || break; sleep 0.1; done
kill -0 "$PROXY_PID" 2>/dev/null && die "SIGTERM 后进程未退出"
wait "$PROXY_PID"
T5_RC=$?
sleep 0.5
FWD_AFTER=$("$SYSCTL" -n net.inet.ip.forwarding 2>/dev/null || echo "?")
T5_RESTORED=0
if state_restored after-term; then
    T5_RESTORED=1
fi
RDR_LEFT=$("$PFCTL" -sn 2>/dev/null | grep -c '^rdr ' || true)
say "ip.forwarding=$FWD_AFTER (进入时 $FWD_BEFORE)"
say "残留的 rdr 规则数: ${RDR_LEFT:-0}"
PROXY_PID=""

# ---------------------------------------------------------------------------
# T6：死人开关
# ---------------------------------------------------------------------------
head2 "T6 SIGKILL 后死人开关能否撤掉 pf 规则"
BEFORE_KILL=""
AFTER_KILL=""
T6_RESTORED=0
START_LINE=$(($(wc -l <"$PROXY_LOG") + 1))
RUST_LOG=procsocks=info "$BIN" --config "$CONFIG" run >>"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
READY=0
for _ in $(seq 1 100); do
    tail -n +"$START_LINE" "$PROXY_LOG" | grep -q "pf 透明重定向已启用" && READY=1 && break
    kill -0 "$PROXY_PID" 2>/dev/null || break
    sleep 0.1
done
if [ "$READY" != "1" ]; then
    say "第二次启动失败，T6 无法验证"
else
    BEFORE_KILL=$("$PFCTL" -sn 2>/dev/null | grep -c '^rdr ')
    say "SIGKILL 前 rdr 规则数: $BEFORE_KILL"
    # 注意：这里只杀主进程。死人开关是它的子进程，必须活下来把规则撤掉。
    kill -9 "$PROXY_PID" 2>/dev/null
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
    for _ in $(seq 1 60); do
        AFTER_KILL=$("$PFCTL" -sn 2>/dev/null | grep -c '^rdr ' || true)
        if state_restored after-kill; then
            T6_RESTORED=1
            break
        fi
        sleep 0.2
    done
    say "SIGKILL 后 rdr 规则数: ${AFTER_KILL:-?}"
    say "ip.forwarding=$("$SYSCTL" -n net.inet.ip.forwarding 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# 结论
# ---------------------------------------------------------------------------
head2 "3. 结论"
verdict() {
    printf '  [%s] %-40s %s\n' "$2" "$1" "$3" | tee -a "$REPORT"
    [ "$2" != FAIL ] || FAILURES=$((FAILURES + 1))
}

if [ "$T1_RC" -eq 0 ] && [ -n "$IP_T1" ] && [ "$T1_PROXIED" -ge 1 ]; then
    extra=""
    [ -n "$IP_T3" ] && [ "$IP_T1" = "$IP_T3" ] && extra="，与经代理的参考出口一致"
    verdict "T1 普通用户经上游 SOCKS5" PASS "出口 ${IP_T1}，$T1_PROXIED 条走了代理$extra"
elif [ "$T1_HITS" -ge 1 ]; then
    verdict "T1 普通用户经上游 SOCKS5" FAIL "拦到了 $T1_HITS 条但没有一条 decision=proxy"
else
    verdict "T1 普通用户经上游 SOCKS5" FAIL "一条都没拦到：$(head -1 "$WORK/t1.err")"
fi

if [ "$T2_HITS" -eq 0 ] && { [ "$HTTP_T2" = "200" ] || [ "$HTTP_T2" = "301" ] || [ "$HTTP_T2" = "302" ]; }; then
    verdict "T2 root 出站被豁免" PASS "root 的连接没进归属日志，且直连探针 HTTP $HTTP_T2"
elif [ "$T2_HITS" -gt 0 ]; then
    verdict "T2 root 出站被豁免" FAIL "root 被拦了 $T2_HITS 条，user 豁免没生效"
else
    verdict "T2 root 出站被豁免" FAIL "虽然没被拦，但直连探针失败（${HTTP_T2:-?}），pf 可能把网络搞坏了"
fi

if [ "$T3_RC" -eq 0 ] && [ -n "$IP_T3" ] && [ "$T3_HITS" -eq 0 ]; then
    verdict "T3 回环目标不被拦截" PASS "拿到了 ${IP_T3}，没有绕回自己"
else
    verdict "T3 回环目标不被拦截" FAIL "失败（可能死循环）：$(head -1 "$WORK/t3.err")"
fi

if [ "$T4_DIRECT" -ge 1 ] && [ "$HTTP_T4" = "200" ]; then
    verdict "T4 不匹配进程走直连回退" PASS "$T4_DIRECT 条 decision=direct，探针 HTTP $HTTP_T4"
elif [ "$HTTP_T4" = "200" ]; then
    verdict "T4 不匹配进程走直连回退" FAIL "探针通了，但日志里没有 decision=direct（$T4_HITS 条被接管）"
else
    verdict "T4 不匹配进程走直连回退" FAIL "直连探针失败（${HTTP_T4:-?}）"
fi

if [ "$T5_RC" -eq 0 ] && [ "$FWD_AFTER" = "$FWD_BEFORE" ] && [ "$T5_RESTORED" -eq 1 ]; then
    verdict "T5 正常退出后 pf 还原" PASS "forwarding=${FWD_AFTER}，无残留规则"
else
    verdict "T5 正常退出后 pf 还原" FAIL "forwarding=${FWD_AFTER}（进入时 $FWD_BEFORE），残留 ${RDR_LEFT:-?} 条 rdr"
fi

if [ -n "$AFTER_KILL" ] && [ -n "$BEFORE_KILL" ] && [ "$AFTER_KILL" -lt "$BEFORE_KILL" ] && [ "$T6_RESTORED" -eq 1 ]; then
    verdict "T6 SIGKILL 后死人开关生效" PASS "rdr 从 $BEFORE_KILL 降到 $AFTER_KILL"
else
    verdict "T6 SIGKILL 后死人开关生效" FAIL "rdr 仍有 ${AFTER_KILL:-?} 条（SIGKILL 前是 ${BEFORE_KILL:-?}），规则没被撤掉"
fi

if [ "$TEST_IPV6" = yes ]; then
    if [ "$T7_RC" -eq 0 ] && [ -n "$IP_T7" ] && [ "$T7_PROXIED" -ge 1 ]; then
        verdict "T7 IPv6 经上游 SOCKS5" PASS "$T7_PROXIED 条走代理，出口 $IP_T7"
    else
        verdict "T7 IPv6 经上游 SOCKS5" FAIL "IPv6 请求未完成；需可用的 IPv6 网络与探针目标"
    fi
fi

say ""
say "失败项: $FAILURES"
[ "$FAILURES" -eq 0 ] || exit 1
