#!/bin/bash
#
# ProcSocks macOS spike —— 验证「pf + route-to」透明 TCP 代理路线是否可行
#
#   sudo bash run-spike.sh
#
# 它会一次性回答三个问题：
#   Q1  能否拦住「本机普通用户进程」发出的 TCP？
#   Q2  能否用 `pfctl -s state` 还原出这条连接的原始目的地？
#   Q3  代理自己（root）发出去的连接能否不被再次拦截（不回环）？
#   Q4  端到端：普通用户的 curl 能否在完全无感知的情况下被代理并成功拿到响应？
#
# 安全边界：
#   * 不改 /etc/pf.conf 文件本身，只用 `pfctl -f` 载入一份临时「主规则集」
#   * 只重定向 REDIR_PORTS（默认 80），HTTPS / SSH 完全不受影响
#   * 退出时（含 Ctrl+C、出错、kill）自动恢复 pf 并停掉监听器
#   * 如果 pf 当前处于 Enabled 状态，脚本会拒绝运行（除非 SPIKE_FORCE=1）
#
# 手工兜底恢复：  sudo pfctl -d
#
set -uo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${SPIKE_WORK:-/tmp/procsocks-spike}"
REPORT="$WORK/report.txt"

TARGET_HOST="${TARGET_HOST:-example.com}"
TARGET_PORT="${TARGET_PORT:-80}"
REDIR_PORTS="${REDIR_PORTS:-80}"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1}"
LISTEN_PORT="${LISTEN_PORT:-7891}"
TPROXY_USER="${TPROXY_USER:-root}"

CURL=/usr/bin/curl
PFCTL=/sbin/pfctl
SYSCTL=/usr/sbin/sysctl
PYTHON="${PYTHON:-/usr/bin/python3}"

RULESET="$WORK/pf.spike.conf"
LISTENER_LOG="$WORK/listener.log"
LISTENER_ERR="$WORK/listener.err"
LISTENER_PID=""
PF_TOKEN=""

# --------------------------------------------------------------------------
# 输出 / 报告
# --------------------------------------------------------------------------
say()  { printf '%s\n' "$*" | tee -a "$REPORT"; }
head2() { printf '\n===== %s =====\n' "$*" | tee -a "$REPORT"; }

die() { say "错误: $*"; exit 1; }

# --------------------------------------------------------------------------
# 清理：无论怎么退出都要把系统恢复原状
# --------------------------------------------------------------------------
cleanup() {
    local rc=$?
    trap - EXIT INT TERM

    # 撤掉看门狗，别让它在脚本结束后误伤无关进程
    # （子 shell 里跑的是 sleep，必须连它的子进程一起收掉，
    #   否则那个 sleep 会在 90 秒后对着一个可能已被复用的 PID 发信号）
    if [ -n "${WATCHDOG_PID:-}" ]; then
        kill "$WATCHDOG_PID" 2>/dev/null
        [ -x /usr/bin/pkill ] && /usr/bin/pkill -P "$WATCHDOG_PID" 2>/dev/null
    fi

    head2 "清理"

    if [ -n "$LISTENER_PID" ] && kill -0 "$LISTENER_PID" 2>/dev/null; then
        kill "$LISTENER_PID" 2>/dev/null
        sleep 0.3
        kill -9 "$LISTENER_PID" 2>/dev/null
        say "已停止监听器 (pid=$LISTENER_PID)"
    fi

    # 恢复 Apple 默认的主规则集
    if [ -f /etc/pf.conf ]; then
        "$PFCTL" -f /etc/pf.conf 2>/dev/null && say "已恢复主规则集 /etc/pf.conf" \
            || say "警告: 恢复 /etc/pf.conf 失败，请手工执行 sudo pfctl -f /etc/pf.conf"
    fi

    # 释放我们那一份 enable 引用
    if [ -n "$PF_TOKEN" ]; then
        "$PFCTL" -X "$PF_TOKEN" 2>/dev/null
    fi

    # 如果进来时 pf 是关的，就把它关回去
    if [ "${PF_WAS_ENABLED:-0}" = "0" ]; then
        "$PFCTL" -d 2>/dev/null && say "已把 pf 关闭（脚本启动前它就是关闭的）"
    fi

    # 恢复 ip forwarding
    if [ -n "${FORWARDING_BEFORE:-}" ]; then
        "$SYSCTL" -w "net.inet.ip.forwarding=$FORWARDING_BEFORE" >/dev/null 2>&1
        say "已恢复 net.inet.ip.forwarding=$FORWARDING_BEFORE"
    fi

    say ""
    say "报告文件: $REPORT"
    say "监听器日志: $LISTENER_LOG"
    say "如果网络异常，手工兜底:  sudo pfctl -d"

    exit $rc
}
trap cleanup EXIT INT TERM

# --------------------------------------------------------------------------
# 0. 前置检查
# --------------------------------------------------------------------------
mkdir -p "$WORK"
# 目录是 root 建的，但后面要以普通用户身份 curl -o 写入，必须放开写权限
chmod 777 "$WORK"
: > "$REPORT"
: > "$LISTENER_LOG"
: > "$LISTENER_ERR"

head2 "ProcSocks macOS spike"
say "时间:       $(date '+%Y-%m-%d %H:%M:%S')"
say "系统:       $(sw_vers -productVersion) ($(uname -m))"
say "目标:       http://$TARGET_HOST:$TARGET_PORT/"
say "重定向端口: $REDIR_PORTS"
say "监听:       $LISTEN_ADDR:$LISTEN_PORT"

[ "$(id -u)" -eq 0 ] || die "请用 sudo 运行:  sudo bash $SPIKE_DIR/run-spike.sh"
[ -x "$PYTHON" ]     || die "找不到 python3: $PYTHON"
[ -x "$PFCTL" ]      || die "找不到 pfctl: $PFCTL"

# 防呆：把本脚本及其所有子进程的 stdin 接到 /dev/null。
# 只要有哪个子命令（awk/grep/sed…）因为参数被拆错而没拿到输入文件，
# 它就会去读 stdin；接上 /dev/null 会立刻 EOF 报错并退出，而不是永远挂住。
exec 0</dev/null

# ---- spike #2：编译 pidforport（查「谁拥有这个本地端口」的小工具）----
PIDFORPORT_BIN="$SPIKE_DIR/pidforport"
if [ ! -x "$PIDFORPORT_BIN" ] || [ "$SPIKE_DIR/pidforport.c" -nt "$PIDFORPORT_BIN" ]; then
    if command -v xcrun >/dev/null 2>&1; then
        xcrun clang -O2 -o "$PIDFORPORT_BIN" "$SPIKE_DIR/pidforport.c" 2>&1 | sed 's/^/    /'
    else
        cc -O2 -o "$PIDFORPORT_BIN" "$SPIKE_DIR/pidforport.c" 2>&1 | sed 's/^/    /'
    fi
fi
[ -x "$PIDFORPORT_BIN" ] || die "pidforport 编译失败"

# 看门狗：万一还是有什么东西挂住了，90 秒后自己触发清理退出，
# 绝不允许把「pf 规则已载入 + ip.forwarding 已打开」的状态留在机器上。
# 注意用 $$ 而不是 $PPID —— 子 shell 里 $PPID 指向的是 sudo，不是本脚本。
( sleep 90; kill -TERM $$ 2>/dev/null ) &
WATCHDOG_PID=$!

REAL_USER="${SUDO_USER:-}"
if [ -z "$REAL_USER" ] || [ "$REAL_USER" = "root" ]; then
    REAL_USER="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null)"
fi
[ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ] || die "无法确定一个普通用户来做测试（SUDO_USER 为空）"
say "测试用户:   $REAL_USER"

# --------------------------------------------------------------------------
# 1. 记录 pf / forwarding 原始状态
# --------------------------------------------------------------------------
head2 "1. 记录原始状态"

PF_STATUS=$("$PFCTL" -s info 2>/dev/null | awk '/^Status/{print $2}')
PF_WAS_ENABLED=0
[ "$PF_STATUS" = "Enabled" ] && PF_WAS_ENABLED=1
say "pf 状态:                  ${PF_STATUS:-未知}"

if [ "$PF_WAS_ENABLED" = "1" ] && [ "${SPIKE_FORCE:-0}" != "1" ]; then
    say ""
    say "pf 当前是启用状态（可能有 VPN / 安全软件在用）。"
    say "继续跑会临时替换主规则集，可能影响它们。"
    say "确认可以的话请加 SPIKE_FORCE=1 重跑。"
    exit 2
fi

FORWARDING_BEFORE=$("$SYSCTL" -n net.inet.ip.forwarding 2>/dev/null || echo 0)
say "net.inet.ip.forwarding:  $FORWARDING_BEFORE"

# --------------------------------------------------------------------------
# 2. 基线：规则加载前，普通用户能不能正常访问目标
# --------------------------------------------------------------------------
head2 "2. 基线测试（不经过任何代理）"

BASELINE_BODY="$WORK/baseline.body"
BASELINE_CODE=$(/usr/bin/sudo -u "$REAL_USER" "$CURL" -sS --noproxy '*' \
    -o "$BASELINE_BODY" -w '%{http_code}' --max-time 15 \
    "http://$TARGET_HOST:$TARGET_PORT/" 2>"$WORK/baseline.err")
BASELINE_RC=$?
say "HTTP 状态码: ${BASELINE_CODE:-<无>} (curl 退出码 $BASELINE_RC)"

if [ "$BASELINE_CODE" != "200" ] && [ "$BASELINE_CODE" != "301" ] && [ "$BASELINE_CODE" != "302" ]; then
    say ""
    say "基线都不通，后面的结论没有意义。"
    say "curl stderr: $(cat "$WORK/baseline.err" 2>/dev/null | head -3)"
    say "可以换个目标重跑，例如:  TARGET_HOST=baidu.com sudo bash $0"
    exit 3
fi
say "基线正常，可以继续。"

# --------------------------------------------------------------------------
# 3. 生成并载入临时规则集
# --------------------------------------------------------------------------
head2 "3. 载入 pf 规则"

# pf 要求规则严格按段排列：options → normalization → queueing → translation → filtering
# rdr 属于 translation，必须在 filtering 段（Apple 的 anchor 声明 + 我们的 pass 规则）之前
gen_ruleset() {   # $1 = filter 规则里的 user 子句
    cat <<EOF
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"

# ---- ProcSocks spike / translation 段（必须排在 filtering 之前）----
rdr pass proto tcp from any to any port { $REDIR_PORTS } -> $LISTEN_ADDR port $LISTEN_PORT

# ---- Apple 自带的 filtering anchors ----
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"

# ---- ProcSocks spike / filtering 段 ----
# 本机自己产生的流量，rdr 单独拦不住，要靠 route-to 把它踹到 lo0；
# user 子句让代理进程自己的出站连接豁免，从而不会死循环
pass out route-to (lo0 127.0.0.1) proto tcp from any to any port { $REDIR_PORTS } $1
EOF
}

"$SYSCTL" -w net.inet.ip.forwarding=1 >/dev/null 2>&1
say ""
say "已开启 net.inet.ip.forwarding=1"

# pf 对 user 取反有两种写法，逐一试，哪个能载入用哪个
LOADED_VARIANT=""
PF_LOAD_OUT=""
for VARIANT in "user { != $TPROXY_USER }" "user != $TPROXY_USER"; do
    gen_ruleset "$VARIANT" > "$RULESET"
    PF_LOAD_OUT=$("$PFCTL" -f "$RULESET" 2>&1)
    if [ $? -eq 0 ]; then
        LOADED_VARIANT="$VARIANT"
        break
    fi
    say "变体 [$VARIANT] 载入失败: $PF_LOAD_OUT"
done

if [ -z "$LOADED_VARIANT" ]; then
    say ""
    say "两种 user 写法都载入失败。最后一次的错误输出:"
    say "$PF_LOAD_OUT"
    exit 5
fi
say "规则载入成功，user 子句用的是: $LOADED_VARIANT"
[ -n "$PF_LOAD_OUT" ] && say "pfctl 输出: $PF_LOAD_OUT"

say ""
say "最终规则内容:"
sed 's/^/    /' "$RULESET" | tee -a "$REPORT"


PF_ENABLE_OUT=$("$PFCTL" -E 2>&1)
PF_TOKEN=$(printf '%s\n' "$PF_ENABLE_OUT" | awk '/Token/{print $NF}')
say "pfctl -E 输出: $(printf '%s' "$PF_ENABLE_OUT" | tr '\n' ' ')"
say "Token: ${PF_TOKEN:-<无>}"

head2 "3b. pf 实际解析后的规则"
say "--- rdr (pfctl -sn) ---"
"$PFCTL" -sn 2>&1 | tee -a "$REPORT"
say "--- filter (pfctl -sr) ---"
"$PFCTL" -sr 2>&1 | tee -a "$REPORT"

# --------------------------------------------------------------------------
# 4. 启动监听器
# --------------------------------------------------------------------------
head2 "4. 启动监听器"

SPIKE_LOG="$LISTENER_LOG" \
SPIKE_LISTEN_ADDR="$LISTEN_ADDR" \
SPIKE_LISTEN_PORT="$LISTEN_PORT" \
SPIKE_PIDFORPORT="$PIDFORPORT_BIN" \
    nohup "$PYTHON" "$SPIKE_DIR/listener.py" >"$LISTENER_ERR" 2>&1 &
LISTENER_PID=$!

# 不能靠 sleep 拍脑袋：Python 冷启动（要过 CLT shim）可能超过 1 秒。
# 必须轮询日志里那行「监听器已启动」，也就是 bind+listen 成功之后才继续，
# 否则测试 A 会在监听器就绪之前发 SYN，内核回 RST，全部误判成"拦不到"。
wait_for_listener() {
    local waited=0
    while [ "$waited" -lt 150 ]; do
        if grep -q "监听器已启动" "$LISTENER_LOG" 2>/dev/null; then
            # 注意：这里绝对不要用 $(awk "...") —— 嵌在双引号里的多层引号会被
            # bash 拆烂，awk 拿不到程序文本就会去读 stdin 并且永远阻塞。
            say "监听器已就绪（等待 $((waited / 10)).$((waited % 10)) 秒）"
            return 0
        fi
        if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
            say "监听器进程已退出，stderr:"
            sed 's/^/    /' "$LISTENER_ERR" | tee -a "$REPORT"
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    say "等了 15 秒监听器仍未就绪，stderr:"
    sed 's/^/    /' "$LISTENER_ERR" | tee -a "$REPORT"
    return 1
}

say "监听器 pid=$LISTENER_PID"
wait_for_listener || exit 4
say "启动日志: $(head -1 "$LISTENER_LOG" 2>/dev/null)"

# 再稳一手：确认端口真的在 listen
sleep 0.3

hit_count() {
    local n
    n=$(grep -c "被拦截" "$LISTENER_LOG" 2>/dev/null)
    printf '%s' "${n:-0}"
}

# --------------------------------------------------------------------------
# 5. 测试 A：普通用户的流量应当被拦截
# --------------------------------------------------------------------------
head2 "5. 测试 A —— 普通用户 ($REAL_USER) 访问目标"

A_BEFORE=$(hit_count)
A_BODY="$WORK/a.body"
A_CODE=$(/usr/bin/sudo -u "$REAL_USER" "$CURL" -sS --noproxy '*' \
    -o "$A_BODY" -w '%{http_code}' --max-time 20 \
    "http://$TARGET_HOST:$TARGET_PORT/" 2>"$WORK/a.err")
A_RC=$?
sleep 0.5
A_AFTER=$(hit_count)
A_HITS=$((A_AFTER - A_BEFORE))

say "HTTP 状态码:      ${A_CODE:-<无>} (curl 退出码 $A_RC)"
say "被拦截的连接数:   $A_HITS"
say "curl stderr:      $(head -3 "$WORK/a.err" 2>/dev/null | tr '\n' ' ')"
say "返回体大小:       $(wc -c < "$A_BODY" 2>/dev/null | tr -d ' ') 字节"

# --------------------------------------------------------------------------
# 6. 测试 B：root 的流量应当豁免（模拟代理自己的出站）
# --------------------------------------------------------------------------
head2 "6. 测试 B —— root 访问目标（应当不被拦截）"

B_BEFORE=$(hit_count)
B_BODY="$WORK/b.body"
B_CODE=$("$CURL" -sS --noproxy '*' \
    -o "$B_BODY" -w '%{http_code}' --max-time 20 \
    "http://$TARGET_HOST:$TARGET_PORT/" 2>"$WORK/b.err")
B_RC=$?
sleep 0.5
B_AFTER=$(hit_count)
B_HITS=$((B_AFTER - B_BEFORE))

say "HTTP 状态码:      ${B_CODE:-<无>} (curl 退出码 $B_RC)"
say "被拦截的连接数:   $B_HITS   (期望 0)"

# --------------------------------------------------------------------------
# 7. 诊断快照
# --------------------------------------------------------------------------
head2 "7. pf 状态表快照"
"$PFCTL" -s state 2>&1 | tee -a "$REPORT"

head2 "7b. 监听器日志"
cat "$LISTENER_LOG" 2>/dev/null | tee -a "$REPORT"
say "--- listener stderr ---"
cat "$LISTENER_ERR" 2>/dev/null | tee -a "$REPORT"

# --------------------------------------------------------------------------
# 8. 结论
# --------------------------------------------------------------------------
head2 "8. 结论"

verdict() {  # verdict <标签> <PASS|FAIL> <说明>
    printf '  [%s] %-34s %s\n' "$2" "$1" "$3" | tee -a "$REPORT"
}

say ""

if [ "$A_HITS" -ge 1 ]; then
    verdict "Q1 能否拦本机普通用户流量" PASS "拦到了 $A_HITS 条连接"
else
    verdict "Q1 能否拦本机普通用户流量" FAIL "一条都没拦到，规则或 route-to 没生效"
fi

if grep -q "还原出原始目的地" "$LISTENER_LOG" 2>/dev/null; then
    verdict "Q2 能否还原原始目的地" PASS "$(grep -m1 '还原出原始目的地' "$LISTENER_LOG" | sed 's/^.*还原出/还原出/')"
else
    verdict "Q2 能否还原原始目的地" FAIL "pfctl -s state 里没匹配上，见上面的状态表快照"
fi

if [ "$B_HITS" -eq 0 ] && { [ "$B_CODE" = "200" ] || [ "$B_CODE" = "301" ]; }; then
    verdict "Q3 代理自身能否不回环" PASS "root 的 $B_HITS 条连接被正确豁免，且访问成功"
elif [ "$B_HITS" -gt 0 ]; then
    verdict "Q3 代理自身能否不回环" FAIL "root 的流量也被拦了 $B_HITS 条，user 豁免没生效"
else
    verdict "Q3 代理自身能否不回环" FAIL "虽然没被拦，但访问失败（码 ${B_CODE:-无}），pf 可能把网络搞坏了"
fi

if [ "$A_CODE" = "200" ] || [ "$A_CODE" = "301" ]; then
    verdict "Q4 端到端透传" PASS "普通用户无感知拿到 ${A_CODE}，$(( $(wc -c < "$A_BODY" 2>/dev/null || echo 0) )) 字节"
else
    verdict "Q4 端到端透传" FAIL "被拦住了但没转发成功（码 ${A_CODE:-无}），看监听器日志里直连是否失败"
fi

if grep -q "\[libproc\] path=" "$LISTENER_LOG" 2>/dev/null; then
    LP_PID=$(grep -m1 -o '\[libproc\] pid=[0-9]*' "$LISTENER_LOG" | head -1)
    LP_PATH=$(grep -m1 '\[libproc\] path=' "$LISTENER_LOG" | sed 's/^.*path=//')
    verdict "Q5 能否定位发起进程" PASS "$LP_PID  $LP_PATH"
    if grep -q "foreign 与 pfctl 还原结果一致" "$LISTENER_LOG" 2>/dev/null; then
        verdict "Q5b libproc 能否替代 pfctl" PASS "foreign 就是原始目的地，pfctl 文本解析可以删掉"
    else
        verdict "Q5b libproc 能否替代 pfctl" FAIL "两边不一致，仍需保留 pfctl -s state 解析"
    fi
else
    verdict "Q5 能否定位发起进程" FAIL "pidforport 没找到进程，见监听器日志"
    verdict "Q5b libproc 能否替代 pfctl" FAIL "未验证"
fi

say ""
say "把上面这份报告整个贴回来即可。"
