#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProcSocks macOS spike —— 透明 TCP 监听器

由 run-spike.sh 以 root 身份启动。对每一个被 pf 重定向过来的连接：

  1. 记录 getpeername()，也就是「谁连进来的、源端口是多少」
  2. 调用 `pfctl -s state`，按 (客户端地址, 端口) 反查原始目的地
     —— 这一步的解析思路沿用 mitmproxy 的 mitmproxy/platform/pf.py
  3. 直连还原出来的原始目的地，双向搬运字节

之所以能「直连而不死循环」：pf 规则里写了 `user { != root }`，
本进程以 root 运行，它自己发出去的连接不会被 route-to 再抓一次。

所有过程都写进 SPIKE_LOG 指向的文件，供 run-spike.sh 生成报告。
"""

import os
import re
import socket
import subprocess
import sys
import threading
import time

LISTEN_ADDR = os.environ.get("SPIKE_LISTEN_ADDR", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("SPIKE_LISTEN_PORT", "7891"))
LOG_PATH = os.environ.get("SPIKE_LOG", "/tmp/procsocks-spike/listener.log")
CONNECT_TIMEOUT = float(os.environ.get("SPIKE_CONNECT_TIMEOUT", "10"))
MAX_CONN = int(os.environ.get("SPIKE_MAX_CONN", "300"))
PIDFORPORT = os.environ.get("SPIKE_PIDFORPORT", "")
BUFSIZE = 65536

_log_lock = threading.Lock()


def lookup_owner(local_port):
    """调 pidforport 查「谁拥有这个本地端口」，返回 dict 或 None。

    这是 ProcSocks macOS 后端真正要用的原语：pf 保留了客户端源端口，
    所以扫一遍 socket 表就能定位进程 + 可执行路径 + 原始目的地。
    """
    if not PIDFORPORT or not os.path.exists(PIDFORPORT):
        return None
    try:
        proc = subprocess.run(
            [PIDFORPORT, str(local_port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
    except Exception as exc:
        log("pidforport 调用异常: %r" % (exc,))
        return None
    if proc.returncode != 0:
        return None
    out = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip()
    return out or None


def is_loopback(host):
    """判断是不是回环地址。转发到回环地址几乎一定是规则把自己套住了。"""
    if host.startswith("127.") or host == "::1":
        return True
    return host in ("localhost",)


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    with _log_lock:
        try:
            with open(LOG_PATH, "a") as fh:
                fh.write(line + "\n")
        except Exception:
            pass


def read_pf_state():
    """读取 pf 状态表全文。返回 str，失败返回 None。"""
    try:
        proc = subprocess.run(
            ["/sbin/pfctl", "-s", "state"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
    except Exception as exc:
        log("pfctl -s state 调用异常: %r" % (exc,))
        return None
    if proc.returncode != 0:
        log("pfctl -s state 退出码 %d, stderr=%s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace").strip()))
        return None
    return proc.stdout.decode("utf-8", "replace")


_IPV4_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
_BRACKET_V6_RE = re.compile(r"^\[([0-9A-Fa-f:]+)\]:(\d{1,5})$")
_PFCTL_V6_RE = re.compile(r"^([0-9A-Fa-f:]+)\[(\d{1,5})\]$")


def parse_ip_port(token):
    """把 pfctl 输出里的一个地址字段解析成 (host, port)，解析不了返回 None。

    需要兼容三种写法：
        93.184.216.34:80
        [2606:4700::681f:4ad0]:443
        2606:4700::681f:4ad0[443]      <- pfctl 自己的 IPv6 写法
    """
    token = (token or "").strip().strip("(),")
    if not token:
        return None
    for regex in (_IPV4_RE, _BRACKET_V6_RE, _PFCTL_V6_RE):
        m = regex.match(token)
        if m:
            return m.group(1), int(m.group(2))
    return None


def lookup_original(client_ip, client_port, state_text):
    """在 pf 状态表里反查这条连接的原始目的地。

    返回 (host, port, matched_line)；没找到时 host/port 为 None。
    """
    # pfctl 有时会把 IPv4 写成 ipv4-mapped 的形式 ::ffff:127.0.0.1
    client_ip = re.sub(r"^::ffff:(?=\d+\.\d+\.\d+\.\d+$)", "", client_ip)
    spec_v4 = "%s:%d" % (client_ip, client_port)
    spec_v6 = "%s[%d]" % (client_ip, client_port)

    for line in state_text.splitlines():
        if "ESTABLISHED:ESTABLISHED" not in line:
            continue
        if spec_v4 not in line and spec_v6 not in line:
            continue

        tokens = line.split()

        # 首选 mitmproxy 的做法：第 5 个字段就是原始目的地
        if len(tokens) > 4:
            parsed = parse_ip_port(tokens[4])
            if parsed:
                return parsed[0], parsed[1], line

        # 兜底：取 "->" 之后的第一个能解析的地址
        if "->" in tokens:
            idx = tokens.index("->")
            for tok in tokens[idx + 1:]:
                parsed = parse_ip_port(tok)
                if parsed:
                    return parsed[0], parsed[1], line

        return None, None, line

    return None, None, None


def pump(src, dst, tag):
    """把一个方向的字节搬完。"""
    try:
        while True:
            chunk = src.recv(BUFSIZE)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(conn, addr, index, counter):
    client_ip, client_port = addr[0], addr[1]
    with counter["lock"]:
        counter["count"] += 1
        seen = counter["count"]

    if seen > MAX_CONN:
        # 防止规则配错导致连接无限堆积（例如代理自己的出站被再次拦截形成死循环）
        log("连接 #%d: 已超过上限 %d，拒绝继续处理（疑似规则回环）"
            % (index, MAX_CONN))
        conn.close()
        return

    log("连接 #%d: 被拦截，来自 %s:%d" % (index, client_ip, client_port))

    state_text = read_pf_state()
    if state_text is None:
        log("连接 #%d: 读不到 pf 状态表，放弃" % index)
        conn.close()
        return

    dst_ip, dst_port, matched = lookup_original(client_ip, client_port, state_text)
    if dst_ip is None:
        log("连接 #%d: 未能还原原始目的地。当前状态表快照：" % index)
        for raw in state_text.splitlines():
            if raw.strip():
                log("    | %s" % raw)
        conn.close()
        return

    log("连接 #%d: 还原出原始目的地 -> %s:%d" % (index, dst_ip, dst_port))
    log("连接 #%d: 命中的状态行 -> %s" % (index, matched.strip()))

    # ---- spike #2: 用 libproc 交叉验证 ----
    # 如果 libproc 也能同时给出「发起进程」和「原始目的地」，那 pfctl 文本解析
    # 就可以整个删掉 —— 那是最脆的一环。
    owner = lookup_owner(client_port)
    if owner is None:
        log("连接 #%d: [libproc] 未能定位进程" % index)
    else:
        log("连接 #%d: [libproc] pid=%s" % (index, owner.get("pid")))
        log("连接 #%d: [libproc] path=%s" % (index, owner.get("path")))
        log("连接 #%d: [libproc] local=%s foreign=%s"
            % (index, owner.get("local"), owner.get("foreign")))
        foreign = owner.get("foreign", "")
        if foreign.startswith("[") or foreign.count(":") > 1:
            foreign_host = foreign.rsplit(":", 1)[0].strip("[]")
        else:
            foreign_host = foreign.rsplit(":", 1)[0]
        if foreign_host == dst_ip:
            log("连接 #%d: [libproc] foreign 与 pfctl 还原结果一致 ✓" % index)
        else:
            log("连接 #%d: [libproc] foreign(%s) 与 pfctl 结果(%s:%d) 不一致 ✗"
                % (index, foreign, dst_ip, dst_port))

    if (dst_ip, dst_port) == (LISTEN_ADDR, LISTEN_PORT):
        log("连接 #%d: 解析结果就是监听地址本身，连下去会死循环，放弃" % index)
        conn.close()
        return

    if is_loopback(dst_ip):
        log("连接 #%d: 还原出的目的地是回环地址 %s:%d —— 基本可以确定是规则把"
            "代理自己的出站又套回来了，拒绝转发以免死循环" % (index, dst_ip, dst_port))
        conn.close()
        return

    try:
        upstream = socket.create_connection((dst_ip, dst_port), timeout=CONNECT_TIMEOUT)
    except Exception as exc:
        log("连接 #%d: 直连 %s:%d 失败: %r" % (index, dst_ip, dst_port, exc))
        conn.close()
        return

    log("连接 #%d: 直连成功，开始双向转发" % index)
    t = threading.Thread(target=pump, args=(upstream, conn, index), daemon=True)
    t.start()
    pump(conn, upstream, index)
    t.join(timeout=5)
    try:
        upstream.close()
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass
    log("连接 #%d: 转发结束" % index)


def main():
    counter = {"count": 0, "lock": threading.Lock()}

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((LISTEN_ADDR, LISTEN_PORT))
    except OSError as exc:
        log("绑定 %s:%d 失败: %r" % (LISTEN_ADDR, LISTEN_PORT, exc))
        return 1
    srv.listen(128)

    log("监听器已启动 pid=%d uid=%d gid=%d, 绑定 %s:%d"
        % (os.getpid(), os.getuid(), os.getgid(), LISTEN_ADDR, LISTEN_PORT))

    index = 0
    while True:
        try:
            conn, addr = srv.accept()
        except OSError as exc:
            log("accept 失败: %r" % (exc,))
            break
        index += 1
        threading.Thread(target=handle, args=(conn, addr, index, counter), daemon=True).start()

    return 0


if __name__ == "__main__":
    sys.exit(main())
