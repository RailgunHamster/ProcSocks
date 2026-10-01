#!/usr/bin/env python3
"""验证 SOCKS 桥接（`procsocks bridge`）——不需要 root。

这个脚本模拟 Windows 那边 NetFilter 驱动的行为：作为 SOCKS5 客户端连到
监听端口，但**只给出一个 IP 目标，不给域名**。桥接必须自己从后续的
TLS SNI / HTTP Host 里把域名还原出来，再拿域名去和上游 SOCKS5 协商。

它覆盖的正是 macOS 路径共用的那半边（`bridge::relay_through_upstream`），
所以跑通它等于确认了 macOS 后端「嗅探 + 上游 SOCKS5 + 双向转发」没有回归。

用法：
    cargo build --release
    ./target/release/procsocks --config procsocks.local.json bridge &
    python3 scripts/verify-bridge.py
"""
import argparse
import socket
import ssl
import struct
import sys

def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("SOCKS5 握手期间连接关闭")
        data.extend(chunk)
    return bytes(data)


def socks5_connect(listen, ip, port, timeout):
    """以 IP 目标的 SOCKS5 CONNECT 连上本地桥接，返回已建立的 socket。"""
    sock = socket.create_connection(listen, timeout=timeout)
    sock.sendall(b"\x05\x01\x00")  # VER=5, NMETHODS=1, NO-AUTH
    greeting = read_exact(sock, 2)
    if greeting != b"\x05\x00":
        raise RuntimeError(f"桥接拒绝了无认证方法: {greeting!r}")

    request = b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", port)
    sock.sendall(request)
    reply = read_exact(sock, 10)
    if len(reply) < 2 or reply[1] != 0x00:
        raise RuntimeError(f"CONNECT 被拒绝: {reply!r}")
    return sock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=7891)
    parser.add_argument("--host", default="example.com")
    parser.add_argument("--port", type=int)
    parser.add_argument("--tls", action="store_true", help="使用 TLS ClientHello SNI 恢复域名（默认端口 443）")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    if args.port is None:
        args.port = 443 if args.tls else 80
    for port in (args.listen_port, args.port):
        if not 1 <= port <= 65535:
            parser.error("端口必须在 1–65535 之间")
    if args.timeout <= 0:
        parser.error("超时必须大于零")
    try:
        ip = socket.gethostbyname(args.host)
    except OSError as exc:
        print(f"FAIL 无法解析 {args.host}: {exc}")
        return 1
    print(f"目标 IP（故意只给 IP，不给域名）: {ip}")

    try:
        sock = socks5_connect((args.listen_host, args.listen_port), ip, args.port, args.timeout)
    except Exception as exc:
        print(f"FAIL 连接桥接失败: {exc}")
        return 1

    data = b""
    try:
        if args.tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=args.host)
        # In TLS mode SNI must be recovered before the TLS handshake can finish;
        # otherwise the plaintext HTTP Host supplies the recovered hostname.
        sock.sendall(
            f"GET / HTTP/1.1\r\nHost: {args.host}:{args.port}\r\nConnection: close\r\n\r\n".encode()
        )
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        print(f"FAIL TLS 握手或 HTTP 转发出错: {exc}")
        return 1
    finally:
        sock.close()

    if not data:
        print("FAIL 没有收到任何响应（嗅探或上游协商大概失败了）")
        return 1

    status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    print(f"响应状态行: {status}")
    print(f"响应体字节数: {len(data)}")

    parts = status.split()
    ok = len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1] in ("200", "301", "302")
    if ok:
        print()
        print("PASS 桥接完成了域名还原并成功经上游 SOCKS5 取回内容")
        print(f"     （桥接日志里应当能看到 routed={args.host}:{args.port}）")
        return 0
    print(f"FAIL 状态行不是成功响应: {status}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
