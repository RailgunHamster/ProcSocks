# UDP 实现与验证

版本 0.3.0 默认启用 `redirectUdp`。GUI 的“代理 UDP（含 QUIC）”开关、进程列表、
高级代理 / 绕过规则和 5 / 15 / 30 分钟图表共用现有配置。

## 转发路径

Mac 的 PF 将配置端口范围内的非 root UDP 用 `route-to` 送入专用 utun，保留
原始源 / 目标端点。libproc 匹配 IPv4 / IPv6、connected / unconnected 及 wildcard
UDP socket；歧义归属丢弃。每个应用 socket 共用一个 SOCKS 关联，保留跨目标的
源端口语义；未选进程通过专属 utun 的 PF 标记回注原包，保持直连原始源端口。
会话有空闲期限，
发送和返回都检查进程路径与 socket generation，避免 PID / 源端口复用继承旧规则。
返回包保留原目标作为来源，并计算 IPv4、UDP / IPv6 pseudo-header 校验和。
普通 IP 分片有边界和超时限制的重组；SOCKS FRAG != 0 按 RFC 1928 丢弃。

TCP / UDP 共用 watchdog 撤销 PF，并恢复原有 IPv4 / IPv6 转发设置；关闭 utun
socket 会删除该接口。
仅创建专用测试网段的接口地址，没有默认路由或系统 DNS 变更。
多播、255.255.255.255 广播、回环及 IPv6 链路本地 UDP 保持系统原路径。

Windows 的 NetFilter 按进程截取 UDP，向本机桥发送 UDP ASSOCIATE。新适配层
修复了 Netch 1.9.7 在进程判断前直接绕过 UDP 53 的行为。未选进程的 DNS 不改走
代理，内核驱动 / nfapi 版本不变。核心检查新增导出能力和锁定组件的 SHA-256。

## 统计

只在 SOCKS UDP 数据包发送成功后记上传、回包向应用写入成功后记下载。
仅计 DATA，不含 SOCKS / IP / UDP 包头。未匹配、绕过、UDP 协商和失败发送不计入。
UDP 无连接，Mac 会话在空闲 120 秒后回收，应用关闭 socket 后两秒内回收，
因此“活跃连接”也包括 UDP 会话。Windows 关联跟随应用 socket 的控制连接，
上游断开后下一个有效包重建关联，避免应用长时间空闲后 UDP 失效。

## 2026-10-02 验收

- 当前 Mac 上游 `127.0.0.1:7890` 的 UDP ASSOCIATE 与真实 DNS 往返通过。
- Mac 普通用户测试进程同一 unconnected socket 向 `1.1.1.1:53` 和 `8.8.8.8:53`
  发送请求，两个原始来源均正确；GUI 后台计数上传 58 / 下载 122 字节。
- 未命中规则的测试进程真实 UDP 直连通过，未出现在代理流量快照。
- 两个普通用户的直连 UDP socket 在本机非回环地址通信，客户端 / 服务端均保留
  原始源端口；验证 PF 标记回注不会把未选中的 UDP 服务变成另一源端口。
- 隔离 SOCKS 上游完成 Mac 真实 PF → utun → IPv4 / IPv6 UDP → utun 回注路径；
  IPv6 connected socket 上传 / 下载均 29 字节。此项验证本机 IPv6 传输，不宣称
  当前真实上游具备 IPv6 UDP 出网能力：真实上游 IPv6 DNS 测试超时；
  后续切换网络后，本机也没有可用的 IPv6 外网路由。
- railgunhamster 的真实 NetFilter 驱动和新适配层完成 selected helper 的两个
  UDP DNS 目标往返，返回来源正确；原有服务规则随后恢复，UDP 开启。
- Windows 真实驱动配隔离上游完成 60000 / 8192 / 0 字节的逐字节 UDP 回显；
  同一应用 socket 空闲 125 秒，上游控制连接在 30 秒断开后，下一包重连成功。
- 自动测试覆盖地址包头、超长 / 截断 / SOCKS 分片、双目标关联、客户端来源隔离、
  TCP 控制连接关闭、UDP 归属、分片重组及返回包校验和。

`gui/NetworkTest.swift` 测试应用增加 IPv4 / IPv6 UDP DNS 往返，可通过
`scripts/build-network-test-app.sh` 构建，再从 GUI 选中该应用运行。
将 app 放在不被用户高级绕过规则匹配的目录，例如 `~/Applications/`。

## 使用边界

UDP 按原始 IP 转发，TCP 的严格域名选项不作用于 UDP，也不嗅探 QUIC SNI。
本项目能传输 QUIC 数据包，未以某个 HTTP/3 网站成功响应作为本次验收条件。
是否访问成功及上游如何分流，仍取决于上游的 UDP、目标 IP、IPv6 与路由规则。
系统 DNS 服务代发的请求归属系统服务，不自动归属原始调用应用；不改全系统 DNS。
root 程序和上面列出的本地通信例外仍不在接管范围。
