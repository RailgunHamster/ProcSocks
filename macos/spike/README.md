# ProcSocks macOS spike —— pf 路线可行性验证

这一步**不是**在写 ProcSocks 的 macOS 版，而是先用最小成本回答一个岔路口问题：

> **macOS 上不花钱（不办 Apple Developer Program）能不能做透明的按进程 TCP 代理？**

Apple 官方的 Network Extension 要 $99/年 + Developer ID + provisioning profile 才装得上。
另一条路是用 `pf`（macOS 自带的内核包过滤器）+ `route-to`，只需要 root。
mitmproxy 的 `--mode transparent` 在 macOS 上就是这么实现的——但它的文档停留在很多年前，
我要确认它在 **macOS 26** 上还成不成立。

## 跑法

```bash
sudo bash /Users/rh/procsocks-mac/spike/run-spike.sh
```

跑完把终端里那份报告贴回来就行。全过程大概 10 秒。

## 它验证什么

| 编号 | 问题 | 为什么重要 |
|---|---|---|
| Q1 | 能否拦住「本机普通用户进程」发出的 TCP？ | macOS 上 `rdr` 单独拦不住本机流量，必须靠 `pass out route-to`。这是整条路线的前提 |
| Q2 | 能否从 `pfctl -s state` 还原出原始目的地？ | 拦住之后必须知道「这个应用本来想连谁」，否则代理无从下手 |
| Q3 | 代理自己（root）的出站能否被豁免、不回环？ | 代理要去连真实目的地，如果它自己的连接又被 pf 抓回来就是死循环 |
| Q4 | 端到端：普通用户的 `curl` 能否无感知地拿到响应？ | 前三项都过了但不通，说明还差别的环节 |
| Q5 | 能否定位「发起这条连接的是哪个进程」？ | 这是 ProcSocks 路径正则规则的前提，也是 Network Extension 做不到的事 |
| Q5b | socket 的 `foreign` 字段能否替代 `pfctl -s state`？ | 如果成立，就能删掉整条路线里最脆的一环（解析 pfctl 文本输出） |

## 它到底动了什么

**只动这些，退出时全部还原：**

- 用 `pfctl -f` 载入一份**临时主规则集**（内容 = Apple 默认的 `/etc/pf.conf` + 我们的两条规则）。
  **`/etc/pf.conf` 这个文件本身没有被修改。**
- 打开 `net.inet.ip.forwarding=1`，退出时恢复原值。
- 在 `127.0.0.1:7891` 监听。
- 用 `pfctl -E` 多持有一个 pf 启用引用，退出时用 `-X` 释放。

**安全边界：**

- 只重定向 **80 端口**（`REDIR_PORTS` 默认 `80`）。**HTTPS / SSH / 其它一切不受影响。**
- 如果 pf 当前处于 Enabled（可能有 VPN 或安全软件在用），脚本会**拒绝运行**，除非你显式
  `SPIKE_FORCE=1`。
- 出错、Ctrl+C、被 kill 都会走 `trap` 清理。
- 监听器带三重防回环保护：还原出的目的地若是回环地址、或等于监听地址本身、或连接数超过
  `SPIKE_MAX_CONN`（默认 300），一律拒绝转发并大声记日志。

**手工兜底**（万一没清理干净导致 80 端口不通）：

```bash
sudo pfctl -d
sudo pfctl -f /etc/pf.conf
```

## 怎么读结论

脚本最后会打印：

```
  [PASS] Q1 能否拦本机普通用户流量        拦到了 1 条连接
  [PASS] Q2 能否还原原始目的地            还原出原始目的地 -> 93.184.216.34:80
  [PASS] Q3 代理自身能否不回环            root 的 0 条连接被正确豁免，且访问成功
  [PASS] Q4 端到端透传                    普通用户无感知拿到 200，1256 字节
```

**四项全 PASS** → 免费路线成立。后面就是体力活：把 ProcSocks 现有的 Rust 业务代码
（config、规则引擎、SNI/Host 恢复、SOCKS5 客户端）搬过来，再写一个 pf 后端替换掉
Windows 的 NetFilter 后端。

**Q1 或 Q4 FAIL** → 把报告贴回来，重点看两处：
- 第 7b 节「监听器日志」，看是根本没拦到、还是拦到了但还原不出目的地
- 第 7 节「pf 状态表快照」，看 macOS 26 的状态行格式到底长什么样

## 可调开关

```bash
# 换个目标（默认 example.com，如果这个域名不通就换掉）
TARGET_HOST=baidu.com sudo bash run-spike.sh

# 换成 443 测 TLS 透传（风险更大，因为 443 断了影响面广）
REDIR_PORTS=443 sudo bash run-spike.sh

# 用 mitmproxy 文档里的原版配方（代理跑在 nobody 下，而不是豁免 root）
TPROXY_USER=nobody sudo bash run-spike.sh
```

## 文件

| 文件 | 作用 |
|---|---|
| `run-spike.sh` | 编排：载入规则 → 起监听器 → 跑测试 → 出报告 → 还原系统 |
| `listener.py` | 透明监听器：`pfctl -s state` 反查原始目的地 → 直连 → 双向转发 |
| `pidforport.c` | libproc 小工具：查「谁拥有本地 TCP 端口 X」→ PID + 可执行路径 + 原始目的地 |

`listener.py` 里反查原始目的地的那段解析逻辑，脱胎于
[mitmproxy 的 `mitmproxy/platform/pf.py`](https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/platform/pf.py)，
并额外兼容了 IPv6 的三种写法、以及 macOS 26 可能出现的格式差异（解析不出来时会把整个状态表打到日志里）。

产出的报告和日志在 `/tmp/procsocks-spike/`。
