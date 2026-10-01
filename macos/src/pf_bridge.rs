//! macOS：pf 重定向过来的连接怎么处理。
//!
//! 这是 macOS 后端的另一半，和 [`crate::pf`] 配合：
//!
//! ```text
//! 应用 connect(ip, port)
//!    │
//!    ▼  pf: rdr 改写目的地址 + route-to 踹到 lo0
//! 本进程 127.0.0.1:7891 accept()
//!    │  对端地址形如 192.168.72.242:61081 —— 源 IP 和源端口都被保留了
//!    ▼  libproc 扫 socket 表
//! pid + 可执行路径 + 原始目的地
//!    │
//!    ├─ 命中 processPatterns  → 嗅探 SNI/Host → 上游 SOCKS5
//!    └─ 否则                  → 直连原始目的地，纯字节转发
//! ```
//!
//! ## 和 Windows 后端的根本差异
//!
//! Windows 上是对面的 NetFilter 驱动**以 SOCKS5 客户端的身份**连过来的，所以
//! [`crate::bridge`] 的第一件事是 `accept_socks5_request()`，目标地址由驱动在
//! SOCKS5 请求里告诉我们。
//!
//! macOS 上 pf 只是把 TCP 重定向过来，**没有任何 SOCKS5 前导**。目标地址必须
//! 自己查——这就是 [`crate::libproc`] 存在的理由。前半段完全不同，
//! 后半段（嗅探 + 上游 SOCKS5 + 双向转发）两边共用。
//!
//! ## 直连回退为什么不会死循环
//!
//! 不匹配的进程要「原样放行」，也就是由本进程替它连到原始目的地。本进程以 root
//! 运行，而 pf 规则里写了 `user != root`，所以这些出站连接不会再被 route-to 抓
//! 一次。这条链路在 `spike/` 下用真实流量验证过。

#![cfg(target_os = "macos")]

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::{
    bridge::{Target, TargetAddress, relay_through_upstream},
    config::Config,
    libproc,
    rules::RuleSet,
    traffic::Ledger,
};

static CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

pub struct PfBridge {
    /// 至少要有一个 IPv4 监听器；开了 IPv6 就再绑一个 `[::1]:同一端口`。
    ///
    /// 之所以不用一个双栈 socket：tokio 没有暴露 `IPV6_V6ONLY`，显式绑两个地址
    /// 反而更直白，也让"IPv4 没绑上"和"IPv6 没绑上"能分别报错。
    listeners: Vec<TcpListener>,
    config: Arc<Config>,
    rules: Arc<RuleSet>,
    traffic: Option<Arc<Ledger>>,
}

impl PfBridge {
    pub async fn bind(config: Arc<Config>, traffic: Option<Arc<Ledger>>) -> Result<Self> {
        config.validate_bridge()?;
        let rules = Arc::new(RuleSet::compile(
            &config.process_patterns,
            &config.bypass_patterns,
        )?);

        let mut addresses = vec![config.listen];
        if let Some(address) = crate::pf::ipv6_listen_address(&config) {
            addresses.push(address);
        }
        let mut listeners = Vec::with_capacity(addresses.len());
        for address in addresses {
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("failed to listen on {address}"))?;
            listeners.push(listener);
        }

        Ok(Self {
            listeners,
            config,
            rules,
            traffic,
        })
    }

    pub async fn run(self) -> Result<()> {
        let PfBridge {
            listeners,
            config,
            rules,
            traffic,
        } = self;

        info!(
            ports = %config.redirect_ports,
            ipv6 = config.redirect_ipv6,
            process_rules = config.process_patterns.len(),
            bypass_rules = config.bypass_patterns.len(),
            "transparent redirect listener is up"
        );

        // 每个监听地址一个 accept 循环。任意一个出错就整体退出——
        // 半死不活的监听器比直接失败更危险（一半的连接没人接）。
        let mut acceptors = tokio::task::JoinSet::new();
        for listener in listeners {
            acceptors.spawn(accept_loop(
                listener,
                Arc::clone(&config),
                Arc::clone(&rules),
                traffic.clone(),
            ));
        }

        match acceptors.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(anyhow::anyhow!("accept task failed: {error}")),
            // 没有监听器的情况在 bind 阶段就不可能发生（至少有一个地址）。
            None => Ok(()),
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<Config>,
    rules: Arc<RuleSet>,
    traffic: Option<Arc<Ledger>>,
) -> Result<()> {
    let local = listener
        .local_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "?".to_string());
    debug!(listen = %local, "accepting redirected connections");

    loop {
        let (stream, peer) = listener.accept().await?;
        let config = Arc::clone(&config);
        let rules = Arc::clone(&rules);
        let id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let traffic = traffic.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_redirected(stream, peer, config, rules, id, traffic).await {
                // 这里失败是常态（应用关连接、规则不命中还原不出路径等），
                // 所以只记 debug，避免把日志刷爆。
                debug!(connection_id = id, peer = %peer, error = %error, "redirected connection ended");
            }
        });
    }
}

async fn handle_redirected(
    client: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    rules: Arc<RuleSet>,
    id: u64,
    traffic: Option<Arc<Ledger>>,
) -> Result<()> {
    client.set_nodelay(true)?;

    // 对端端口就是应用原始 socket 的本地端口——pf 保留了它。
    // 地址也一起传：pf 同样保留了源地址，两个一起比对才不会在同端口不同
    // 本地地址的场合认错进程。
    let peer_port = peer.port();
    let peer_ip = peer.ip();

    // libproc 扫描是阻塞的系统调用，扔到 blocking 线程池，别卡住 reactor。
    let owner = tokio::task::spawn_blocking(move || {
        libproc::owner_of_local_endpoint(peer_port, Some(peer_ip))
    })
    .await
    .context("libproc lookup task panicked")?
    .context("libproc lookup failed")?;

    let Some(owner) = owner else {
        bail!(
            "could not attribute port {peer_port} to any process (it may have just closed, \
             or we lack the privileges to inspect it)"
        );
    };

    let Some((destination, port)) = owner.foreign else {
        bail!(
            "process {} has no usable destination address",
            owner.executable.display()
        );
    };

    // 防死循环的最后一道闸。
    //
    // pf 规则里已经用 `to ! 127.0.0.0/8` 把回环目标排除了，所以正常情况下
    // 这里根本不该出现回环目的地。一旦出现，说明规则被改坏或者 pf 行为变了，
    // 此时**绝不能**继续转发——那会让代理连自己，形成指数级的连接风暴。
    // 宁可掐掉这一条连接并大声报警。
    if is_loopback_destination(destination) {
        warn!(
            connection_id = id,
            pid = owner.pid,
            destination = %format_args!("{destination}:{port}"),
            "refusing to relay a connection whose destination is loopback; \
             the pf ruleset should have excluded it, so this likely means the \
             rules were tampered with. Dropping to avoid a redirect loop."
        );
        bail!("loopback destination {destination}:{port} would cause a redirect loop");
    }

    let executable = owner.executable_str();
    let (should_proxy, reason) = rules.explain(&executable);

    info!(
        connection_id = id,
        pid = owner.pid,
        executable = %executable,
        destination = %format_args!("{destination}:{port}"),
        local = ?owner.local,
        tcp_state = owner.state,
        decision = if should_proxy { "proxy" } else { "direct" },
        rule = reason.as_deref().unwrap_or("no rule matched"),
        "attributed connection"
    );

    if !should_proxy {
        return relay_direct(client, destination, port, &config, id).await;
    }

    // Only rule-matched upstream relays get counters. Direct fallback above
    // never registers and cannot leak into the GUI's proxy-only totals.
    let connection = traffic
        .as_ref()
        .map(|ledger| ledger.connect(owner.pid, &executable));
    let result = relay_through_upstream(
        client,
        Target {
            address: TargetAddress::Ip(destination),
            port,
        },
        &config,
        id,
        connection.as_ref().map(|connection| connection.counters()),
    )
    .await;
    if let Err(error) = &result {
        warn!(
            connection_id = id,
            pid = owner.pid,
            executable = %executable,
            destination = %format_args!("{destination}:{port}"),
            error = %format_args!("{error:#}"),
            "proxied connection failed"
        );
    }
    result
}

/// 这个目的地算不算回环。
///
/// 除了 `127.0.0.0/8` 和 `::1`，还必须认出 **IPv4-mapped** 形式
/// （`::ffff:127.0.0.1`）：Rust 的 `Ipv6Addr::is_loopback()` 对它返回 `false`，
/// 但它实际上就是回环地址。漏掉这一种就等于在防死循环的闸门上留了个洞。
fn is_loopback_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
    }
}

/// 直连回退：替不匹配的进程把字节原样送出去。
///
/// 本进程是 root，pf 的 `user != root` 会豁免这个出站连接，所以不会绕回自己。
/// 这条路径**不做任何嗅探**——应用本来就连的这个 IP，原样转发就是最透明的做法。
async fn relay_direct(
    mut client: TcpStream,
    destination: IpAddr,
    port: u16,
    config: &Config,
    id: u64,
) -> Result<()> {
    let mut upstream = timeout(
        Duration::from_millis(config.connect_timeout_ms),
        TcpStream::connect((destination, port)),
    )
    .await
    .with_context(|| format!("timed out connecting directly to {destination}:{port}"))?
    .with_context(|| format!("failed to connect directly to {destination}:{port}"))?;
    upstream.set_nodelay(true)?;

    let (uploaded, downloaded) = copy_bidirectional(&mut client, &mut upstream).await?;
    debug!(
        connection_id = id,
        uploaded, downloaded, "direct connection closed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_native_and_ipv4_mapped_loopback_destinations() {
        for address in ["127.0.0.1", "127.23.45.67", "::1", "::ffff:127.0.0.1"] {
            assert!(
                is_loopback_destination(address.parse().unwrap()),
                "{address}"
            );
        }
        for address in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
            assert!(
                !is_loopback_destination(address.parse().unwrap()),
                "{address}"
            );
        }
    }

    #[tokio::test]
    async fn binds_and_accepts_on_both_loopback_families() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = Config::example();
        config.listen = reservation.local_addr().unwrap();
        drop(reservation);

        let bridge = PfBridge::bind(Arc::new(config), None).await.unwrap();
        assert_eq!(bridge.listeners.len(), 2);
        for listener in &bridge.listeners {
            let address = listener.local_addr().unwrap();
            let client = TcpStream::connect(address).await.unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr().unwrap());
        }
    }

    #[tokio::test]
    async fn ipv6_bind_failure_releases_the_ipv4_listener() {
        let blocker = std::net::TcpListener::bind("[::1]:0").unwrap();
        let mut config = Config::example();
        config.listen.set_port(blocker.local_addr().unwrap().port());
        let listen = config.listen;
        let error = PfBridge::bind(Arc::new(config), None).await.err().unwrap();
        assert!(error.to_string().contains("[::1]"));
        let _rebound = TcpListener::bind(listen).await.unwrap();
    }
}
