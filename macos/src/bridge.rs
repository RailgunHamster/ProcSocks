use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout, timeout_at},
};
use tracing::{info, warn};

use crate::{
    config::Config,
    sniff::hostname_from_prefix,
    traffic::{CountedStream, TransferCounters},
};

static CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

pub struct Bridge {
    listener: TcpListener,
    config: Arc<Config>,
}

impl Bridge {
    pub async fn bind(config: Arc<Config>) -> Result<Self> {
        config.validate_bridge()?;
        let listener = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("failed to listen on {}", config.listen))?;
        Ok(Self { listener, config })
    }

    pub async fn run(self) -> Result<()> {
        info!(listen = %self.config.listen, "SOCKS bridge listening");
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let config = Arc::clone(&self.config);
            let id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                if let Err(error) = handle_client(stream, config, id).await {
                    warn!(connection_id = id, peer = %peer, error = %error, "connection failed");
                }
            });
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum TargetAddress {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for TargetAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(formatter, "{ip}"),
            Self::Domain(domain) => formatter.write_str(domain),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub(crate) address: TargetAddress,
    pub(crate) port: u16,
}

async fn handle_client(mut client: TcpStream, config: Arc<Config>, id: u64) -> Result<()> {
    client.set_nodelay(true)?;
    let original = timeout(
        Duration::from_millis(config.connect_timeout_ms),
        accept_socks5_request(&mut client),
    )
    .await
    .context("timed out accepting the client SOCKS5 request")??;

    // The redirector cannot release the application's first bytes until it sees a
    // successful SOCKS reply. Reply optimistically, then recover the real hostname
    // from TLS SNI or the HTTP Host header before dialing the upstream proxy.
    send_socks5_reply(&mut client, 0x00).await?;

    relay_through_upstream(client, original, &config, id, None).await
}

/// 把一条「目标已经确定」的连接经上游 SOCKS5 转发出去。
///
/// 两个平台共用这一段：
///
/// * **Windows**：目标来自 NetFilter 驱动作为 SOCKS5 客户端发来的请求；
/// * **macOS**：目标来自 [`crate::libproc`] 查出来的原始目的地。
///
/// 目标只有 IP 时会先嗅探 TLS SNI / HTTP Host，把域名还原出来再和上游协商——
/// 上游的分流规则通常按域名走，只丢一个 IP 过去会走错路。
pub(crate) async fn relay_through_upstream(
    mut client: TcpStream,
    original: Target,
    config: &Config,
    id: u64,
    counters: Option<&TransferCounters>,
) -> Result<()> {
    let (routed, prefix) = match &original.address {
        TargetAddress::Domain(domain) => (
            Target {
                address: TargetAddress::Domain(domain.clone()),
                port: original.port,
            },
            Vec::new(),
        ),
        TargetAddress::Ip(ip) => {
            let (hostname, prefix) = sniff_hostname(&mut client, config).await?;
            let address = match hostname {
                Some(hostname) => TargetAddress::Domain(hostname),
                None if config.require_hostname => {
                    bail!("could not recover a hostname for {ip}:{}", original.port)
                }
                None => TargetAddress::Ip(*ip),
            };
            (
                Target {
                    address,
                    port: original.port,
                },
                prefix,
            )
        }
    };

    info!(
        connection_id = id,
        original = %format_args!("{}:{}", original.address, original.port),
        routed = %format_args!("{}:{}", routed.address, routed.port),
        "routing connection"
    );

    let upstream = connect_upstream(config, &routed).await.with_context(|| {
        format!(
            "failed to establish SOCKS5 tunnel to {}:{}",
            routed.address, routed.port
        )
    })?;
    upstream.set_nodelay(true)?;
    // Wrap only after negotiation. This also counts the sniffed prefix, which
    // has already been consumed from the client before bidirectional copying.
    let mut upstream = CountedStream::new(upstream, counters.map(|value| &value.uploaded));
    let mut client = CountedStream::new(client, counters.map(|value| &value.downloaded));
    if !prefix.is_empty() {
        upstream.write_all(&prefix).await?;
    }

    let (uploaded, downloaded) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    info!(
        connection_id = id,
        uploaded, downloaded, "proxied connection closed"
    );
    Ok(())
}

async fn accept_socks5_request(stream: &mut TcpStream) -> Result<Target> {
    let version = stream.read_u8().await?;
    if version != 0x05 {
        bail!("unsupported SOCKS version {version}");
    }
    let method_count = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        bail!("client did not offer unauthenticated SOCKS5");
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let request_version = stream.read_u8().await?;
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    let address_type = stream.read_u8().await?;
    if request_version != 0x05 || reserved != 0x00 {
        bail!("invalid SOCKS5 request header");
    }
    if command != 0x01 {
        send_socks5_reply(stream, 0x07).await?;
        bail!("only SOCKS5 CONNECT is supported");
    }

    let address = match address_type {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            TargetAddress::Ip(IpAddr::V4(octets.into()))
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                send_socks5_reply(stream, 0x08).await?;
                bail!("SOCKS5 target domain must not be empty");
            }
            let mut domain = vec![0u8; length];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).context("SOCKS5 domain is not UTF-8")?;
            TargetAddress::Domain(domain)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            TargetAddress::Ip(IpAddr::V6(octets.into()))
        }
        other => {
            send_socks5_reply(stream, 0x08).await?;
            bail!("unsupported SOCKS5 address type {other}")
        }
    };
    let port = stream.read_u16().await?;
    if port == 0 {
        send_socks5_reply(stream, 0x01).await?;
        bail!("SOCKS5 target port must not be zero");
    }
    Ok(Target { address, port })
}

async fn send_socks5_reply(stream: &mut TcpStream, reply: u8) -> Result<()> {
    stream
        .write_all(&[0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn sniff_hostname(
    stream: &mut TcpStream,
    config: &Config,
) -> Result<(Option<String>, Vec<u8>)> {
    let deadline = Instant::now() + Duration::from_millis(config.sniff_timeout_ms);
    let mut prefix = Vec::with_capacity(4096);

    loop {
        if let Some(hostname) = hostname_from_prefix(&prefix) {
            return Ok((Some(hostname), prefix));
        }
        if prefix.len() >= config.max_sniff_bytes {
            return Ok((None, prefix));
        }

        let remaining = config.max_sniff_bytes - prefix.len();
        let mut chunk = vec![0u8; remaining.min(8192)];
        let read = match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(result) => result?,
            Err(_) => return Ok((None, prefix)),
        };
        if read == 0 {
            return Ok((None, prefix));
        }
        prefix.extend_from_slice(&chunk[..read]);
    }
}

async fn connect_upstream(config: &Config, target: &Target) -> Result<TcpStream> {
    timeout(
        Duration::from_millis(config.connect_timeout_ms),
        connect_upstream_inner(config, target),
    )
    .await
    .context("timed out negotiating with the upstream SOCKS5 proxy")?
}

#[cfg(target_os = "macos")]
pub(crate) async fn probe_upstream(config: &Config) -> Result<u128> {
    let started = Instant::now();
    let target = Target {
        address: TargetAddress::Domain("example.com".into()),
        port: 443,
    };
    let stream = connect_upstream(config, &target).await?;
    drop(stream);
    Ok(started.elapsed().as_millis())
}

async fn connect_upstream_inner(config: &Config, target: &Target) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((config.upstream.host.as_str(), config.upstream.port))
        .await
        .context("failed to connect to the upstream SOCKS5 proxy")?;

    let wants_auth = config.upstream.username.is_some();
    if wants_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        bail!("upstream returned an invalid SOCKS version");
    }
    match greeting[1] {
        0x00 => {}
        0x02 if wants_auth => authenticate_upstream(config, &mut stream).await?,
        0xff => bail!("upstream rejected all SOCKS5 authentication methods"),
        method => bail!("upstream selected unsupported SOCKS5 method {method}"),
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match &target.address {
        TargetAddress::Ip(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        TargetAddress::Ip(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        TargetAddress::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                bail!("target domain must contain between 1 and 255 bytes");
            }
            request.push(0x03);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[2] != 0x00 {
        bail!("upstream returned an invalid SOCKS5 response");
    }
    if response[1] != 0x00 {
        bail!(
            "upstream SOCKS5 CONNECT failed with reply 0x{:02x}",
            response[1]
        );
    }
    discard_socks_address(&mut stream, response[3]).await?;
    Ok(stream)
}

async fn authenticate_upstream(config: &Config, stream: &mut TcpStream) -> Result<()> {
    let username = config
        .upstream
        .username
        .as_deref()
        .unwrap_or_default()
        .as_bytes();
    let password = config
        .upstream
        .password
        .as_deref()
        .unwrap_or_default()
        .as_bytes();
    let mut request = Vec::with_capacity(username.len() + password.len() + 3);
    request.extend_from_slice(&[0x01, username.len() as u8]);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        bail!("upstream SOCKS5 username/password authentication failed");
    }
    Ok(())
}

async fn discard_socks_address(stream: &mut TcpStream, address_type: u8) -> Result<()> {
    match address_type {
        0x01 => {
            let mut rest = [0u8; 4 + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut rest = vec![0u8; length + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 16 + 2];
            stream.read_exact(&mut rest).await?;
        }
        other => return Err(anyhow!("upstream returned unknown address type {other}")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn send_request(client: &mut TcpStream, request: &[u8]) -> [u8; 10] {
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        client.write_all(request).await.unwrap();
        let mut response = [0; 10];
        client.read_exact(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn proxy_counters_include_sniffed_payload_and_update_before_connection_closes() {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = Config::example();
            config.upstream.port = listener.local_addr().unwrap().port();
            let request = b"GET / HTTP/1.1\r\nHost: test.example\r\n\r\n";
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            let (release, wait) = tokio::sync::oneshot::channel();
            let mock = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                accept_socks5_request(&mut stream).await.unwrap();
                send_socks5_reply(&mut stream, 0).await.unwrap();
                let mut received = vec![0; request.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, request);
                stream.write_all(response).await.unwrap();
                wait.await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let (mut client, server) = socket_pair().await;
            let counters = Arc::new(TransferCounters::default());
            let measured = Arc::clone(&counters);
            let relay = tokio::spawn(async move {
                relay_through_upstream(
                    server,
                    Target {
                        address: TargetAddress::Ip("192.0.2.1".parse().unwrap()),
                        port: 80,
                    },
                    &config,
                    901,
                    Some(&measured),
                )
                .await
            });
            client.write_all(request).await.unwrap();
            let mut received = vec![0; response.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, response);
            assert_eq!(
                counters.uploaded.load(Ordering::Relaxed),
                request.len() as u64
            );
            assert_eq!(
                counters.downloaded.load(Ordering::Relaxed),
                response.len() as u64
            );
            assert!(!relay.is_finished(), "live counters must not wait for EOF");
            client.shutdown().await.unwrap();
            release.send(()).unwrap();
            mock.await.unwrap();
            relay.await.unwrap().unwrap();
        })
        .await
        .expect("metered relay stalled");
    }

    #[tokio::test]
    async fn a_failed_socks_handshake_does_not_count_sniffed_or_negotiation_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::example();
        config.upstream.port = listener.local_addr().unwrap().port();
        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0xff]).await.unwrap();
        });
        let (mut client, server) = socket_pair().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test.example\r\n\r\n")
            .await
            .unwrap();
        let counters = TransferCounters::default();
        assert!(
            relay_through_upstream(
                server,
                Target {
                    address: TargetAddress::Ip("192.0.2.1".parse().unwrap()),
                    port: 80
                },
                &config,
                902,
                Some(&counters)
            )
            .await
            .is_err()
        );
        assert_eq!(counters.uploaded.load(Ordering::Relaxed), 0);
        assert_eq!(counters.downloaded.load(Ordering::Relaxed), 0);
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn fragmented_http_routes_to_the_complete_hostname_and_preserves_all_bytes() {
        timeout(Duration::from_secs(5), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = Config::example();
            config.upstream.port = upstream.local_addr().unwrap().port();
            let request = b"GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n";
            let split = b"GET / HTTP/1.1\r\nHost: api".len();

            let mock = tokio::spawn(async move {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let target = accept_socks5_request(&mut stream).await.unwrap();
                assert!(matches!(target.address, TargetAddress::Domain(ref host) if host == "api.example.com"));
                assert_eq!(target.port, 80);
                send_socks5_reply(&mut stream, 0).await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, request);
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let (mut client, server) = socket_pair().await;
            let bridge = tokio::spawn(handle_client(server, Arc::new(config), 1));
            let reply = send_request(&mut client, &[5, 1, 0, 1, 192, 0, 2, 1, 0, 80]).await;
            assert_eq!(reply[1], 0);
            client.write_all(&request[..split]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            client.write_all(&request[split..]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.ends_with(b"\r\n\r\nOK"));
            mock.await.unwrap();
            bridge.await.unwrap().unwrap();
        }).await.expect("bridge relay stalled");
    }

    #[tokio::test]
    async fn idle_downstream_handshake_times_out() {
        let (_client, server) = socket_pair().await;
        let config = Config {
            connect_timeout_ms: 30,
            ..Config::example()
        };
        let error = timeout(
            Duration::from_secs(2),
            handle_client(server, Arc::new(config), 2),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("timed out accepting"));
    }

    #[tokio::test]
    async fn malformed_downstream_targets_receive_a_failure_reply() {
        for request in [
            vec![5, 2, 0, 1],                     // BIND is unsupported.
            vec![5, 1, 0, 3, 0],                  // Empty domain.
            vec![5, 1, 0, 1, 192, 0, 2, 1, 0, 0], // Port zero.
        ] {
            let (mut client, mut server) = socket_pair().await;
            let task = tokio::spawn(async move { accept_socks5_request(&mut server).await });
            let reply = timeout(Duration::from_secs(2), send_request(&mut client, &request))
                .await
                .unwrap();
            assert_ne!(reply[1], 0);
            assert!(task.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn negotiates_username_password_and_an_ipv6_target() {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = Config::example();
            config.upstream.port = listener.local_addr().unwrap().port();
            config.upstream.username = Some("user".into());
            config.upstream.password = Some("password".into());
            let ip: IpAddr = "2001:db8::1".parse().unwrap();
            let mock = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 4];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 2, 0, 2]);
                stream.write_all(&[5, 2]).await.unwrap();
                let mut credentials = [0; 15];
                stream.read_exact(&mut credentials).await.unwrap();
                assert_eq!(&credentials, b"\x01\x04user\x08password");
                stream.write_all(&[1, 0]).await.unwrap();
                let mut request = [0; 22];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..4], &[5, 1, 0, 4]);
                let IpAddr::V6(ip) = ip else { unreachable!() };
                assert_eq!(&request[4..20], &ip.octets());
                assert_eq!(&request[20..], &443u16.to_be_bytes());
                send_socks5_reply(&mut stream, 0).await.unwrap();
                stream.write_all(b"ready").await.unwrap();
            });
            let mut stream = connect_upstream(
                &config,
                &Target {
                    address: TargetAddress::Ip(ip),
                    port: 443,
                },
            )
            .await
            .unwrap();
            let mut payload = [0; 5];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ready");
            mock.await.unwrap();
        })
        .await
        .expect("authenticated SOCKS negotiation stalled");
    }

    #[tokio::test]
    async fn rejects_an_upstream_reply_with_a_nonzero_reserved_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::example();
        config.upstream.port = listener.local_addr().unwrap().port();
        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accept_socks5_request(&mut stream).await.unwrap();
            stream
                .write_all(&[5, 0, 1, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let target = Target {
            address: TargetAddress::Domain("api.example.com".into()),
            port: 443,
        };
        let error = connect_upstream(&config, &target).await.unwrap_err();
        assert!(error.to_string().contains("invalid SOCKS5 response"));
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn upstream_negotiation_is_bounded_by_the_connection_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::example();
        config.upstream.port = listener.local_addr().unwrap().port();
        config.connect_timeout_ms = 30;
        let target = Target {
            address: TargetAddress::Domain("api.example.com".into()),
            port: 443,
        };
        let error = timeout(Duration::from_secs(2), connect_upstream(&config, &target))
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("timed out negotiating"));
    }
}
