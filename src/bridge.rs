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
use tracing::{debug, info, warn};

use crate::{config::Config, sniff::hostname_from_prefix};

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
enum TargetAddress {
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
struct Target {
    address: TargetAddress,
    port: u16,
}

async fn handle_client(mut client: TcpStream, config: Arc<Config>, id: u64) -> Result<()> {
    client.set_nodelay(true)?;
    let original = accept_socks5_request(&mut client).await?;

    // The redirector cannot release the application's first bytes until it sees a
    // successful SOCKS reply. Reply optimistically, then recover the real hostname
    // from TLS SNI or the HTTP Host header before dialing the upstream proxy.
    send_socks5_reply(&mut client, 0x00).await?;

    let (routed, prefix) = match &original.address {
        TargetAddress::Domain(domain) => (
            Target {
                address: TargetAddress::Domain(domain.clone()),
                port: original.port,
            },
            Vec::new(),
        ),
        TargetAddress::Ip(ip) => {
            let (hostname, prefix) = sniff_hostname(&mut client, &config).await?;
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

    let mut upstream = connect_upstream(&config, &routed).await?;
    upstream.set_nodelay(true)?;
    if !prefix.is_empty() {
        upstream.write_all(&prefix).await?;
    }

    let (uploaded, downloaded) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    debug!(
        connection_id = id,
        uploaded, downloaded, "connection closed"
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
            if bytes.len() > u8::MAX as usize {
                bail!("target domain is longer than 255 bytes");
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
    if response[0] != 0x05 {
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
