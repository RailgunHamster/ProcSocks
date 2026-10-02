//! SOCKS5 UDP ASSOCIATE client and loopback relay, shared by both platforms.
//! Association lifetime is tied to its TCP control connection (RFC 1928).
use crate::{
    bridge::{Target, TargetAddress},
    config::Config,
};
use anyhow::{Context, Result, bail};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
    time::{Instant, timeout},
};

static ASSOCIATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(256);

pub(crate) const MAX_PACKET: usize = 65_507;
pub(crate) const IDLE: Duration = Duration::from_secs(120);

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn encode(target: &Target, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    append_target(&mut packet, target)?;
    if packet.len() + payload.len() > MAX_PACKET {
        bail!("UDP payload exceeds the SOCKS relay datagram limit");
    }
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn append_target(packet: &mut Vec<u8>, target: &Target) -> Result<()> {
    match &target.address {
        TargetAddress::Ip(IpAddr::V4(ip)) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        TargetAddress::Ip(IpAddr::V6(ip)) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
        TargetAddress::Domain(domain) => {
            if domain.is_empty() || domain.len() > 255 {
                bail!("invalid SOCKS UDP domain length");
            }
            packet.extend_from_slice(&[3, domain.len() as u8]);
            packet.extend_from_slice(domain.as_bytes());
        }
    }
    packet.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

pub(crate) fn decode(packet: &[u8]) -> Result<(Target, &[u8])> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        bail!("invalid or fragmented SOCKS UDP datagram");
    }
    let (address, end) = match packet[3] {
        1 if packet.len() >= 10 => (
            TargetAddress::Ip(IpAddr::V4(<[u8; 4]>::try_from(&packet[4..8])?.into())),
            8,
        ),
        4 if packet.len() >= 22 => (
            TargetAddress::Ip(IpAddr::V6(<[u8; 16]>::try_from(&packet[4..20])?.into())),
            20,
        ),
        3 if packet.len() >= 5 && packet[4] > 0 && packet.len() >= 7 + packet[4] as usize => {
            let end = 5 + packet[4] as usize;
            (
                TargetAddress::Domain(std::str::from_utf8(&packet[5..end])?.to_owned()),
                end,
            )
        }
        _ => bail!("truncated or unknown SOCKS UDP address"),
    };
    let port = u16::from_be_bytes(packet[end..end + 2].try_into()?);
    if port == 0 {
        bail!("UDP destination port must not be zero");
    }
    Ok((Target { address, port }, &packet[end + 2..]))
}

async fn read_target(stream: &mut TcpStream, atyp: u8) -> Result<Target> {
    let address = match atyp {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            TargetAddress::Ip(IpAddr::V4(ip.into()))
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            TargetAddress::Ip(IpAddr::V6(ip.into()))
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                bail!("empty relay domain");
            }
            let mut domain = vec![0; len];
            stream.read_exact(&mut domain).await?;
            TargetAddress::Domain(String::from_utf8(domain)?)
        }
        _ => bail!("invalid UDP relay address type"),
    };
    Ok(Target {
        address,
        port: stream.read_u16().await?,
    })
}

pub(crate) struct Association {
    pub control: TcpStream,
    pub socket: UdpSocket,
}

impl Association {
    pub async fn connect(config: &Config) -> Result<Self> {
        timeout(
            Duration::from_millis(config.connect_timeout_ms),
            Self::connect_inner(config),
        )
        .await
        .context("SOCKS5 UDP ASSOCIATE timed out")?
    }
    async fn connect_inner(config: &Config) -> Result<Self> {
        let mut control =
            TcpStream::connect((config.upstream.host.as_str(), config.upstream.port)).await?;
        let peer = control.peer_addr()?;
        let authenticated = config.upstream.username.is_some();
        control
            .write_all(if authenticated {
                &[5, 2, 0, 2]
            } else {
                &[5, 1, 0]
            })
            .await?;
        let mut method = [0; 2];
        control.read_exact(&mut method).await?;
        match method {
            [5, 0] => {}
            [5, 2] if authenticated => {
                crate::bridge::authenticate_upstream(config, &mut control).await?
            }
            _ => bail!("upstream rejected SOCKS5 UDP authentication"),
        }
        // Address unknown until the relay chooses a family: RFC allows 0.0.0.0:0.
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut header = [0; 4];
        control.read_exact(&mut header).await?;
        if header[0] != 5 || header[2] != 0 {
            bail!("invalid UDP ASSOCIATE response");
        }
        if header[1] != 0 {
            bail!(
                "upstream does not accept UDP ASSOCIATE (reply 0x{:02x}); selected UDP will not be sent directly",
                header[1]
            );
        }
        let relay = read_target(&mut control, header[3]).await?;
        if relay.port == 0 {
            bail!("upstream returned UDP relay port zero");
        }
        let relay = match relay.address {
            TargetAddress::Ip(ip) => {
                SocketAddr::new(if ip.is_unspecified() { peer.ip() } else { ip }, relay.port)
            }
            TargetAddress::Domain(domain) => lookup_host((domain.as_str(), relay.port))
                .await?
                .next()
                .context("UDP relay domain has no addresses")?,
        };
        let bind = if relay.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        // Connected UDP rejects datagrams from other sources, including local spoofers.
        socket.connect(relay).await?;
        Ok(Self { control, socket })
    }
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub async fn send(&self, target: &Target, payload: &[u8]) -> Result<()> {
        let packet = encode(target, payload)?;
        let sent = self.socket.send(&packet).await?;
        if sent != packet.len() {
            bail!("partial UDP send");
        }
        Ok(())
    }
}

/// Each TCP client owns a separate ephemeral UDP socket. Never share its source
/// port or associations with another local client.
pub(crate) async fn serve(
    mut control: TcpStream,
    requested: Target,
    config: Arc<Config>,
) -> Result<()> {
    let _permit = match ASSOCIATIONS.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            crate::bridge::send_socks5_reply(&mut control, 1).await?;
            bail!("UDP association limit reached");
        }
    };
    if !config.redirect_udp {
        crate::bridge::send_socks5_reply(&mut control, 7).await?;
        bail!("UDP disabled");
    }
    let peer = control.peer_addr()?;
    let mut peer = SocketAddr::new(normalize(peer.ip()), requested.port);
    if let TargetAddress::Ip(ip) = requested.address {
        if !ip.is_unspecified() && normalize(ip) != peer.ip() {
            bail!("UDP association source does not match TCP client");
        }
    } else {
        bail!("UDP association source must be an IP address");
    }
    let listener =
        UdpSocket::bind(SocketAddr::new(normalize(control.local_addr()?.ip()), 0)).await?;
    let upstream = match Association::connect(&config).await {
        Ok(upstream) => upstream,
        Err(error) => {
            crate::bridge::send_socks5_reply(&mut control, 1).await?;
            return Err(error);
        }
    };
    let mut reply = vec![5, 0, 0];
    let addr = listener.local_addr()?;
    append_target(
        &mut reply,
        &Target {
            address: TargetAddress::Ip(addr.ip()),
            port: addr.port(),
        },
    )?;
    control.write_all(&reply).await?;
    let (mut remote_control, mut remote_socket) = (Some(upstream.control), Some(upstream.socket));
    let mut client_packet = vec![0; MAX_PACKET + 1];
    let mut remote_packet = vec![0; MAX_PACKET + 1];
    let mut closed = [0; 1];
    let mut upstream_closed = [0; 1];
    let idle = tokio::time::sleep(IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = control.read(&mut closed) => return Ok(()),
            // The Windows adapter ties association lifetime to the application
            // socket. Closing an idle control connection would break its still
            // live UDP socket. Both variants remain bounded by ASSOCIATIONS.
            _ = async { if cfg!(windows) { std::future::pending::<()>().await; } else { idle.as_mut().await; } } => return Ok(()),
            _ = async {
                if let Some(control) = &mut remote_control { let _ = control.read(&mut upstream_closed).await; }
                else { std::future::pending::<()>().await; }
            } => { remote_control = None; remote_socket = None; },
            received = listener.recv_from(&mut client_packet) => {
                let (len,source) = received?;
                let source = SocketAddr::new(normalize(source.ip()),source.port());
                if source.ip()!=peer.ip() || (peer.port()!=0 && source.port()!=peer.port()) {continue;}
                if len>MAX_PACKET || decode(&client_packet[..len]).is_err() {continue;}
                if peer.port()==0 {peer.set_port(source.port());}
                if remote_socket.is_none() {
                    match Association::connect(&config).await {
                        Ok(association) => { remote_control=Some(association.control); remote_socket=Some(association.socket); },
                        Err(error) => { tracing::debug!(%error,"UDP upstream reconnect failed; dropping selected datagram"); continue; }
                    }
                }
                let socket = remote_socket.as_ref().unwrap();
                match socket.send(&client_packet[..len]).await {
                    Ok(sent) if sent==len => idle.as_mut().reset(Instant::now()+IDLE),
                    _ => { remote_control=None; remote_socket=None; },
                }
            }
            received = async {
                if let Some(socket) = &remote_socket { socket.recv(&mut remote_packet).await }
                else { std::future::pending::<std::io::Result<usize>>().await }
            } => {
                let len=match received { Ok(len)=>len, Err(_)=>{remote_control=None;remote_socket=None;continue;} };
                if peer.port()==0 || len>MAX_PACKET || decode(&remote_packet[..len]).is_err() {continue;}
                listener.send_to(&remote_packet[..len],peer).await?;
                idle.as_mut().reset(Instant::now()+IDLE);
            }
        }
    }
}

/// An actual DNS datagram roundtrip, not just a successful ASSOCIATE reply.
#[cfg(target_os = "macos")]
pub(crate) async fn probe(config: &Config) -> Result<()> {
    let mut association = Association::connect(config).await?;
    let id = (std::process::id() as u16).wrapping_add(0x5a31);
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let target = Target {
        address: TargetAddress::Ip("1.1.1.1".parse()?),
        port: 53,
    };
    association.send(&target, &query).await?;
    let mut packet = vec![0; MAX_PACKET + 1];
    let mut eof = [0; 1];
    timeout(Duration::from_millis(config.connect_timeout_ms),async {
        loop {tokio::select! {
            _=association.control.read(&mut eof)=>bail!("UDP upstream control connection closed"),
            len=association.socket.recv(&mut packet)=>{
                let len=len?;let (source,payload)=decode(&packet[..len])?;
                if source.port==53 && matches!(source.address,TargetAddress::Ip(ip) if ip=="1.1.1.1".parse::<IpAddr>()?) && payload.len()>=12 && payload[..2]==id.to_be_bytes() && payload[2]&0x80!=0 {
                    if payload[3]&15!=0{bail!("UDP DNS resolver returned an error");}
                    return Ok(());
                }
            }
        }}
    }).await.context("UDP relay accepted ASSOCIATE but the DNS roundtrip timed out")?
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_roundtrip_and_truncation() {
        for address in [
            TargetAddress::Ip("192.0.2.1".parse().unwrap()),
            TargetAddress::Ip("2001:db8::1".parse().unwrap()),
            TargetAddress::Domain("example.com".into()),
        ] {
            let target = Target { address, port: 443 };
            let packet = encode(&target, b"hello").unwrap();
            let (decoded, data) = decode(&packet).unwrap();
            assert_eq!(decoded.port, 443);
            assert_eq!(decoded.address.to_string(), target.address.to_string());
            assert_eq!(data, b"hello");
            for len in 0..packet.len() - 5 {
                assert!(decode(&packet[..len]).is_err());
            }
            let mut fragmented = packet.clone();
            fragmented[2] = 1;
            assert!(decode(&fragmented).is_err());
        }
        assert!(
            encode(
                &Target {
                    address: TargetAddress::Ip("1.1.1.1".parse().unwrap()),
                    port: 53
                },
                &vec![0; MAX_PACKET]
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn downstream_udp_is_source_pinned_and_closes_with_its_tcp_client() {
        timeout(Duration::from_secs(5), async {
            let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mock_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = mock_udp.local_addr().unwrap();
            let mut config = Config::example();
            config.upstream.port = mock_listener.local_addr().unwrap().port();
            let mock = tokio::spawn(async move {
                let (mut control, _) = mock_listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                control.read_exact(&mut greeting).await.unwrap();
                control.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                control.read_exact(&mut request).await.unwrap();
                let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                reply.extend_from_slice(&relay_addr.port().to_be_bytes());
                control.write_all(&reply).await.unwrap();
                let mut packet = vec![0; MAX_PACKET];
                for expected in [b"one".as_slice(), b"two".as_slice()] {
                    let (len, peer) = mock_udp.recv_from(&mut packet).await.unwrap();
                    assert_eq!(decode(&packet[..len]).unwrap().1, expected);
                    mock_udp.send_to(&packet[..len], peer).await.unwrap();
                }
                let mut eof = [0; 1];
                assert_eq!(control.read(&mut eof).await.unwrap(), 0);
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut control = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            let bridge = tokio::spawn(serve(
                server,
                Target {
                    address: TargetAddress::Ip("0.0.0.0".parse().unwrap()),
                    port: 0,
                },
                Arc::new(config),
            ));
            let mut header = [0; 4];
            control.read_exact(&mut header).await.unwrap();
            assert_eq!(header, [5, 0, 0, 1]);
            let advertised = read_target(&mut control, 1).await.unwrap();
            let TargetAddress::Ip(ip) = advertised.address else {
                panic!("expected relay IP")
            };
            let relay = SocketAddr::new(ip, advertised.port);
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = Target {
                address: TargetAddress::Ip("192.0.2.1".parse().unwrap()),
                port: 443,
            };
            let mut packet = vec![0; MAX_PACKET];
            client
                .send_to(&encode(&target, b"one").unwrap(), relay)
                .await
                .unwrap();
            let (len, _) = client.recv_from(&mut packet).await.unwrap();
            assert_eq!(decode(&packet[..len]).unwrap().1, b"one");
            attacker
                .send_to(&encode(&target, b"intruder").unwrap(), relay)
                .await
                .unwrap();
            let mut fragment = encode(&target, b"fragment").unwrap();
            fragment[2] = 1;
            client.send_to(&fragment, relay).await.unwrap();
            client
                .send_to(&encode(&target, b"two").unwrap(), relay)
                .await
                .unwrap();
            let (len, _) = client.recv_from(&mut packet).await.unwrap();
            assert_eq!(decode(&packet[..len]).unwrap().1, b"two");
            assert!(
                timeout(Duration::from_millis(50), attacker.recv(&mut packet))
                    .await
                    .is_err()
            );
            control.shutdown().await.unwrap();
            bridge.await.unwrap().unwrap();
            mock.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn real_udp_association_preserves_two_targets_and_control_lifetime() {
        timeout(Duration::from_secs(5), async {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay.local_addr().unwrap();
            let mut config = Config::example();
            config.upstream.port = tcp.local_addr().unwrap().port();
            let mock = tokio::spawn(async move {
                let (mut control, _) = tcp.accept().await.unwrap();
                let mut greeting = [0; 3];
                control.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                control.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                control.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
                let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0];
                reply.extend_from_slice(&relay_addr.port().to_be_bytes());
                control.write_all(&reply).await.unwrap();
                let mut packet = vec![0; MAX_PACKET];
                for expected in ["192.0.2.1", "2001:db8::1"] {
                    let (len, peer) = relay.recv_from(&mut packet).await.unwrap();
                    let (target, payload) = decode(&packet[..len]).unwrap();
                    assert_eq!(target.address.to_string(), expected);
                    assert_eq!(payload, b"probe");
                    relay.send_to(&packet[..len], peer).await.unwrap();
                }
            });
            let mut association = Association::connect(&config).await.unwrap();
            let mut packet = vec![0; MAX_PACKET];
            for ip in ["192.0.2.1", "2001:db8::1"] {
                association
                    .send(
                        &Target {
                            address: TargetAddress::Ip(ip.parse().unwrap()),
                            port: 443,
                        },
                        b"probe",
                    )
                    .await
                    .unwrap();
                let len = association.socket.recv(&mut packet).await.unwrap();
                assert_eq!(decode(&packet[..len]).unwrap().1, b"probe");
            }
            mock.await.unwrap();
            let mut eof = [0; 1];
            assert_eq!(association.control.read(&mut eof).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }
}
