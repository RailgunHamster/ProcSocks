//! UDP-only packet transport. PF routes non-root UDP here without rewriting its
//! destination. No default route, DNS setting or NetworkExtension entitlement is
//! installed. Closing the control socket destroys the interface.
use crate::{
    bridge::{Target, TargetAddress},
    config::Config,
    libproc,
    rules::RuleSet,
    traffic::Ledger,
    udp::{self, Association},
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, unix::AsyncFd},
    sync::mpsc,
    time::Instant,
};
use tracing::{debug, info, warn};

const MAX_SESSIONS: usize = 1024;
const QUEUE: usize = 64;

pub(crate) struct Tunnel {
    fd: AsyncFd<OwnedFd>,
    pub name: String,
}
impl Tunnel {
    pub fn open() -> Result<Self> {
        // All layouts/constants are provided by libc's Apple target, matching
        // <sys/kern_control.h> and <net/if_utun.h> in the active SDK.
        let raw =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut ctl: libc::ctl_info = unsafe { std::mem::zeroed() };
        for (out, byte) in ctl.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
            *out = *byte as libc::c_char;
        }
        if unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut ctl) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: ctl.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        if unsafe {
            libc::connect(
                raw,
                (&addr as *const libc::sockaddr_ctl).cast(),
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut name = [0u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let name =
            std::str::from_utf8(&name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())])?
                .to_owned();
        if !name
            .strip_prefix("utun")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        {
            bail!("invalid utun interface name");
        }
        let output = std::process::Command::new("/sbin/ifconfig")
            .args([
                &name,
                "inet",
                "198.18.0.1",
                "198.18.0.2",
                "netmask",
                "255.255.255.252",
                "mtu",
                "65535",
                "up",
            ])
            .output()?;
        if !output.status.success() {
            bail!(
                "could not bring up {name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let output = std::process::Command::new("/sbin/ifconfig")
            .args([&name, "inet6", "fd70:726f:6373:6f63::1", "prefixlen", "128"])
            .output()?;
        if !output.status.success() {
            bail!(
                "could not configure UDP IPv6 transport: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            name,
        })
    }
    pub async fn recv(&self, packet: &mut [u8]) -> Result<usize> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| {
                let len = unsafe {
                    libc::recv(fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len(), 0)
                };
                if len < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(len as usize)
                }
            }) {
                Ok(result) => return Ok(result?),
                Err(_) => continue,
            }
        }
    }
    async fn send(&self, packet: &[u8]) -> Result<()> {
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| {
                let len =
                    unsafe { libc::send(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len(), 0) };
                if len < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(len as usize)
                }
            }) {
                Ok(result) => {
                    if result? != packet.len() {
                        bail!("partial utun datagram write");
                    }
                    return Ok(());
                }
                Err(_) => continue,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    source: SocketAddr,
    destination: SocketAddr,
}
#[derive(Debug)]
struct Datagram {
    flow: Flow,
    payload: Vec<u8>,
    _budget: Option<tokio::sync::OwnedSemaphorePermit>,
}

// IP fragments cannot be forwarded independently as UDP. Reassembly is bounded
// separately from relay sessions, expires after 5 seconds, rejects overlaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragmentKey {
    source: IpAddr,
    destination: IpAddr,
    id: u32,
}
#[derive(Default)]
struct Fragments {
    entries: HashMap<FragmentKey, Fragment>,
}
struct Fragment {
    parts: Vec<(usize, Vec<u8>)>,
    end: Option<usize>,
    seen: Instant,
}
impl Fragments {
    fn assemble(
        &mut self,
        key: FragmentKey,
        offset: usize,
        more: bool,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        self.entries
            .retain(|_, entry| entry.seen.elapsed() < Duration::from_secs(5));
        if data.is_empty() || offset + data.len() > 65535 || (more && !data.len().is_multiple_of(8))
        {
            self.entries.remove(&key);
            return None;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= 128 {
            return None;
        }
        let entry = self.entries.entry(key).or_insert_with(|| Fragment {
            parts: Vec::new(),
            end: None,
            seen: Instant::now(),
        });
        if entry
            .parts
            .iter()
            .any(|(start, part)| offset < *start + part.len() && *start < offset + data.len())
            || entry.parts.len() >= 128
        {
            self.entries.remove(&key);
            return None;
        }
        if !more {
            let end = offset + data.len();
            if entry.end.is_some_and(|old| old != end) {
                self.entries.remove(&key);
                return None;
            }
            entry.end = Some(end);
        }
        entry.parts.push((offset, data.to_vec()));
        entry.parts.sort_unstable_by_key(|part| part.0);
        let end = entry.end?;
        let mut cursor = 0;
        for (start, part) in &entry.parts {
            if *start != cursor {
                return None;
            }
            cursor += part.len();
        }
        if cursor != end {
            return None;
        }
        let entry = self.entries.remove(&key)?;
        Some(entry.parts.into_iter().flat_map(|part| part.1).collect())
    }
    fn decode(&mut self, packet: &[u8]) -> Option<Datagram> {
        if packet.len() < 4 {
            return None;
        }
        let family = u32::from_be_bytes(packet[..4].try_into().ok()?);
        let ip = &packet[4..];
        let (source, destination, data) = match family as i32 {
            libc::AF_INET if ip.len() >= 20 && ip[0] >> 4 == 4 && ip[9] == 17 => {
                let header = (ip[0] as usize & 15) * 4;
                let len = u16::from_be_bytes(ip[2..4].try_into().ok()?) as usize;
                if header < 20 || len > ip.len() || len < header {
                    return None;
                }
                let source = IpAddr::V4(<[u8; 4]>::try_from(&ip[12..16]).ok()?.into());
                let destination = IpAddr::V4(<[u8; 4]>::try_from(&ip[16..20]).ok()?.into());
                let frag = u16::from_be_bytes(ip[6..8].try_into().ok()?);
                let data = if frag & 0x3fff != 0 {
                    self.assemble(
                        FragmentKey {
                            source,
                            destination,
                            id: u16::from_be_bytes(ip[4..6].try_into().ok()?) as u32,
                        },
                        ((frag & 0x1fff) as usize) * 8,
                        frag & 0x2000 != 0,
                        &ip[header..len],
                    )?
                } else {
                    ip[header..len].to_vec()
                };
                (source, destination, data)
            }
            libc::AF_INET6 if ip.len() >= 40 && ip[0] >> 4 == 6 => {
                let len = 40 + u16::from_be_bytes(ip[4..6].try_into().ok()?) as usize;
                if len > ip.len() {
                    return None;
                }
                let source = IpAddr::V6(<[u8; 16]>::try_from(&ip[8..24]).ok()?.into());
                let destination = IpAddr::V6(<[u8; 16]>::try_from(&ip[24..40]).ok()?.into());
                let mut next = ip[6];
                let mut start = 40;
                for _ in 0..8 {
                    match next {
                        17 => break,
                        0 | 43 | 60 => {
                            if start + 2 > len {
                                return None;
                            }
                            let end = start + (ip[start + 1] as usize + 1) * 8;
                            if end > len {
                                return None;
                            }
                            next = ip[start];
                            start = end;
                        }
                        44 => {
                            if start + 8 > len || ip[start] != 17 {
                                return None;
                            }
                            let bits =
                                u16::from_be_bytes(ip[start + 2..start + 4].try_into().ok()?);
                            let key = FragmentKey {
                                source,
                                destination,
                                id: u32::from_be_bytes(ip[start + 4..start + 8].try_into().ok()?),
                            };
                            let data = self.assemble(
                                key,
                                (bits & 0xfff8) as usize,
                                bits & 1 != 0,
                                &ip[start + 8..len],
                            )?;
                            return decode_udp(source, destination, &data);
                        }
                        _ => return None,
                    }
                }
                if next != 17 || start > len {
                    return None;
                }
                (source, destination, ip[start..len].to_vec())
            }
            _ => return None,
        };
        decode_udp(source, destination, &data)
    }
}
fn decode_udp(source: IpAddr, destination: IpAddr, data: &[u8]) -> Option<Datagram> {
    if data.len() < 8 {
        return None;
    }
    let len = u16::from_be_bytes(data[4..6].try_into().ok()?) as usize;
    if len < 8 || len != data.len() {
        return None;
    }
    let source = SocketAddr::new(source, u16::from_be_bytes(data[..2].try_into().ok()?));
    let destination = SocketAddr::new(destination, u16::from_be_bytes(data[2..4].try_into().ok()?));
    if source.port() == 0 || destination.port() == 0 {
        return None;
    }
    Some(Datagram {
        flow: Flow {
            source,
            destination,
        },
        payload: data[8..].to_vec(),
        _budget: None,
    })
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += ((pair[0] as u32) << 8) + pair.get(1).copied().unwrap_or(0) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn reply_packet(flow: Flow, payload: &[u8]) -> Result<Vec<u8>> {
    let udp_len = 8 + payload.len();
    if udp_len > 65535 {
        bail!("UDP reply too large");
    }
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&flow.destination.port().to_be_bytes());
    udp.extend_from_slice(&flow.source.port().to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    let mut packet = Vec::new();
    match (flow.destination.ip(), flow.source.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            if udp_len + 20 > 65535 {
                bail!("IPv4 UDP reply too large");
            }
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
            packet.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
            let mut ip = vec![0x45, 0];
            ip.extend_from_slice(&((udp_len + 20) as u16).to_be_bytes());
            ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
            ip.extend_from_slice(&source.octets());
            ip.extend_from_slice(&destination.octets());
            let sum = checksum(&ip);
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
            packet.extend_from_slice(&ip);
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
            packet.extend_from_slice(&(libc::AF_INET6 as u32).to_be_bytes());
            packet.extend_from_slice(&[0x60, 0, 0, 0]);
            packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
            packet.extend_from_slice(&[17, 64]);
            packet.extend_from_slice(&source.octets());
            packet.extend_from_slice(&destination.octets());
        }
        _ => bail!("UDP flow address families differ"),
    }
    pseudo.extend_from_slice(&udp);
    let sum = checksum(&pseudo);
    udp[6..8].copy_from_slice(&(if sum == 0 { 65535 } else { sum }).to_be_bytes());
    packet.extend_from_slice(&udp);
    Ok(packet)
}

pub(crate) struct UdpBridge {
    pub tunnel: Arc<Tunnel>,
    config: Arc<Config>,
    rules: Arc<RuleSet>,
    ledger: Option<Arc<Ledger>>,
}
impl UdpBridge {
    pub async fn bind(config: Arc<Config>, ledger: Option<Arc<Ledger>>) -> Result<Self> {
        // Fail before installing any PF rule if the upstream rejects UDP.
        let association = Association::connect(&config)
            .await
            .context("UDP support is enabled but the upstream proxy rejected it")?;
        drop(association);
        Ok(Self {
            tunnel: Arc::new(Tunnel::open().context("failed to create the UDP utun interface")?),
            rules: Arc::new(RuleSet::compile(
                &config.process_patterns,
                &config.bypass_patterns,
            )?),
            config,
            ledger,
        })
    }
    pub async fn run(self) -> Result<()> {
        info!(interface=%self.tunnel.name,"transparent UDP relay is up");
        let mut sessions: HashMap<SocketAddr, mpsc::Sender<Datagram>> = HashMap::new();
        let mut tasks = tokio::task::JoinSet::new();
        let budget = Arc::new(tokio::sync::Semaphore::new(16 * 1024 * 1024));
        let mut fragments = Fragments::default();
        let mut packet = vec![0; 65575];
        loop {
            tokio::select! {
                Some(result)=tasks.join_next()=>{if let Err(error)=result{warn!(%error,"UDP session task failed");}}
                result=self.tunnel.recv(&mut packet)=>{
                    let len=result?;
                    if len==0{bail!("UDP interface closed");}
                    let Some(mut datagram)=fragments.decode(&packet[..len]) else{continue;};
                    let Ok(permit) = Arc::clone(&budget).try_acquire_many_owned(datagram.payload.len().max(1) as u32) else { continue; };
                    datagram._budget = Some(permit);
                    let flow=datagram.flow;
                    if flow.destination.ip().is_loopback()||flow.destination.ip().is_multicast()||flow.destination.ip().is_unspecified(){continue;}
                    if let Some(sender)=sessions.get(&flow.source) && !sender.is_closed() {let _=sender.try_send(datagram);continue;}
                    sessions.retain(|_,sender|!sender.is_closed());
                    if sessions.len()>=MAX_SESSIONS {debug!("UDP session limit reached; dropping datagram");continue;}
                    let config=Arc::clone(&self.config);let tunnel=Arc::clone(&self.tunnel);let rules=Arc::clone(&self.rules);let ledger=self.ledger.clone();
                    let (sender,receiver)=mpsc::channel(QUEUE);sender.try_send(datagram)?;sessions.insert(flow.source,sender);
                    tasks.spawn(async move {if let Err(error)=relay(flow.source,receiver,tunnel,config,rules,ledger).await {debug!(?flow,error=%format_args!("{error:#}"),"UDP session ended");}});
                }
            }
        }
    }
}
// One association per application UDP socket, preserving NAT/source-port
// behavior across multiple destinations (including direct STUN/P2P traffic).
async fn relay(
    source: SocketAddr,
    mut receiver: mpsc::Receiver<Datagram>,
    tunnel: Arc<Tunnel>,
    config: Arc<Config>,
    rules: Arc<RuleSet>,
    ledger: Option<Arc<Ledger>>,
) -> Result<()> {
    let first = receiver
        .recv()
        .await
        .context("UDP session closed before its first packet")?;
    let initial_destination = first.flow.destination;
    let owner = tokio::task::spawn_blocking(move || {
        libproc::owner_of_udp_endpoint(source, initial_destination)
    })
    .await??
    .context("UDP socket owner missing or ambiguous; refusing to guess")?;
    let (proxy, reason) = rules.explain(&owner.executable_str());
    info!(pid=owner.pid, executable=%owner.executable.display(), %source,
          destination=%initial_destination, decision=if proxy { "proxy" } else { "direct" },
          rule=?reason, "attributed UDP session");
    let counted = if proxy {
        ledger
            .as_ref()
            .map(|ledger| ledger.connect(owner.pid, &owner.executable_str()))
    } else {
        None
    };
    let association = if proxy {
        Some(Association::connect(&config).await?)
    } else {
        None
    };
    let (mut control, upstream_socket) = match association {
        Some(Association { control, socket }) => (Some(control), Some(socket)),
        None => (None, None),
    };
    let mut allowed: HashMap<SocketAddr, Instant> = HashMap::new();
    let mut pending = Some(first);
    let mut packet = vec![0; udp::MAX_PACKET + 1];
    let mut eof = [0; 1];
    let mut last_activity = Instant::now();
    let mut maintenance = tokio::time::interval(Duration::from_secs(2));
    loop {
        let event = if let Some(datagram) = pending.take() {
            (true, Some(datagram))
        } else {
            tokio::time::timeout_at(last_activity + udp::IDLE, async {
                tokio::select! {
                    _ = maintenance.tick() => Ok((false, None)),
                    datagram = receiver.recv() => Ok::<_,anyhow::Error>((true, datagram)),
                    received = async {
                        if let Some(socket) = &upstream_socket {
                            Ok::<_,std::io::Error>((socket.recv(&mut packet).await?, None))
                        } else {
                            std::future::pending::<std::io::Result<(usize, Option<SocketAddr>)>>().await
                        }
                    } => {
                        let (len, peer) = received?;
                        if len > udp::MAX_PACKET { return Ok((false, None)); }
                        let (destination, payload) = if let Some(peer) = peer { (peer, packet[..len].to_vec()) } else {
                            let (target, payload) = match udp::decode(&packet[..len]) { Ok(packet) => packet, Err(_) => return Ok((false, None)) };
                            let TargetAddress::Ip(ip) = target.address else { return Ok((false, None)); };
                            (SocketAddr::new(ip, target.port), payload.to_vec())
                        };
                        let Some(seen) = allowed.get_mut(&destination) else { return Ok((false, None)); };
                        if seen.elapsed() >= udp::IDLE { return Ok((false, None)); }
                        *seen = Instant::now();
                        Ok((false, Some(Datagram { flow: Flow { source, destination }, payload, _budget: None })))
                    }
                    _ = async {
                        if let Some(control) = &mut control { let _ = control.read(&mut eof).await; }
                        else { std::future::pending::<()>().await; }
                    } => bail!("UDP upstream control connection closed"),
                }
            }).await.context("UDP idle timeout")??
        };
        let Some(datagram) = event.1 else {
            if event.0 {
                return Ok(());
            }
            let pid = owner.pid;
            let generation = owner.socket_generation;
            let executable = owner.executable_str().into_owned();
            let any_destination = SocketAddr::new(initial_destination.ip(), 0);
            if !tokio::task::spawn_blocking(move || {
                libproc::process_owns_udp_endpoint(
                    pid,
                    source,
                    any_destination,
                    generation,
                    &executable,
                )
            })
            .await??
            {
                return Ok(());
            }
            continue;
        };
        last_activity = Instant::now();
        let destination = datagram.flow.destination;
        let pid = owner.pid;
        let generation = owner.socket_generation;
        let executable = owner.executable_str().into_owned();
        let current = tokio::task::spawn_blocking(move || {
            libproc::process_owns_udp_endpoint(pid, source, destination, generation, &executable)
        })
        .await??;
        if !current {
            bail!("UDP socket owner changed");
        }
        if event.0 {
            allowed.retain(|_, seen| seen.elapsed() < udp::IDLE);
            if !allowed.contains_key(&destination) && allowed.len() >= 256 {
                continue;
            }
            if !proxy {
                // Reinject the original direction. PF tags only traffic entering
                // this root-owned utun, then permits its normal kernel routing.
                // No NAT/source-port change, including replies from UDP servers.
                let original = reply_packet(
                    Flow {
                        source: destination,
                        destination: source,
                    },
                    &datagram.payload,
                )?;
                tunnel.send(&original).await?;
                continue;
            }
            let packet = udp::encode(
                &Target {
                    address: TargetAddress::Ip(destination.ip()),
                    port: destination.port(),
                },
                &datagram.payload,
            )?;
            let sent = if let Some(socket) = &upstream_socket {
                socket.send(&packet).await?
            } else {
                unreachable!("only selected sessions send upstream")
            };
            if sent != packet.len() {
                bail!("partial UDP datagram send");
            }
            allowed.insert(destination, Instant::now());
            if let Some(counter) = &counted {
                crate::traffic::record_bytes(&counter.counters().uploaded, datagram.payload.len());
            }
        } else {
            tunnel
                .send(&reply_packet(datagram.flow, &datagram.payload)?)
                .await?;
            if let Some(counter) = &counted {
                crate::traffic::record_bytes(
                    &counter.counters().downloaded,
                    datagram.payload.len(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replies_have_valid_ip_udp_checksums_and_original_endpoints() {
        for (source, destination) in [
            ("192.0.2.2:50000", "198.51.100.9:443"),
            ("[2001:db8::2]:50000", "[2001:db8::9]:443"),
        ] {
            let flow = Flow {
                source: source.parse().unwrap(),
                destination: destination.parse().unwrap(),
            };
            let packet = reply_packet(flow, b"odd payload").unwrap();
            let decoded = Fragments::default().decode(&packet).unwrap();
            assert_eq!(decoded.flow.source, flow.destination);
            assert_eq!(decoded.flow.destination, flow.source);
            assert_eq!(decoded.payload, b"odd payload");
            let start = if flow.source.is_ipv4() { 24 } else { 44 };
            let mut pseudo = Vec::new();
            if flow.source.is_ipv4() {
                assert_eq!(checksum(&packet[4..24]), 0);
                pseudo.extend_from_slice(&packet[16..24]);
                pseudo.extend_from_slice(&[0, 17]);
                pseudo.extend_from_slice(&((packet.len() - start) as u16).to_be_bytes());
            } else {
                pseudo.extend_from_slice(&packet[12..44]);
                pseudo.extend_from_slice(&((packet.len() - start) as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, 17]);
            }
            pseudo.extend_from_slice(&packet[start..]);
            assert_eq!(checksum(&pseudo), 0);
        }
    }
    #[test]
    fn fragment_reassembly_rejects_overlap_and_handles_out_of_order() {
        let key = FragmentKey {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
            id: 1,
        };
        let mut fragments = Fragments::default();
        assert!(fragments.assemble(key, 8, false, b"tail").is_none());
        assert_eq!(
            fragments.assemble(key, 0, true, b"12345678").unwrap(),
            b"12345678tail"
        );
        assert!(fragments.assemble(key, 0, true, b"12345678").is_none());
        assert!(fragments.assemble(key, 0, false, b"overlap").is_none());
        assert!(fragments.entries.is_empty());
    }
}
