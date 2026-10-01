//! macOS：把「本地 TCP 端口」映射回「发起连接的那个进程」。
//!
//! 这是 macOS 后端的核心原语。pf 把连接重定向到我们时，客户端的
//! **源 IP 和源端口都被保留**（已由 `spike/` 下的实测确认），因此只要扫一遍
//! 全系统 socket 表找出「谁拥有这个本地端口」，就能同时拿到：
//!
//! * 发起进程的 pid
//! * 它的可执行文件完整路径（给 `processPatterns` / `bypassPatterns` 做正则匹配）
//! * **原始目的地**——socket 的 foreign 地址在 rdr 改写之后依然是应用当初
//!   `connect()` 的目标，所以不需要再去解析 `pfctl -s state` 的文本输出
//!
//! 全部通过 libproc 完成，不需要任何 Apple entitlement，也不需要第三方 DLL。
//! 读取其它用户的进程需要 root；读取自己的进程不需要。
//!
//! 结构体布局由 `docs/libproc-layout.md` 记录的 SDK 偏移量锁定，并在文件末尾
//! 用编译期断言强制校验——布局一旦被 Apple 改动，构建就会失败而不是静默读错内存。

#![cfg(target_os = "macos")]

use std::{
    ffi::OsString,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

use anyhow::{Result, bail};

// ---------------------------------------------------------------------------
// libproc 常量（取自 macOS SDK 的 <libproc.h> / <sys/proc_info.h>）
// ---------------------------------------------------------------------------

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_TCP: i32 = 2;
const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;

unsafe extern "C" {
    fn proc_listpids(kind: u32, typeinfo: u32, buffer: *mut u8, buffersize: i32) -> i32;
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut u8, buffersize: i32) -> i32;
    fn proc_pidfdinfo(pid: i32, fd: i32, flavor: i32, buffer: *mut u8, buffersize: i32) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
}

// ---------------------------------------------------------------------------
// 结构体布局
// ---------------------------------------------------------------------------

/// `struct in4in6_addr`：3 个 64 位填充 + 4 字节 IPv4 地址。
/// 对 IPv6 socket，这 16 字节整体就是一个 `in6_addr`。
#[repr(C)]
#[derive(Clone, Copy)]
struct In4In6Addr {
    _pad: [u8; 12],
    addr4: [u8; 4],
}

impl In4In6Addr {
    fn to_ip(self, family: i32) -> Option<IpAddr> {
        match family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(self.addr4))),
            AF_INET6 => {
                // IPv6 会覆盖整个 16 字节区域，所以按 in6_addr 重新读一遍。
                let mut octets = [0u8; 16];
                octets[..12].copy_from_slice(&self._pad);
                octets[12..].copy_from_slice(&self.addr4);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}

/// `struct in_sockinfo`（80 字节）。只声明我们真正读的字段，
/// 其余用与 C 布局等宽的填充占位。
#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: i32,        // 偏移 0
    insi_lport: i32,        // 偏移 4
    _gap0: [u8; 24],        // 8..32：gencnt 与 v4/v6 选项区
    insi_faddr: In4In6Addr, // 偏移 32
    insi_laddr: In4In6Addr, // 偏移 48
    _tail: [u8; 16],        // 64..80
}

/// `struct tcp_sockinfo`（120 字节）。
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo, // 偏移 0
    tcpsi_state: i32,      // 偏移 80
    _tail: [u8; 36],       // 84..120
}

/// `struct socket_info`（768 字节）。`soi_proto` 是 528 字节的 union，
/// TCP 情形下把 `TcpSockInfo` 叠在它的起始处。
#[repr(C)]
struct SocketInfo {
    _soi_stat: [u8; 136], //   0..136  vinfo_stat
    _soi_so: u64,         // 136
    _soi_pcb: u64,        // 144
    _soi_type: i32,       // 152
    _soi_protocol: i32,   // 156
    soi_family: i32,      // 160
    _soi_options: i16,    // 164
    _soi_linger: i16,     // 166
    _soi_state: i16,      // 168
    _soi_qlen: i16,       // 170
    _soi_incqlen: i16,    // 172
    _soi_qlimit: i16,     // 174
    _soi_timeo: i16,      // 176
    _soi_error: u16,      // 178
    _soi_oobmark: u32,    // 180
    _soi_rcv: [u8; 24],   // 184..208  sockbuf_info
    _soi_snd: [u8; 24],   // 208..232  sockbuf_info
    soi_kind: i32,        // 232
    _soi_proto_rfu: u32,  // 236
    soi_proto: [u8; 528], // 240..768  union
}

/// `struct proc_fileinfo`（24 字节）——只需要它占位。
#[repr(C)]
struct ProcFileInfo {
    _bytes: [u8; 24],
}

/// `struct socket_fdinfo`（792 字节）：`psi` 在偏移 24。
#[repr(C)]
struct SocketFdInfo {
    _pfi: ProcFileInfo,
    psi: SocketInfo,
}

/// `struct proc_fdinfo`（8 字节）。
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

// 编译期布局断言：这些数字全部来自 macOS SDK 的 offsetof/sizeof 实测值。
// 一旦 Apple 改动布局，这里会直接编译失败，而不是运行时静默读错内存。
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<ProcFdInfo>() == 8);
    assert!(offset_of!(ProcFdInfo, proc_fd) == 0);
    assert!(offset_of!(ProcFdInfo, proc_fdtype) == 4);

    assert!(size_of::<In4In6Addr>() == 16);
    assert!(offset_of!(In4In6Addr, addr4) == 12);

    assert!(size_of::<InSockInfo>() == 80);
    assert!(offset_of!(InSockInfo, insi_fport) == 0);
    assert!(offset_of!(InSockInfo, insi_lport) == 4);
    assert!(offset_of!(InSockInfo, insi_faddr) == 32);
    assert!(offset_of!(InSockInfo, insi_laddr) == 48);

    assert!(size_of::<TcpSockInfo>() == 120);
    assert!(offset_of!(TcpSockInfo, tcpsi_ini) == 0);
    assert!(offset_of!(TcpSockInfo, tcpsi_state) == 80);

    assert!(size_of::<ProcFileInfo>() == 24);
    assert!(size_of::<SocketInfo>() == 768);
    assert!(offset_of!(SocketInfo, soi_family) == 160);
    assert!(offset_of!(SocketInfo, soi_kind) == 232);
    assert!(offset_of!(SocketInfo, soi_proto) == 240);

    assert!(size_of::<SocketFdInfo>() == 792);
    assert!(offset_of!(SocketFdInfo, psi) == 24);
};

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------

/// 一条连接发起方的身份信息。
#[derive(Debug, Clone)]
pub struct ConnectionOwner {
    pub pid: i32,
    /// 可执行文件完整路径，例如 `/usr/bin/curl`。
    pub executable: PathBuf,
    /// socket 的本地地址（也就是 pf 替我们保留下来的那个源地址）。
    pub local: Option<(IpAddr, u16)>,
    /// **应用当初 `connect()` 的目标**——不是被 rdr 改写后的地址。
    pub foreign: Option<(IpAddr, u16)>,
    /// TCP 状态（macOS 的 `TCPS_*`，4 = ESTABLISHED）。
    pub state: i32,
}

/// Read-only process inventory; UID filtering keeps root services out of the
/// selectable list, since the pf backend deliberately exempts them.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningProcess {
    pub pid: i32,
    pub uid: u32,
    pub name: String,
    pub executable_path: PathBuf,
}

pub fn running_processes() -> Result<Vec<RunningProcess>> {
    let mut pids = Vec::new();
    list_all_pids(&mut pids)?;
    let mut path_buffer = Vec::new();
    let mut processes = Vec::new();
    // SAFETY: geteuid has no arguments or side effects.
    let uid = unsafe { libc::geteuid() };
    for pid in pids.into_iter().filter(|pid| *pid > 0) {
        // SAFETY: the buffer is initialized, correctly sized and aligned for
        // the SDK's proc_bsdinfo. A process can disappear between both calls.
        let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>();
        let written = unsafe {
            proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size as i32,
            )
        };
        if written != size as i32 || info.pbi_uid != uid || info.pbi_uid == 0 {
            continue;
        }
        let executable_path = executable_path(pid, &mut path_buffer)?;
        let Some(name) = executable_path.file_name() else {
            continue;
        };
        processes.push(RunningProcess {
            pid,
            uid,
            name: name.to_string_lossy().into_owned(),
            executable_path,
        });
    }
    processes.sort_by(|a, b| a.name.cmp(&b.name).then(a.pid.cmp(&b.pid)));
    Ok(processes)
}

impl ConnectionOwner {
    /// 可执行路径的字符串形式，匹配不到 UTF-8 时退化为 lossy 结果。
    pub fn executable_str(&self) -> std::borrow::Cow<'_, str> {
        self.executable.to_string_lossy()
    }
}

impl fmt::Display for ConnectionOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pid={} path={}", self.pid, self.executable.display())?;
        if let Some((ip, port)) = self.foreign {
            write!(f, " -> {ip}:{port}")?;
        }
        Ok(())
    }
}

/// 用「本地端口 + 本地地址」反查发起连接的进程。
///
/// 为什么必须连地址一起匹配：**同一个端口号可以同时出现在不同的本地地址上**
/// ——`127.0.0.1:5000` 和 `192.168.1.5:5000` 完全可以属于两个不同的进程。
/// 只按端口匹配会认错进程，进而用错规则（本该直连的被代理，或反之）。
///
/// 之所以能这么比对：pf 把连接重定向过来时，客户端的**源地址和源端口都原样
/// 保留**，所以 `getpeername()` 拿到的地址就是对方 socket 的本地地址。这一点
/// 在 `spike/` 下实测确认过。
///
/// `local_address` 传 `None` 时退化为只按端口匹配（仅在拿不到对端地址时使用）。
///
/// 返回 `Ok(None)` 表示扫遍了所有进程都没找到——通常是连接已经关闭，
/// 或者调用方权限不足（非 root 时看不了别的用户的进程）。
pub fn owner_of_local_endpoint(
    local_port: u16,
    local_address: Option<IpAddr>,
) -> Result<Option<ConnectionOwner>> {
    // 每条被接管的连接都要扫几百个进程。缓冲区在这里一次性准备好、整轮复用，
    // 否则就是「每个 pid 重新分配两块 Vec」，那点分配开销会直接叠加到全机每条
    // 新建连接的延迟上（`redirectPorts: "all"` 时这就是全机的网络手感）。
    let mut scratch = Scratch::default();
    list_all_pids(&mut scratch.pids)?;

    for index in 0..scratch.pids.len() {
        let pid = scratch.pids[index];
        if pid <= 0 {
            continue;
        }
        if let Some(owner) = owner_in_process(pid, local_port, local_address, &mut scratch)? {
            return Ok(Some(owner));
        }
    }
    Ok(None)
}

/// 一轮查询里可以反复使用的缓冲区集合。
#[derive(Default)]
struct Scratch {
    /// `proc_listpids` 的结果。
    pids: Vec<i32>,
    /// 当前进程的 fd 列表，在进程之间复用。
    fds: Vec<u8>,
    /// `proc_pidpath` 的可执行路径缓冲。
    path: Vec<u8>,
}

fn list_all_pids(buffer: &mut Vec<i32>) -> Result<()> {
    // 第一次调用只为拿所需缓冲区大小。
    let needed = unsafe { proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        bail!("proc_listpids failed while sizing the pid buffer");
    }
    // 进程数随时在变，留一点余量。缓冲区由调用方复用，不在这里新分配。
    let capacity = needed as usize / size_of_pid() + 32;
    if buffer.len() < capacity {
        buffer.resize(capacity, 0);
    }

    let written = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            buffer.as_mut_ptr().cast::<u8>(),
            (buffer.len() * size_of_pid()) as i32,
        )
    };
    if written <= 0 {
        bail!("proc_listpids failed");
    }
    buffer.truncate(written as usize / size_of_pid());
    Ok(())
}

const fn size_of_pid() -> usize {
    std::mem::size_of::<i32>()
}

fn owner_in_process(
    pid: i32,
    local_port: u16,
    local_address: Option<IpAddr>,
    scratch: &mut Scratch,
) -> Result<Option<ConnectionOwner>> {
    let needed = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        // 权限不足（别人的进程且我们不是 root）或进程正在退出，都当作"没有"。
        return Ok(None);
    }
    let fd_size = std::mem::size_of::<ProcFdInfo>();
    let needed_bytes = needed as usize + fd_size * 8;
    if scratch.fds.len() < needed_bytes {
        scratch.fds.resize(needed_bytes, 0);
    }
    let buffer = &mut scratch.fds;

    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
        )
    };
    if written <= 0 {
        return Ok(None);
    }
    let count = written as usize / fd_size;

    for index in 0..count {
        let start = index * fd_size;
        let entry: ProcFdInfo =
            unsafe { std::ptr::read_unaligned(buffer[start..].as_ptr().cast::<ProcFdInfo>()) };
        if entry.proc_fdtype != PROX_FDTYPE_SOCKET {
            continue;
        }

        let mut info = std::mem::MaybeUninit::<SocketFdInfo>::uninit();
        let size = std::mem::size_of::<SocketFdInfo>() as i32;
        let read = unsafe {
            proc_pidfdinfo(
                pid,
                entry.proc_fd,
                PROC_PIDFDSOCKETINFO,
                info.as_mut_ptr().cast::<u8>(),
                size,
            )
        };
        if read != size {
            continue;
        }
        let info = unsafe { info.assume_init() };

        if info.psi.soi_kind != SOCKINFO_TCP {
            continue;
        }
        let family = info.psi.soi_family;
        if family != AF_INET && family != AF_INET6 {
            continue;
        }

        let tcp: TcpSockInfo =
            unsafe { std::ptr::read_unaligned(info.psi.soi_proto.as_ptr().cast::<TcpSockInfo>()) };

        // 端口字段是网络字节序（已由 spike 实测确认），必须 ntohs。
        let lport = u16::from_be(tcp.tcpsi_ini.insi_lport as u16);
        if lport != local_port {
            continue;
        }
        let fport = u16::from_be(tcp.tcpsi_ini.insi_fport as u16);

        let local_ip = tcp.tcpsi_ini.insi_laddr.to_ip(family);
        // 地址也要对上：同端口不同本地地址是完全合法的两回事。
        if let (Some(wanted), Some(actual)) = (local_address, local_ip)
            && wanted != actual
        {
            continue;
        }

        let local = local_ip.map(|ip| (ip, lport));
        let foreign = tcp.tcpsi_ini.insi_faddr.to_ip(family).map(|ip| (ip, fport));

        let executable = executable_path(pid, &mut scratch.path)?;

        return Ok(Some(ConnectionOwner {
            pid,
            executable,
            local,
            foreign,
            state: tcp.tcpsi_state,
        }));
    }

    Ok(None)
}

fn executable_path(pid: i32, buffer: &mut Vec<u8>) -> Result<PathBuf> {
    let size = PROC_PIDPATHINFO_MAXSIZE as usize;
    if buffer.len() < size {
        buffer.resize(size, 0);
    }
    let written = unsafe { proc_pidpath(pid, buffer.as_mut_ptr(), PROC_PIDPATHINFO_MAXSIZE) };
    if written <= 0 {
        // 拿不到路径时不要整体失败——pid 本身仍然有用，只是规则匹配会落空。
        return Ok(PathBuf::new());
    }
    Ok(PathBuf::from(OsString::from_vec(
        buffer[..written as usize].to_vec(),
    )))
}

/// 给隐藏子命令 `bench-libproc` 用的耗时基准。
///
/// 为什么值得单独测：`redirectPorts: "all"` 时**整机每一条非 root 的 TCP 连接**
/// 都要做一次连接归属查询，所以这个函数的单次耗时直接决定了全机的网络手感。
/// 拿真实数字说话，别靠猜。
pub fn benchmark(iterations: u32) -> Result<String> {
    use std::time::{Duration, Instant};

    // 建一条真实的本地环路连接，用它的本地端点当查询目标。
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let target = listener.local_addr()?;
    let client = std::net::TcpStream::connect(target)?;
    let local = client.local_addr()?;

    // 预热一次，把首次的页错误等噪声排除掉。
    let _ = owner_of_local_endpoint(local.port(), Some(local.ip()))?;

    let mut samples = Vec::with_capacity(iterations as usize);
    let mut found = 0usize;
    for _ in 0..iterations {
        let start = Instant::now();
        if owner_of_local_endpoint(local.port(), Some(local.ip()))?.is_some() {
            found += 1;
        }
        samples.push(start.elapsed());
    }
    if samples.is_empty() {
        return Ok("iterations=0".to_string());
    }

    samples.sort_unstable();
    let total: Duration = samples.iter().sum();
    let n = samples.len();
    let pick = |percent: usize| samples[(n - 1) * percent / 100];

    Ok(format!(
        "iterations={n}\n\
         resolved={found}\n\
         min={:?}\n\
         p50={:?}\n\
         p95={:?}\n\
         max={:?}\n\
         mean={:?}\n\
         processes={}\n\
         note=非 root 时读不到别的用户的进程，数字会明显偏低",
        samples[0],
        pick(50),
        pick(95),
        samples[n - 1],
        total / n as u32,
        process_count().unwrap_or(0),
    ))
}

/// 当前可见的进程数。基准报告用。
fn process_count() -> Result<usize> {
    let mut pids = Vec::new();
    list_all_pids(&mut pids)?;
    Ok(pids.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拿一个真实存在的 TCP 连接做自检：在本进程内连出去，
    /// 然后用它的本地端点反查，必须查到我们自己。
    #[test]
    fn resolves_the_owning_process_of_a_live_connection() {
        assert_connection_owner("127.0.0.1:0");
    }

    #[test]
    fn resolves_the_owning_process_of_a_live_ipv6_connection() {
        assert_connection_owner("[::1]:0");
    }

    fn assert_connection_owner(listen: &str) {
        use std::net::TcpStream;

        // 连本机一个我们刚监听的端口，避免依赖外网。
        let listener = std::net::TcpListener::bind(listen).expect("bind probe listener");
        let addr = listener.local_addr().expect("probe listener addr");
        let client = TcpStream::connect(addr).expect("connect to probe listener");
        let local = client.local_addr().expect("client local addr");

        let owner = owner_of_local_endpoint(local.port(), Some(local.ip()))
            .expect("scan should not error")
            .expect("our own connection must be discoverable");

        assert_eq!(owner.pid, std::process::id() as i32);
        assert!(
            owner.executable.to_string_lossy().contains("procsocks"),
            "expected the test binary path, got {}",
            owner.executable.display()
        );
        assert_eq!(owner.foreign, Some((addr.ip(), addr.port())));
        assert_eq!(owner.local, Some((local.ip(), local.port())));
    }

    #[test]
    fn reports_nothing_for_an_unused_port() {
        // 端口 1 上不会有人监听，也不会有人从它发起连接。
        let owner = owner_of_local_endpoint(1, None).expect("scan should not error");
        assert!(owner.is_none(), "port 1 should have no owner: {owner:?}");
    }

    /// 地址对不上时必须返回 None，而不是按端口"就近"认领一个别的进程。
    /// 这是防误判的关键：同端口不同本地地址是合法的。
    #[test]
    fn refuses_to_match_on_port_alone_when_the_address_differs() {
        use std::net::{IpAddr, Ipv4Addr, TcpStream};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let addr = listener.local_addr().expect("probe listener addr");
        let client = TcpStream::connect(addr).expect("connect to probe listener");
        let port = client.local_addr().expect("client local addr").port();

        // 换一个我们这条连接绝对没用的本地地址。
        let wrong: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let owner = owner_of_local_endpoint(port, Some(wrong)).expect("scan should not error");
        assert!(
            owner.is_none(),
            "port {port} belongs to 127.0.0.1, not {wrong}; got {owner:?}"
        );
    }
}
