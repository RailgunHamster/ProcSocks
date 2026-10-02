//! Count payload bytes when writes succeed, rather than estimating from process
//! network totals. SOCKS negotiation and direct fallback never use these counters.
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub(crate) struct TransferCounters {
    pub uploaded: AtomicU64,
    pub downloaded: AtomicU64,
}

pub(crate) fn record_bytes(counter: &AtomicU64, bytes: usize) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(bytes as u64))
    });
}

pub(crate) struct CountedStream<'a, T> {
    inner: T,
    written: Option<&'a AtomicU64>,
}

impl<'a, T> CountedStream<'a, T> {
    pub fn new(inner: T, written: Option<&'a AtomicU64>) -> Self {
        Self { inner, written }
    }

    fn record(&self, bytes: usize) {
        if let Some(counter) = self.written {
            record_bytes(counter, bytes);
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountedStream<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountedStream<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(bytes)) = &result {
            self.record(*bytes);
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(bytes)) = &result {
            self.record(*bytes);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use anyhow::{Context as _, Result};
    use serde::Serialize;
    use std::{
        collections::BTreeMap,
        fs::{self, OpenOptions},
        io::Write,
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
        path::{Path, PathBuf},
        sync::{Arc, Mutex, atomic::AtomicUsize, mpsc},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    #[derive(Default)]
    pub(crate) struct Ledger {
        processes: Mutex<BTreeMap<i32, Arc<ProcessCounters>>>,
    }

    struct ProcessCounters {
        pid: i32,
        executable_path: String,
        name: String,
        counters: TransferCounters,
        active: AtomicUsize,
    }

    pub(crate) struct Connection(Arc<ProcessCounters>);

    impl Connection {
        pub fn counters(&self) -> &TransferCounters {
            &self.0.counters
        }
    }

    impl Drop for Connection {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct Snapshot {
        schema_version: u8,
        session_id: String,
        sampled_at: f64,
        processes: Vec<ProcessSnapshot>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ProcessSnapshot {
        pid: i32,
        executable_path: String,
        name: String,
        uploaded: u64,
        downloaded: u64,
        active_connections: usize,
    }

    impl Ledger {
        pub fn connect(&self, pid: i32, executable: &str) -> Connection {
            let mut processes = self
                .processes
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let process = processes
                .entry(pid)
                .or_insert_with(|| Arc::new(ProcessCounters::new(pid, executable)));
            if process.executable_path != executable {
                *process = Arc::new(ProcessCounters::new(pid, executable));
            }
            process.active.fetch_add(1, Ordering::Relaxed);
            Connection(Arc::clone(process))
        }

        pub fn snapshot(&self, session_id: &str) -> Snapshot {
            let processes = self
                .processes
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            Snapshot {
                schema_version: 1,
                session_id: session_id.into(),
                sampled_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
                processes: processes
                    .values()
                    .map(|process| ProcessSnapshot {
                        pid: process.pid,
                        executable_path: process.executable_path.clone(),
                        name: process.name.clone(),
                        uploaded: process.counters.uploaded.load(Ordering::Relaxed),
                        downloaded: process.counters.downloaded.load(Ordering::Relaxed),
                        active_connections: process.active.load(Ordering::Relaxed),
                    })
                    .collect(),
            }
        }
    }

    impl ProcessCounters {
        fn new(pid: i32, executable: &str) -> Self {
            Self {
                pid,
                executable_path: executable.into(),
                name: Path::new(executable)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into(),
                counters: TransferCounters::default(),
                active: AtomicUsize::new(0),
            }
        }
    }

    /// A private, atomically replaced snapshot for the existing GUI owner. The
    /// parent directory is root-owned; the GUI can read but cannot replace it.
    pub(crate) struct Publisher {
        pub ledger: Arc<Ledger>,
        stop: mpsc::Sender<()>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl Publisher {
        pub fn start(path: PathBuf, owner: u32) -> Result<Self> {
            let ledger = Arc::new(Ledger::default());
            let session = format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
            );
            publish(&path, owner, &ledger.snapshot(&session), 0)?;
            let (stop, receiver) = mpsc::channel();
            let source = Arc::clone(&ledger);
            let worker = std::thread::spawn(move || {
                let mut sequence = 1u64;
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    receiver.recv_timeout(Duration::from_secs(1))
                {
                    if let Err(error) = publish(&path, owner, &source.snapshot(&session), sequence)
                    {
                        tracing::warn!(error = %error, "could not publish proxy traffic counters");
                    }
                    sequence = sequence.wrapping_add(1);
                }
            });
            Ok(Self {
                ledger,
                stop,
                worker: Some(worker),
            })
        }
    }

    impl Drop for Publisher {
        fn drop(&mut self) {
            let _ = self.stop.send(());
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn publish(path: &Path, owner: u32, snapshot: &Snapshot, sequence: u64) -> Result<()> {
        let parent = path.parent().context("traffic snapshot has no parent")?;
        let temporary = parent.join(format!(".traffic-{}-{sequence}", std::process::id()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&temporary)?;
            // SAFETY: a live descriptor; only this ordinary user may read it.
            if unsafe { libc::fchown(file.as_raw_fd(), owner, u32::MAX) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            file.write_all(&serde_json::to_vec(snapshot)?)?;
            fs::rename(&temporary, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.context("failed to write proxy traffic snapshot")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        #[test]
        fn snapshot_is_private_complete_json_and_atomically_replaces_a_symlink() {
            let directory = std::env::temp_dir().join(format!(
                "procsocks-traffic-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("traffic.json");
            let victim = directory.join("untouched.txt");
            fs::write(&victim, b"untouched").unwrap();
            std::os::unix::fs::symlink(&victim, &path).unwrap();
            let ledger = Ledger::default();
            let connection = ledger.connect(7, "/proxy-only");
            connection.counters().uploaded.store(123, Ordering::Relaxed);
            // SAFETY: getuid has no arguments or preconditions.
            let owner = unsafe { libc::getuid() };
            publish(&path, owner, &ledger.snapshot("test-session"), 0).unwrap();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_file());
            assert_eq!(metadata.uid(), owner);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
            let snapshot: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(snapshot["processes"][0]["uploaded"], 123);
            assert_eq!(snapshot["sessionId"], "test-session");
            assert_eq!(fs::read(&victim).unwrap(), b"untouched");
            fs::remove_dir_all(directory).unwrap();
        }

        #[test]
        fn parallel_connections_keep_their_process_and_close_even_on_error() {
            let ledger = Ledger::default();
            let first = ledger.connect(7, "/Applications/A.app/Contents/MacOS/A");
            let second = ledger.connect(7, "/Applications/A.app/Contents/MacOS/A");
            let other = ledger.connect(8, "/Applications/B.app/Contents/MacOS/B");
            first.counters().uploaded.store(12, Ordering::Relaxed);
            other.counters().downloaded.store(35, Ordering::Relaxed);
            let snapshot = ledger.snapshot("test");
            assert_eq!(snapshot.processes[0].active_connections, 2);
            assert_eq!(snapshot.processes[0].uploaded, 12);
            assert_eq!(snapshot.processes[0].downloaded, 0);
            assert_eq!(snapshot.processes[1].downloaded, 35);
            drop(first);
            drop(second);
            drop(other);
            assert!(
                ledger
                    .snapshot("test")
                    .processes
                    .iter()
                    .all(|p| p.active_connections == 0)
            );
        }

        #[test]
        fn a_reused_pid_with_a_different_executable_starts_new_counters() {
            let ledger = Ledger::default();
            let old = ledger.connect(7, "/old");
            old.counters().uploaded.store(999, Ordering::Relaxed);
            let new = ledger.connect(7, "/new");
            new.counters().uploaded.store(2, Ordering::Relaxed);
            drop(old);
            let snapshot = ledger.snapshot("test");
            assert_eq!(snapshot.processes[0].uploaded, 2);
            assert_eq!(snapshot.processes[0].active_connections, 1);
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use macos::{Ledger, Publisher};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_only_successful_writes_including_partial_writes() {
        let (stream, mut peer) = tokio::io::duplex(3);
        let count = AtomicU64::new(0);
        let mut stream = CountedStream::new(stream, Some(&count));
        assert_eq!(stream.write(b"hello").await.unwrap(), 3);
        assert_eq!(count.load(Ordering::Relaxed), 3);
        let mut received = [0; 3];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hel");
        peer.write_all(b"abc").await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(
            count.load(Ordering::Relaxed),
            3,
            "reads are not forwarded bytes"
        );
        drop(peer);
        assert!(stream.write(b"lost").await.is_err());
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn an_unmetered_direct_stream_does_not_change_proxy_counters() {
        let (stream, mut peer) = tokio::io::duplex(16);
        let counters = TransferCounters::default();
        let mut direct = CountedStream::new(stream, None);
        direct.write_all(b"direct").await.unwrap();
        let mut received = [0; 6];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"direct");
        assert_eq!(counters.uploaded.load(Ordering::Relaxed), 0);
        assert_eq!(counters.downloaded.load(Ordering::Relaxed), 0);
    }
}
