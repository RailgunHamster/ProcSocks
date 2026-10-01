//! Exercise real process signals without loading pf rules or using an upstream.
#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct BridgeProcess {
    child: Child,
    directory: PathBuf,
}

impl Drop for BridgeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn verify_signal(signal: &str, inherited_blocked_mask: bool) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "procsocks-signal-{}-{nonce}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let config_path = directory.join("config.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "listen": reservation.local_addr().unwrap().to_string(),
            "upstream": { "host": "127.0.0.1", "port": 9 }
        }))
        .unwrap(),
    )
    .unwrap();
    drop(reservation);

    let mut command = Command::new(env!("CARGO_BIN_EXE_procsocks"));
    command
        .arg("--config")
        .arg(&config_path)
        .arg("bridge")
        .env("RUST_LOG", "procsocks=info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if inherited_blocked_mask {
        // SAFETY: only async-signal-safe libc operations run after fork. This
        // reproduces the signal mask inherited from a privileged launcher.
        unsafe {
            command.pre_exec(|| {
                let mut signals = std::mem::zeroed::<libc::sigset_t>();
                if libc::sigemptyset(&mut signals) != 0
                    || libc::sigaddset(&mut signals, libc::SIGTERM) != 0
                    || libc::sigaddset(&mut signals, libc::SIGINT) != 0
                    || libc::sigprocmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let child = command.spawn().unwrap();
    let mut process = BridgeProcess { child, directory };
    let stdout = process.child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let ready = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("bridge did not start");
    assert!(ready.contains("SOCKS bridge listening"), "{ready}");
    assert!(
        !ready.contains("\x1b["),
        "redirected logs must be plain text: {ready}"
    );

    let status = Command::new("/bin/kill")
        .args([signal, &process.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    let exit = loop {
        if let Some(exit) = process.child.try_wait().unwrap() {
            break exit;
        }
        assert!(
            Instant::now() < deadline,
            "bridge did not shut down after {signal}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        exit.success(),
        "bridge died from {signal} instead of returning normally: {exit}"
    );
    reader.join().unwrap();
    let logs = receiver.try_iter().collect::<Vec<_>>().join("\n");
    assert!(logs.contains("shutdown requested"), "{logs}");
}

#[test]
fn sigterm_stops_the_bridge_gracefully() {
    verify_signal("-TERM", false);
}

#[test]
fn sigint_stops_the_bridge_gracefully() {
    verify_signal("-INT", false);
}

#[test]
fn sigterm_stops_the_bridge_with_an_inherited_blocked_mask() {
    verify_signal("-TERM", true);
}

#[test]
fn sigint_stops_the_bridge_with_an_inherited_blocked_mask() {
    verify_signal("-INT", true);
}
