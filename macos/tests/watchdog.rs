//! 死人开关的管道机制集成测试。
//!
//! 「无人值守机器上不会把自己关在门外」这条承诺由两半组成：
//!
//! * **写端关闭 → 子进程醒来**（这份文件验证，不需要 root）
//! * **醒来之后确实把 pf 规则撤掉了**（需要 root，由 `scripts/verify-macos.sh`
//!   的 T6 用真实 SIGKILL 验证）
//!
//! 之所以要把前一半单独测出来，是因为它是整条链路的触发条件：父进程被 SIGKILL
//! 时不会有任何信号发给子进程，唯一的"死亡通知"就是管道写端被内核关闭。这段
//! 管道语义如果错了，后面撤规则撤得再干净也没有机会执行。

#![cfg(target_os = "macos")]

use std::{
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const STATE: &str = r#"{"pf_was_enabled":false,"forwarding_before":0,"pf_token":null}"#;

fn spawn_watchdog() -> Child {
    Command::new(env!("CARGO_BIN_EXE_procsocks"))
        .args(["pf-watchdog", "--dry-run", "--state", STATE])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn the watchdog")
}

fn wait_for_exit(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 只要父进程还攥着管道写端，watchdog 就必须一直阻塞着——它绝不能"提前"醒来
/// 把正在服务的 pf 规则撤掉。
#[test]
fn blocks_while_the_parent_still_holds_the_pipe() {
    let mut child = spawn_watchdog();
    let pipe = child.stdin.take().expect("stdin should be piped");

    std::thread::sleep(Duration::from_millis(500));
    let early = child.try_wait().expect("try_wait failed");
    assert!(
        early.is_none(),
        "watchdog exited while the pipe was still open (status {early:?}); \
         it would tear down pf rules under a healthy process"
    );

    drop(pipe);
    let _ = child.kill();
    let _ = child.wait();
}

/// 写端一关（父进程无论怎么死都会发生），watchdog 必须马上醒来退出。
#[test]
fn wakes_up_as_soon_as_the_pipe_closes() {
    let mut child = spawn_watchdog();
    let pipe = child.stdin.take().expect("stdin should be piped");

    std::thread::sleep(Duration::from_millis(300));
    assert!(child.try_wait().expect("try_wait failed").is_none());

    // 模拟父进程消失：写端被丢弃，内核关闭管道，读端拿到 EOF。
    drop(pipe);

    let status = wait_for_exit(&mut child, Duration::from_secs(10));
    let _ = child.kill();
    assert!(
        status.is_some(),
        "watchdog never woke up after the pipe closed; the dead-man switch is broken"
    );
}

/// 握手参数被拒绝时必须快速失败，而不是挂在那里等 EOF。
#[test]
fn rejects_a_malformed_state_payload() {
    let output = Command::new(env!("CARGO_BIN_EXE_procsocks"))
        .args(["pf-watchdog", "--dry-run", "--state", "not json"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run the watchdog");

    assert!(
        !output.status.success(),
        "a malformed state payload should fail loudly"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("watchdog state"),
        "unexpected error output: {stderr}"
    );
}
