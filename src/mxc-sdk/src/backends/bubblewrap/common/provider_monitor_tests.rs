use super::*;

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::unistd::pipe2;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::Instant;

/// The read end must not block, or a disarmed monitor could never notice.
fn watch_pipe() -> (OwnedFd, OwnedFd) {
    let (reader, writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
    let flags = fcntl(reader.as_raw_fd(), FcntlArg::F_GETFL).expect("read descriptor flags");
    fcntl(
        reader.as_raw_fd(),
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .expect("set descriptor nonblocking");
    (reader, writer)
}

fn sleeping_sandbox() -> Arc<Mutex<Child>> {
    Arc::new(Mutex::new(
        Command::new("sleep").arg("30").spawn().expect("spawn"),
    ))
}

fn exited_within(child: &Arc<Mutex<Child>>, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let exited = child
            .lock()
            .map(|child| {
                matches!(
                    crate::mxc_common::sandbox_process::poll_child_exit(&child),
                    Ok(Some(_))
                )
            })
            .unwrap_or(false);
        if exited {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

fn reap(child: &Arc<Mutex<Child>>) {
    if let Ok(mut child) = child.lock() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn a_lost_provider_takes_the_sandbox_down_with_it() {
    let (watch, writer) = watch_pipe();
    let child = sleeping_sandbox();
    let mut monitor = ProviderMonitor::watch(watch, Arc::clone(&child), false);

    drop(writer);

    assert!(
        exited_within(&child, Duration::from_secs(10)),
        "the sandbox outlived the provider carrying its only route"
    );
    assert!(
        monitor.disarm(),
        "the loss must reach the run rather than being reported as a workload exit"
    );
    reap(&child);
}

#[test]
fn a_disarmed_monitor_leaves_the_sandbox_alone() {
    let (watch, writer) = watch_pipe();
    let child = sleeping_sandbox();
    let mut monitor = ProviderMonitor::watch(watch, Arc::clone(&child), false);

    monitor.disarm();
    drop(writer);

    assert!(
        !exited_within(&child, Duration::from_millis(500)),
        "teardown closing the watch must not be mistaken for a provider death"
    );
    assert!(!monitor.provider_lost());
    reap(&child);
}

#[test]
fn a_monitor_over_an_already_reaped_sandbox_still_settles() {
    let (watch, writer) = watch_pipe();
    let child = Arc::new(Mutex::new(Command::new("true").spawn().expect("spawn")));
    reap(&child);
    let mut monitor = ProviderMonitor::watch(watch, Arc::clone(&child), true);

    drop(writer);

    assert!(monitor.disarm(), "the loss is still worth reporting");
}

#[test]
fn provider_observation_leaves_an_exited_leader_unreaped() {
    let (watch, writer) = watch_pipe();
    let child = Arc::new(Mutex::new(Command::new("true").spawn().expect("spawn")));
    assert!(exited_within(&child, Duration::from_secs(10)));
    let mut monitor = ProviderMonitor::watch(watch, Arc::clone(&child), true);

    drop(writer);
    assert!(monitor.disarm());
    let mut leader = child.lock().unwrap();
    assert_eq!(
        crate::mxc_common::sandbox_process::poll_child_exit(&leader).unwrap(),
        Some(0),
        "the monitor must not release the PID before process-tree cleanup"
    );
    assert!(leader.wait().unwrap().success());
}
