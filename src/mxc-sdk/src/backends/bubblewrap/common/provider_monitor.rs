// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Watches the sandbox's network provider for the lifetime of the workload.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::OwnedFd;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::mxc_common::sandbox_process::group_kill;

/// Also the longest a disarmed monitor keeps its thread alive.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Terminates the sandbox if its network provider dies while the workload runs.
///
/// The private-namespace modes route the sandbox entirely through
/// `slirp4netns`, so losing it leaves the workload running with no network.
pub(crate) struct ProviderMonitor {
    lost: Arc<AtomicBool>,
    disarmed: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProviderMonitor {
    /// Start watching `watch`, killing `child` if the provider goes away first.
    pub(crate) fn watch(watch: OwnedFd, child: Arc<Mutex<Child>>, group: bool) -> Self {
        let lost = Arc::new(AtomicBool::new(false));
        let disarmed = Arc::new(AtomicBool::new(false));
        let thread_lost = Arc::clone(&lost);
        let thread_disarmed = Arc::clone(&disarmed);

        let handle = thread::spawn(move || {
            let mut watch = File::from(watch);
            let mut byte = [0_u8; 1];
            let mut lost_provider = false;
            loop {
                match watch.read(&mut byte) {
                    // Every holder of the write end has exited, so neither the
                    // supervisor nor an orphaned slirp is left to carry traffic.
                    Ok(0) => {
                        lost_provider = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) => {}
                    Err(_) => break,
                }

                // Read before this, never after: teardown disarms while the
                // supervisor is still up, so an already-pending EOF is a real
                // loss and must not be discarded here.
                if thread_disarmed.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(POLL_INTERVAL);
            }

            if !lost_provider {
                return;
            }
            thread_lost.store(true, Ordering::SeqCst);
            if thread_disarmed.load(Ordering::SeqCst) {
                return;
            }

            let Ok(mut child) = child.lock() else {
                return;
            };
            // Observe without reaping: the executor still owns process-tree
            // cleanup, and the leader's PID must stay reserved until then.
            if matches!(
                crate::mxc_common::sandbox_process::poll_child_exit(&child),
                Ok(None)
            ) {
                let _ = if group {
                    group_kill(&mut child)
                } else {
                    child.kill()
                };
            }
        });

        Self {
            lost,
            disarmed,
            handle: Some(handle),
        }
    }

    /// Whether the provider was lost while the workload was running.
    pub(crate) fn provider_lost(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }

    /// Stop watching, and report whether a loss had already been observed.
    pub(crate) fn disarm(&mut self) -> bool {
        self.disarmed.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.provider_lost()
    }
}

impl Drop for ProviderMonitor {
    fn drop(&mut self) {
        self.disarm();
    }
}

#[cfg(test)]
#[path = "provider_monitor_tests.rs"]
mod tests;
