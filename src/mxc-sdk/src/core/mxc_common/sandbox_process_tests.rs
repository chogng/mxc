use super::poll_child_exit;

use std::process::Command;
use std::time::Duration;
use std::time::Instant;

#[test]
fn observation_preserves_exit_codes_and_leaves_reaping_to_wait() {
    for (script, expected) in [("exit 37", 37), ("kill -KILL $$", -1)] {
        let mut child = Command::new("sh").args(["-c", script]).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let observed = loop {
            match poll_child_exit(&child).unwrap() {
                Some(code) => break code,
                None if Instant::now() < deadline => std::thread::yield_now(),
                None => {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("child did not exit before the deadline");
                }
            }
        };
        // Repeated observation must retain the zombie and its PID for cleanup.
        let again = poll_child_exit(&child).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(observed, expected);
        assert_eq!(again, Some(expected));
        assert_eq!(status.code().unwrap_or(-1), expected);
    }
}

#[test]
fn observing_a_running_child_does_not_block() {
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let result = poll_child_exit(&child);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(result.unwrap(), None);
}
