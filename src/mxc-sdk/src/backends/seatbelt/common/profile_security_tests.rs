use super::*;

#[test]
fn directory_discovery_keeps_shared_cache_writes_and_launchservices_closed() {
    let profile = build_profile_with_proxy(&ExecutionRequest::default(), None).unwrap();
    assert!(profile.contains("(global-name \"com.apple.bsd.dirhelper\")"));
    assert!(!profile.contains("(allow mach-lookup)"));
    assert!(!profile.contains("com.apple.lsd"));
    assert!(!profile.contains("(allow file-read* file-write* (subpath \"/private/var/folders\"))"));
    assert!(!profile.contains("(allow file-read* file-write* (subpath \"/private/tmp\"))"));
}

#[test]
fn protected_children_pin_ancestors_after_all_grants() {
    let mut request = ExecutionRequest::default();
    request.policy.readwrite_paths = vec!["/workspace".into(), "/destination".into()];
    request.policy.readonly_paths = vec!["/workspace/config/settings".into()];
    request.policy.denied_paths = vec!["/workspace/private/secret".into()];
    let profile = build_profile_with_proxy(&request, None).unwrap();
    for path in [
        "/workspace",
        "/destination",
        "/workspace/config",
        "/workspace/private",
    ] {
        let anchor = format!(
            "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal \"{path}\")))"
        );
        assert!(profile.contains(&anchor), "{profile}");
        assert!(profile.find(&anchor) > profile.find("policy.deniedPaths"));
    }
    assert!(profile.contains("(deny system-fcntl (fcntl-command 80 110))"));
}

#[test]
fn full_disk_write_only_omits_fcntl_denial_without_carveouts() {
    let mut request = ExecutionRequest::default();
    request.policy.readwrite_paths = vec!["/".into()];
    assert!(
        !build_profile_with_proxy(&request, None)
            .unwrap()
            .contains("system-fcntl")
    );
    request.policy.readonly_paths = vec!["/private-data".into()];
    assert!(
        build_profile_with_proxy(&request, None)
            .unwrap()
            .contains("system-fcntl")
    );
}
