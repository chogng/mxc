// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
use windows::Win32::Security::GetSecurityDescriptorControl;
use windows::Win32::Security::SetFileSecurityW;
use windows::Win32::Security::SetSecurityDescriptorControl;
use windows::Win32::Security::SECURITY_DESCRIPTOR_CONTROL;

const FIRST: &str = "S-1-5-21-611-612-613-614";
const SECOND: &str = "S-1-5-21-621-622-623-624";

fn sddl(path: &Path) -> String {
    let descriptor = read_dacl_descriptor(path).unwrap();
    let mut text = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
        .unwrap();
    }
    let value = unsafe { text.to_string().unwrap() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    value
}

fn legacy(path: &Path) {
    let descriptor = read_dacl_descriptor(path).unwrap();
    unsafe {
        SetSecurityDescriptorControl(
            descriptor.0,
            SECURITY_DESCRIPTOR_CONTROL(0x0500),
            SECURITY_DESCRIPTOR_CONTROL(0),
        )
        .unwrap();
        assert!(SetFileSecurityW(
            PCWSTR(wide(path).as_ptr()),
            DACL_SECURITY_INFORMATION,
            descriptor.0
        )
        .as_bool());
    }
    assert!(!sddl(path).contains("AI"));
}

#[test]
fn overlapping_grants_preserve_mixed_inheritance_control_and_other_sids() {
    for protection in [0, 0x1000] {
        overlapping_fixture(protection);
    }
}

fn overlapping_fixture(protection: u16) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let old = root.join("legacy");
    let modern = root.join("modern");
    let protected = root.join("protected");
    fs::write(&old, "old").unwrap();
    fs::create_dir(&modern).unwrap();
    let grandchild = modern.join("grandchild");
    fs::write(&grandchild, "modern").unwrap();
    fs::create_dir(&protected).unwrap();
    let isolated = protected.join("child");
    fs::write(&isolated, "protected").unwrap();
    let descriptor = read_dacl_descriptor(&protected).unwrap();
    unsafe {
        SetSecurityDescriptorControl(
            descriptor.0,
            SECURITY_DESCRIPTOR_CONTROL(0x1500),
            SECURITY_DESCRIPTOR_CONTROL(0x1500),
        )
        .unwrap();
        assert!(SetFileSecurityW(
            PCWSTR(wide(&protected).as_ptr()),
            DACL_SECURITY_INFORMATION,
            descriptor.0
        )
        .as_bool());
    }
    legacy(&root);
    legacy(&old);
    legacy(&grandchild);
    // A protected legacy DACL can retain ACEs inherited before protection was
    // enabled. Those flags are part of the baseline, not explicit grants.
    let descriptor = read_dacl_descriptor(&root).unwrap();
    unsafe {
        SetSecurityDescriptorControl(
            descriptor.0,
            SECURITY_DESCRIPTOR_CONTROL(0x1500),
            SECURITY_DESCRIPTOR_CONTROL(protection),
        )
        .unwrap();
        assert!(SetFileSecurityW(
            PCWSTR(wide(&root).as_ptr()),
            DACL_SECURITY_INFORMATION,
            descriptor.0
        )
        .as_bool());
    }
    let paths = [&root, &old, &modern, &protected, &isolated, &grandchild];
    let before = paths.map(|path| sddl(path));
    let mut first = DaclManager::in_directory(&temp.path().join("journal-one")).unwrap();
    let mut second = DaclManager::in_directory(&temp.path().join("journal-two")).unwrap();
    first
        .grant_appcontainer_access(FIRST, std::slice::from_ref(&root), &[])
        .unwrap();
    second
        .grant_appcontainer_access(SECOND, std::slice::from_ref(&root), &[])
        .unwrap();
    for child in [&old, &modern, &grandchild] {
        let granted = sddl(child);
        assert!(granted.contains(FIRST), "{granted}");
        assert!(granted.contains(SECOND), "{granted}");
    }
    first.restore_strict().unwrap();
    assert!(!scan_explicit_aces_for_sid(&root, SECOND)
        .unwrap()
        .is_empty());
    for child in [&old, &modern, &grandchild] {
        let granted = sddl(child);
        assert!(!granted.contains(FIRST), "{granted}");
        assert!(granted.contains(SECOND), "{granted}");
    }
    assert_eq!(sddl(&protected), before[3]);
    assert_eq!(sddl(&isolated), before[4]);
    second.restore_strict().unwrap();
    assert_eq!(paths.map(|path| sddl(path)), before);
}

#[test]
fn orphan_recovery_restores_control_after_interrupted_propagation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let child = root.join("child");
    fs::write(&child, "unchanged").unwrap();
    legacy(&root);
    legacy(&child);
    let before = [&root, &child].map(|path| sddl(path));
    let journal = temp.path().join("journal");
    let mut manager = DaclManager::in_directory(&journal).unwrap();
    manager
        .grant_appcontainer_access(FIRST, std::slice::from_ref(&root), &[])
        .unwrap();
    // Simulate a crash between the Windows propagation and metadata restore.
    apply_explicit_ace(&root, FIRST, RW_MASK, AceType::Allow, true).unwrap();
    assert!(sddl(&root).starts_with("D:AI("));
    let mut state: StateFile =
        serde_json::from_slice(&fs::read(&manager.state_path).unwrap()).unwrap();
    assert_eq!(state.applied[0].legacy_inheritance.len(), 2);
    state.pid = 0x7fff_fffe;
    write_state_file(&manager.state_path, &state).unwrap();
    std::mem::forget(manager);
    let report = recover_orphaned_state_in(&journal).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.aces_restored, 1);
    assert_eq!([&root, &child].map(|path| sddl(path)), before);
    assert_eq!(fs::read_dir(&journal).unwrap().count(), 0);
    let descriptor = read_dacl_descriptor(&child).unwrap();
    let mut control = 0;
    let mut revision = 0;
    unsafe {
        GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision).unwrap();
    }
    assert_eq!(control & 0x0400, 0);
}
