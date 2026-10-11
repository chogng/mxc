use super::*;

#[test]
fn psec_probe_classifies_only_confirmed_missing_capabilities_as_unsupported() {
    for error in [
        LearningModeError::ApiSetUnavailable {
            api: "process security-environment",
            api_set: "api-ms-win-security-basecontainer-l1-1-0",
        },
        LearningModeError::ExportMissing {
            api: "process security-environment",
            export: "CreateProcessSecurityEnvironment",
            detail: "missing".into(),
        },
        LearningModeError::HResultCall {
            function: "CreateProcessSecurityEnvironment",
            code: E_NOTIMPL.0,
        },
        LearningModeError::ApiCall {
            function: "UpdateProcThreadAttribute",
            code: ERROR_NOT_SUPPORTED.0,
        },
    ] {
        let result = psec_probe_error(error);
        assert_eq!(
            result.code,
            crate::mxc_common::mxc_error::MxcErrorCode::UnsupportedContainment
        );
        assert!(result.operation().is_some());
    }
}

#[test]
fn psec_probe_preserves_operational_failures_instead_of_enabling_fallback() {
    let error = psec_probe_error(LearningModeError::HResultCall {
        function: "CreateProcessSecurityEnvironment",
        code: windows::Win32::Foundation::E_ACCESSDENIED.0,
    });

    assert_eq!(
        error.code,
        crate::mxc_common::mxc_error::MxcErrorCode::BackendUnavailable
    );
    assert_eq!(error.operation(), Some("CreateProcessSecurityEnvironment"));
    assert_eq!(error.native_code(), Some("0x80070005"));

    let load = psec_probe_error(LearningModeError::DllLoad("bad image".into()));
    assert_eq!(
        load.code,
        crate::mxc_common::mxc_error::MxcErrorCode::BackendUnavailable
    );
    assert_eq!(load.operation(), Some("LoadLibraryExW(processmodel.dll)"));
}
