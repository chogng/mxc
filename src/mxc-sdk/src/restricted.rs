// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Prepared launches that prohibit host ACL mutation and backend degradation.

use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{
    ContainmentBackend, ExecutionRequest, FailurePhase, ScriptResponse,
};
use crate::mxc_common::sandbox_process::{SandboxBackend, SandboxProcess, StdioMode};
use crate::policy::ContainerRequest;
use crate::sandbox::{MxcProcess, MxcPtyProcess, MxcPtySize};
use crate::{Error, ErrorCode};
use std::path::PathBuf;

/// Host-owned runtime controls, separate from workload-authored configuration.
#[derive(Debug, Default)]
pub struct RestrictedLaunchOptions {
    /// A trusted Bubblewrap executable selected by the embedding application.
    pub bubblewrap_executable: Option<PathBuf>,
    /// Unix socket directories allowed by an otherwise socket-denying Seatbelt profile.
    pub unix_socket_paths: Vec<String>,
    /// Additional Seatbelt deny rules compiled by the embedding application.
    /// The SDK retains ownership of the baseline profile.
    pub seatbelt_denials: String,
}

/// A validated platform process launch. Windows requires PSEC; no ACL fallback is used.
pub struct RestrictedLaunch {
    request: ExecutionRequest,
}

/// Prepare a platform process without launching the workload or changing host ACLs.
/// Missing Windows policy capabilities report `UnsupportedContainment`; OS failures
/// preserve their structured diagnostic. Launch failures never choose another backend.
pub fn prepare_restricted(
    request: ContainerRequest,
    options: RestrictedLaunchOptions,
) -> Result<RestrictedLaunch, Error> {
    let mut request = crate::policy::prepare_creation_request(&request, None)?.inner;
    let expected = if cfg!(target_os = "windows") {
        ContainmentBackend::ProcessContainer
    } else if cfg!(target_os = "linux") {
        ContainmentBackend::Bubblewrap
    } else {
        ContainmentBackend::Seatbelt
    };
    if request.containment != expected {
        return Err(Error::new(
            ErrorCode::UnsupportedContainment,
            "restricted launches require the host platform process backend",
        ));
    }
    request.policy.fallback.allow_dacl_mutation = false;
    request.bubblewrap_executable = options.bubblewrap_executable;
    #[cfg(target_os = "windows")]
    crate::process_container_common::base_container_runner::BaseContainerRunner::require_psec(
        &request,
    )
    .map_err(Error::from)?;
    #[cfg(target_os = "macos")]
    {
        let seatbelt = request.seatbelt.get_or_insert_with(Default::default);
        seatbelt.allow_unix_sockets = false;
        seatbelt.allowed_unix_socket_paths = options.unix_socket_paths;
        if !options.seatbelt_denials.is_empty() {
            if seatbelt.profile_override.is_some() {
                return Err(Error::new(
                    ErrorCode::UnsupportedContainment,
                    "additional Seatbelt denials cannot extend a profile override",
                ));
            }
            let mut profile = crate::seatbelt_common::profile_builder::build_profile_with_proxy(
                &request,
                request.policy.network_proxy.address.as_ref(),
            )
            .map_err(|message| Error::new(ErrorCode::UnsupportedContainment, message))?;
            profile.push_str(&options.seatbelt_denials);
            request
                .seatbelt
                .as_mut()
                .expect("Seatbelt configuration was created")
                .profile_override = Some(profile);
        }
    }
    #[cfg(not(target_os = "macos"))]
    if !options.unix_socket_paths.is_empty() || !options.seatbelt_denials.is_empty() {
        return Err(Error::new(
            ErrorCode::UnsupportedContainment,
            "Seatbelt restrictions require macOS",
        ));
    }
    Ok(RestrictedLaunch { request })
}

impl RestrictedLaunch {
    /// Launch with separate pipes. The caller owns output draining and execution budgets.
    pub fn spawn(self) -> Result<MxcProcess, Error> {
        self.spawn_inner(StdioMode::Pipes).map(MxcProcess::new)
    }

    /// Launch attached to a caller-controlled terminal.
    pub fn spawn_with_pty(self, size: MxcPtySize) -> Result<MxcPtyProcess, Error> {
        size.validate()?;
        self.spawn_inner(StdioMode::Pty(size.into()))
            .and_then(MxcPtyProcess::new)
    }

    /// Inherit the embedding helper's standard streams and console.
    pub fn spawn_inherited(self) -> Result<MxcProcess, Error> {
        self.spawn_inner(StdioMode::Inherit).map(MxcProcess::new)
    }

    fn spawn_inner(self, stdio: StdioMode) -> Result<Box<dyn SandboxProcess>, Error> {
        crate::mxc_engine::spawn_execution_request_with_logger_and(
            &self.request,
            Logger::new(Mode::Buffer),
            |request, logger| {
                #[cfg(target_os = "windows")]
                let mut backend = crate::process_container_common::base_container_runner::BaseContainerRunner::new();
                #[cfg(target_os = "linux")]
                let mut backend = crate::bwrap_common::bwrap_runner::BubblewrapScriptRunner::new();
                #[cfg(target_os = "macos")]
                let mut backend =
                    crate::seatbelt_common::seatbelt_runner::SeatbeltScriptRunner::new();
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                return backend.spawn(request, logger, stdio).map_err(spawn_error);
                #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                Err(
                    crate::mxc_common::mxc_error::MxcError::unsupported_containment(
                        "unsupported platform",
                    ),
                )
            },
        )
    }
}

fn spawn_error(response: ScriptResponse) -> crate::mxc_common::mxc_error::MxcError {
    let code = match response.failure_phase {
        FailurePhase::BackendUnavailable => ErrorCode::BackendUnavailable,
        FailurePhase::Rejected => ErrorCode::PolicyValidation,
        _ => ErrorCode::BackendError,
    };
    let mut message = response.error_message;
    if !response.extended_error.is_empty() {
        message.push_str(&format!(" ({})", response.extended_error));
    }
    crate::mxc_common::mxc_error::MxcError::new(
        match code {
            ErrorCode::BackendUnavailable => {
                crate::mxc_common::mxc_error::MxcErrorCode::BackendUnavailable
            }
            ErrorCode::PolicyValidation => {
                crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
            }
            _ => crate::mxc_common::mxc_error::MxcErrorCode::BackendError,
        },
        message,
    )
}

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn preparation_preserves_explicit_environment_and_denies_host_acl_changes() {
        let mut request = ContainerRequest::new("exit 0");
        request.environment = Some(Vec::new());
        request.inherit_default_environment = Some(false);
        let prepared = prepare_restricted(request, RestrictedLaunchOptions::default()).unwrap();
        assert_eq!(prepared.request.env, Some(Vec::new()));
        assert!(!prepared.request.inherit_default_env);
        assert!(!prepared.request.policy.fallback.allow_dacl_mutation);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn denials_extend_the_baseline_and_cannot_replace_an_override() {
        let denials = "\n(deny file-write* (literal \"/private/blocked\"))";
        let prepared = prepare_restricted(
            ContainerRequest::new("exit 0"),
            RestrictedLaunchOptions {
                seatbelt_denials: denials.into(),
                ..Default::default()
            },
        )
        .unwrap();
        let seatbelt = prepared.request.seatbelt.unwrap();
        assert!(!seatbelt.allow_unix_sockets);
        let profile = seatbelt.profile_override.unwrap();
        assert!(profile.starts_with("(version 1)"));
        assert!(profile.ends_with(denials));
        let mut config = crate::v1::configs::SeatbeltConfig::default();
        config.profile_override = Some("(version 1)(allow default)".into());
        let mut request = ContainerRequest::new("exit 0");
        request.containment = crate::v1::Containment::Seatbelt(config);
        assert!(matches!(
            prepare_restricted(
                request,
                RestrictedLaunchOptions {
                    seatbelt_denials: denials.into(),
                    ..Default::default()
                }
            ),
            Err(Error {
                code: ErrorCode::UnsupportedContainment,
                ..
            })
        ));
    }
}
