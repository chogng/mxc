// Licensed under the MIT License.

//! Rejects VM-host sockets that bypass Linux network and filesystem namespaces.

use nix::libc;
use std::fs::File;
use std::io;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(crate) struct SocketFilter(File);

impl SocketFilter {
    pub(crate) fn new() -> io::Result<Self> {
        // WSL's binfmt handler retains /init through an open kernel reference.
        // Hiding /init or /run therefore cannot prevent Windows process creation.
        // Its bridge first creates an AF_VSOCK listener, outside the Linux IP
        // namespace. Block that operation for every workload and descendant.
        let architecture = if cfg!(target_arch = "x86_64") {
            0xc000_003e
        } else if cfg!(target_arch = "aarch64") {
            0xc000_00b7
        } else {
            return Err(io::Error::other("unsupported seccomp syscall architecture"));
        };
        let load = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        let equal = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        let ret = (libc::BPF_RET | libc::BPF_K) as u16;
        let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let mut instructions = vec![
            instruction(
                load,
                0,
                0,
                std::mem::offset_of!(libc::seccomp_data, arch) as u32,
            ),
            instruction(equal, 1, 0, architecture),
            instruction(ret, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
            instruction(
                load,
                0,
                0,
                std::mem::offset_of!(libc::seccomp_data, nr) as u32,
            ),
        ];
        if cfg!(target_arch = "x86_64") {
            // x32 uses the x86_64 audit architecture but different syscall
            // numbers. It must not bypass the socket-domain check below.
            instructions.extend([
                instruction(
                    (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
                    0,
                    1,
                    0x4000_0000,
                ),
                instruction(ret, 0, 0, deny),
            ]);
        }
        instructions.extend([
            instruction(equal, 1, 0, libc::SYS_socket as u32),
            instruction(ret, 0, 0, libc::SECCOMP_RET_ALLOW),
            instruction(
                load,
                0,
                0,
                std::mem::offset_of!(libc::seccomp_data, args) as u32,
            ),
            instruction(equal, 0, 1, libc::AF_VSOCK as u32),
            instruction(ret, 0, 0, deny),
            instruction(ret, 0, 0, libc::SECCOMP_RET_ALLOW),
        ]);
        let descriptor =
            unsafe { libc::memfd_create(c"mxc-socket-filter".as_ptr(), libc::MFD_CLOEXEC) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        for item in instructions {
            file.write_all(&item.code.to_ne_bytes())?;
            file.write_all(&[item.jt, item.jf])?;
            file.write_all(&item.k.to_ne_bytes())?;
        }
        // Bubblewrap reads the filter from the current descriptor offset.
        std::io::Seek::rewind(&mut file)?;
        Ok(Self(file))
    }

    pub(crate) fn configure(&self, command: &mut Command) {
        let descriptor = self.0.as_raw_fd();
        command.args(["--seccomp", &descriptor.to_string()]);
        // Only the spawned bwrap inherits this descriptor; other concurrent
        // children retain CLOEXEC. Bwrap consumes and closes it before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
