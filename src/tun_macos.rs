//! Minimal macOS `utun` device: a `PF_SYSTEM`/`SYSPROTO_CONTROL` kernel
//! control socket, no external "tun" crate — mirrors `tun_linux.rs`'s
//! philosophy of using only the raw syscalls this needs, kept small enough
//! to audit directly. Interface addressing (`ifconfig`) and routing
//! (`route`) are applied by shelling out to system tools already assumed
//! present on any macOS LocalScale runs on, same pattern as `tun_linux.rs`.
//!
//! Unlike Linux's `/dev/net/tun` (which can be opened by an unprivileged
//! process with `IFF_NO_PI` to skip the 4-byte protocol header), a macOS
//! `utun` socket always prefixes every packet with a 4-byte address-family
//! header (`AF_INET` for IPv4). `read()`/`write()` below add and strip that
//! header so callers deal in plain IP packets either way.
//!
//! Requires root (or appropriate entitlements) to open the control socket
//! and to run `ifconfig`/`route` below.

use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::process::Command;

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
const AF_INET_HEADER: [u8; 4] = [0, 0, 0, 2]; // htonl(AF_INET) on all Apple targets

pub struct TunDevice {
    fd: RawFd,
    name: String,
}

impl TunDevice {
    /// Creates a new `utunN` interface. macOS assigns the number itself —
    /// `requested_unit` of `0` lets the kernel pick the next free one, which
    /// is what every real caller wants; the assigned name is read back
    /// afterward via `name()`.
    pub fn create(requested_unit: u32) -> io::Result<Self> {
        // SAFETY: PF_SYSTEM/SYSPROTO_CONTROL is a well-defined macOS socket
        // domain/protocol pair; a failed socket() call is reported through
        // the normal errno path below, not undefined behavior.
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut info: libc::ctl_info = unsafe { mem::zeroed() };
        for (slot, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: `fd` is the socket just created above, `info` is a
        // correctly-sized, zero-initialized `ctl_info` the kernel fills in.
        let result = unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) };
        if result < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }

        let mut addr: libc::sockaddr_ctl = unsafe { mem::zeroed() };
        addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        // sc_unit is 1-based: 0 means "let the kernel assign the next free
        // utun unit", any other value requests that specific utunN.
        addr.sc_unit = requested_unit;

        // SAFETY: `addr` is a validly-sized, in-scope `sockaddr_ctl`; `fd`
        // is the socket created above and not yet connected.
        let result = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ctl>() as u32,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }

        let name = read_interface_name(fd)?;
        Ok(Self { fd, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Brings the interface up and assigns `ip`/`peer_ip` as a point-to-point
    /// pair (`utun` interfaces are always point-to-point on macOS, so
    /// `ifconfig` requires both addresses in the same call rather than a
    /// separate route command).
    pub fn configure_address(&self, ip: &str, peer_ip: &str) -> io::Result<()> {
        run_ifconfig(&[&self.name, ip, peer_ip, "up"])
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// A `utun` socket owns exactly one raw fd usable for both reading and
/// writing, so cloning it for use across two threads is just `dup()`.
pub struct TunHandle(RawFd);

impl TunDevice {
    pub fn try_clone_handle(&self) -> io::Result<TunHandle> {
        // SAFETY: `self.fd` is a valid, open fd for the lifetime of `self`.
        let cloned = unsafe { libc::dup(self.fd) };
        if cloned < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(TunHandle(cloned))
    }
}

impl TunHandle {
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut framed = vec![0u8; buf.len() + 4];
        let n = unsafe {
            libc::read(self.0, framed.as_mut_ptr() as *mut libc::c_void, framed.len())
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Ok(0);
        }
        let payload_len = n - 4;
        buf[..payload_len].copy_from_slice(&framed[4..n]);
        Ok(payload_len)
    }

    pub fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&AF_INET_HEADER);
        framed.extend_from_slice(packet);
        let n = unsafe {
            libc::write(self.0, framed.as_ptr() as *const libc::c_void, framed.len())
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn read_interface_name(fd: RawFd) -> io::Result<String> {
    let mut name_buf = [0u8; libc::IFNAMSIZ];
    let mut len = name_buf.len() as libc::socklen_t;
    // SAFETY: `fd` is the connected utun socket; `name_buf`/`len` describe a
    // validly-sized output buffer for `getsockopt`.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name_buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = name_buf.iter().position(|b| *b == 0).unwrap_or(name_buf.len());
    Ok(String::from_utf8_lossy(&name_buf[..end]).into_owned())
}

fn run_ifconfig(args: &[&str]) -> io::Result<()> {
    let status = Command::new("ifconfig").args(args).status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("`ifconfig {}` exited with {status}", args.join(" ")),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises a real `utun` device + `ifconfig` on the host running the
    /// test — needs root. `#[ignore]`d so ordinary `cargo test` stays
    /// unaffected; run explicitly with `sudo cargo test --release --bin
    /// localscaled tun_macos -- --ignored`.
    #[test]
    #[ignore]
    fn real_utun_device_can_be_created_and_addressed() {
        let device = TunDevice::create(0).expect("create utun device");
        assert!(device.name().starts_with("utun"));
        device
            .configure_address("10.250.250.1", "10.250.250.2")
            .expect("configure address");
        let shown = Command::new("ifconfig")
            .arg(device.name())
            .output()
            .expect("run ifconfig");
        let output = String::from_utf8_lossy(&shown.stdout);
        assert!(
            output.contains("10.250.250.1"),
            "expected configured address in `ifconfig` output, got: {output}"
        );
        assert!(
            output.contains("UP"),
            "expected interface to be up, got: {output}"
        );
    }
}
