//! Minimal Linux TUN device: raw `/dev/net/tun` + `TUNSETIFF`, no external
//! "tun" crate — just the ioctl LocalScale actually needs, kept small enough
//! to audit directly. Interface addressing (`ip addr`/`ip link`) is applied
//! by shelling out to the `ip` tool already assumed present on any Linux
//! LocalScale runs on (the same pattern used elsewhere in this codebase for
//! `hostname`), rather than hand-rolling `SIOCSIFADDR` socket ioctls.
//!
//! Requires `CAP_NET_ADMIN` (or root) to open `/dev/net/tun` with
//! `TUNSETIFF` and to run the `ip` commands below — `scripts/install-linux.sh`
//! grants this to the installed binary via `setcap`.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::process::Command;

const IFNAMSIZ: usize = 16;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
// `_IOW('T', 202, int)` — the standard, stable Linux TUNSETIFF ioctl number
// (unchanged since the tun driver's introduction; every minimal TUN
// implementation, including the kernel's own selftests, hardcodes this).
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// Mirrors the layout of the kernel's `struct ifreq` closely enough for
/// `TUNSETIFF`: a 16-byte interface name followed by the `ifr_flags` short
/// used by this ioctl, then padding to match the struct's real size (40
/// bytes on Linux) so the kernel never reads past the end of this value.
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: i16,
    _padding: [u8; 22],
}

pub struct TunDevice {
    file: File,
    name: String,
}

impl TunDevice {
    /// Creates (or attaches to) a TUN interface. `requested_name` is a hint
    /// — under 16 bytes including the nul terminator, e.g. "localscale0";
    /// the kernel may return a different name in `ifr_name`, which is what
    /// `name()` reports afterward.
    pub fn create(requested_name: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let mut ifr = IfReq {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0; 22],
        };
        let name_bytes = requested_name.as_bytes();
        if name_bytes.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN interface name must be under 16 bytes",
            ));
        }
        for (slot, byte) in ifr.ifr_name.iter_mut().zip(name_bytes) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: `file` is a valid, open fd for /dev/net/tun for the
        // duration of this call, and `ifr` is a validly-sized, in-scope
        // buffer matching what TUNSETIFF expects to read and write.
        let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifr) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = interface_name_from(&ifr.ifr_name);
        Ok(Self { file, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    /// Brings the interface up and assigns `cidr` (e.g. "10.0.0.5/24") by
    /// invoking the system `ip` tool — see module docs for why this isn't a
    /// raw ioctl too.
    pub fn configure_address(&self, cidr: &str) -> io::Result<()> {
        run_ip(&["addr", "add", cidr, "dev", &self.name])?;
        run_ip(&["link", "set", "dev", &self.name, "up"])
    }

    /// Adds a route to `peer_ip` (a single host, no mask) through this
    /// interface — the only routing decision a 2-node point-to-point link
    /// needs: everything addressed to the peer goes through the tunnel.
    /// Takes the interface name rather than `&self` so callers that only
    /// have the name (e.g. a thread that learned the peer's address after
    /// the device itself was handed off to another owner) can still add it.
    pub fn route_to_peer(interface_name: &str, peer_ip: &str) -> io::Result<()> {
        run_ip(&["route", "replace", peer_ip, "dev", interface_name])
    }
}

fn interface_name_from(raw: &[libc::c_char; IFNAMSIZ]) -> String {
    let bytes: Vec<u8> = raw
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("`ip {}` exited with {status}", args.join(" ")),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises real `/dev/net/tun` + `ip addr`/`ip link` on the host
    /// running the test — needs `CAP_NET_ADMIN` (root, or a binary with
    /// `setcap cap_net_admin+ep`, as `scripts/install-linux.sh` grants the
    /// installed daemon). `#[ignore]`d so ordinary `cargo test` (CI, dev
    /// machines without that capability) stays unaffected; run explicitly
    /// with `sudo cargo test --release -p localscale-agent --bin localscaled
    /// tun_linux -- --ignored`.
    #[test]
    #[ignore]
    fn real_tun_device_can_be_created_and_addressed() {
        let device = TunDevice::create("lstest0").expect("create TUN device");
        assert!(!device.name().is_empty());
        device
            .configure_address("10.250.250.1/24")
            .expect("configure address");
        let shown = Command::new("ip")
            .args(["addr", "show", device.name()])
            .output()
            .expect("run ip addr show");
        let output = String::from_utf8_lossy(&shown.stdout);
        assert!(
            output.contains("10.250.250.1"),
            "expected configured address in `ip addr show` output, got: {output}"
        );
        assert!(
            output.contains("UP"),
            "expected interface to be up, got: {output}"
        );
    }
}
