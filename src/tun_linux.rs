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

/// `setcap cap_net_admin+eip` on the installed binary (see
/// `scripts/install-linux.sh`) gives *this* process `CAP_NET_ADMIN` — but a
/// plain `Command::new("ip")` execs a fresh binary that does not inherit it
/// (file capabilities don't propagate to children by default), which is why
/// the `ip addr`/`ip route` calls below would otherwise fail with
/// "RTNETLINK answers: Operation not permitted" despite the TUN device
/// itself opening fine. Raising `CAP_NET_ADMIN` into this process's
/// *ambient* capability set (once, lazily) makes every child process exec'd
/// afterward inherit it too, without needing to setcap `ip` itself (a
/// shared system binary this project has no business modifying).
/// Mirrors the kernel's `struct __user_cap_header_struct` — see
/// capabilities(7) / capget(2). Not in the `libc` crate (that's `libcap`
/// territory, which this project avoids depending on).
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

/// Mirrors `struct __user_cap_data_struct`. One entry covers capability
/// bits 0-31; version 3 always transfers two entries (bits 32-63 in the
/// second), even though every capability this project touches (CAP_NET_ADMIN
/// = 12) fits in the first.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

fn ensure_net_admin_ambient() {
    use std::sync::Once;
    static RAISE_AMBIENT: Once = Once::new();
    // Linux's <linux/capability.h> CAP_NET_ADMIN, not exposed by the `libc`
    // crate itself (that header belongs to `libcap`, which this project
    // intentionally doesn't depend on to stay self-contained) — the value
    // is a stable kernel ABI constant, unchanged since capabilities were
    // introduced.
    const CAP_NET_ADMIN: u32 = 12;
    RAISE_AMBIENT.call_once(|| {
        // `setcap cap_net_admin+eip` on this binary (see
        // scripts/install-linux.sh) grants CAP_NET_ADMIN in this process's
        // *permitted* set at exec time — but NOT its *inheritable* set:
        // despite the file's own "i" bit, a file's inheritable bit only
        // takes effect combined with whatever the *launching* process
        // already had inheritable (which is nothing, for an ordinary shell
        // or systemd unit). Ambient-capability raising requires the
        // capability in both the permitted AND inheritable sets of this
        // process, so we move it from permitted into inheritable ourselves
        // via capset(2) before raising it into the ambient set — that's
        // legal because a process can always add a capability it already
        // holds in its permitted set to its own inheritable set.
        let mut header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapUserData::default(); 2];
        // SAFETY: `header`/`data` are correctly-sized, in-scope buffers
        // matching what capget(2) expects for version 3.
        let get_result = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapUserHeader,
                data.as_mut_ptr(),
            )
        };
        if get_result != 0 {
            crate::log_event(&format!(
                "tun: capget failed: {}",
                io::Error::last_os_error()
            ));
            return;
        }
        data[0].inheritable |= 1 << CAP_NET_ADMIN;
        // capset(2) re-reads `header.pid`/`version` from what we pass, same
        // as the capget call above.
        let mut set_header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        // SAFETY: same layout contract as the capget call above; `data` now
        // holds the current capability sets with CAP_NET_ADMIN added to
        // "inheritable" only (effective/permitted are left exactly as the
        // kernel reported them, so this can't grant anything new).
        let set_result = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut set_header as *mut CapUserHeader,
                data.as_ptr(),
            )
        };
        if set_result != 0 {
            crate::log_event(&format!(
                "tun: capset failed (needs CAP_NET_ADMIN already in the permitted set — see scripts/install-linux.sh): {}",
                io::Error::last_os_error()
            ));
            return;
        }
        let raise_result = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE,
                CAP_NET_ADMIN as libc::c_ulong,
                0,
                0,
            )
        };
        if raise_result != 0 {
            crate::log_event(&format!(
                "tun: prctl(PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN) failed: {}",
                io::Error::last_os_error()
            ));
        }
    });
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    ensure_net_admin_ambient();
    let output = Command::new("ip").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "`ip {}` exited with {}: {}",
                args.join(" "),
                output.status,
                stderr.trim()
            ),
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
