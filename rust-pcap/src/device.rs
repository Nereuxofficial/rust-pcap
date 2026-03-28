use std::ffi::CString;

/// A network interface to capture packets from.
///
/// # Examples
///
/// Capture from a specific interface:
/// ```no_run
/// # use rust_pcap::device::Device;
/// let dev = Device::lookup("eth0").unwrap();
/// ```
///
/// Capture from all interfaces:
/// ```no_run
/// # use rust_pcap::device::Device;
/// let dev = Device::any();
/// ```
#[derive(Debug, Clone)]
pub struct Device {
    /// Interface name (e.g. `"eth0"`), or `"any"` for all interfaces.
    pub name: String,
    /// Interface index, or `None` when capturing on all interfaces.
    pub ifindex: Option<u32>,
}

impl Device {
    /// Look up a network interface by name and return a [`Device`] for it.
    ///
    /// Returns an error if the interface does not exist.
    pub fn lookup(name: &str) -> std::io::Result<Self> {
        let cname = CString::new(name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SAFETY: if_nametoindex is async-signal-safe and only reads the string.
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self {
                name: name.to_owned(),
                ifindex: Some(idx),
            })
        }
    }

    /// Capture from **all** interfaces (equivalent to `tcpdump -i any`).
    pub fn any() -> Self {
        Self {
            name: "any".to_owned(),
            ifindex: None,
        }
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}
