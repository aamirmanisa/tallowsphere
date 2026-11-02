//! Test support: bind a listener on a second loopback address portably.
//!
//! The redirect fixtures need a *second host* to stand in for an unlisted
//! origin. A second `127.0.0.1:<port>` cannot serve that role: the scope
//! register keys on host, not port (`scope::host_key` ends a name or IPv4
//! literal at its port separator), so one grant for `127.0.0.1` authorises
//! every port on it. `127.0.0.2` is a distinct host key.
//!
//! Linux configures the whole of `127.0.0.0/8` on `lo`, so binding `127.0.0.2`
//! there needs no setup. macOS configures only `127.0.0.1` on `lo0`, and the
//! bind fails with `EADDRNOTAVAIL` until the alias is added. This module adds
//! the alias on that failure and retries; if the alias cannot be configured
//! the fixture panics with the reason instead of skipping — a redirect test
//! that silently does not run is worse than no test.

use std::net::TcpListener;

/// Bind `bind`, adding the loopback alias first if the platform refuses the
/// address as not configured (macOS). Panics with both errors when neither
/// path works.
pub(crate) fn bind_loopback(bind: &str) -> TcpListener {
    match TcpListener::bind(bind) {
        Ok(listener) => listener,
        Err(first) if is_addr_not_available(&first) && cfg!(target_os = "macos") => {
            let host = host_of(bind);
            if let Err(alias_err) = add_lo0_alias(host) {
                panic!(
                    "bind {bind} failed ({first}) and the {host} loopback alias could not be \
                     configured ({alias_err}); run `sudo ifconfig lo0 alias {host} up` and \
                     re-run the test"
                );
            }
            TcpListener::bind(bind).unwrap_or_else(|e| {
                panic!("bind {bind} still failed after adding the {host} lo0 alias: {e}")
            })
        }
        Err(e) => panic!("bind {bind}: {e}"),
    }
}

/// `EADDRNOTAVAIL` — the address is valid but not configured on an interface.
fn is_addr_not_available(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::AddrNotAvailable)
}

/// The host half of a `host:port` bind string.
fn host_of(bind: &str) -> &str {
    bind.rsplit_once(':').map_or(bind, |(host, _)| host)
}

#[cfg(unix)]
fn add_lo0_alias(host: &str) -> Result<(), String> {
    // The test runner is often already root (CI container, `sudo cargo test`);
    // try `ifconfig` directly first and fall back to non-interactive `sudo`
    // so a password prompt can never hang the suite.
    let direct = std::process::Command::new("ifconfig")
        .args(["lo0", "alias", host, "up"])
        .status();
    if matches!(direct, Ok(s) if s.success()) {
        return Ok(());
    }
    let direct_err = match &direct {
        Ok(s) => format!("ifconfig exited {s}"),
        Err(e) => format!("ifconfig: {e}"),
    };
    match std::process::Command::new("sudo")
        .args(["-n", "ifconfig", "lo0", "alias", host, "up"])
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("{direct_err}; sudo -n ifconfig exited {s}")),
        Err(e) => Err(format!("{direct_err}; sudo -n: {e}")),
    }
}

#[cfg(not(unix))]
fn add_lo0_alias(host: &str) -> Result<(), String> {
    Err(format!(
        "no loopback alias mechanism on this platform for {host}"
    ))
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn host_of_strips_the_port() {
        assert_eq!(host_of("127.0.0.2:0"), "127.0.0.2");
        assert_eq!(host_of("127.0.0.1:8080"), "127.0.0.1");
    }

    #[test]
    fn bind_loopback_binds_the_primary_loopback() {
        let listener = super::bind_loopback("127.0.0.1:0");
        assert!(listener
            .local_addr()
            .expect("local addr")
            .ip()
            .is_loopback());
    }

    #[test]
    fn addr_not_available_is_recognised() {
        // TEST-NET-1 is never configured on a local interface, so the bind is
        // refused with EADDRNOTAVAIL — the exact failure macOS produces for an
        // unaliased `127.0.0.2`. If this predicate stops matching, the macOS
        // alias path silently stops running and the fixture panics instead.
        let err = std::net::TcpListener::bind("192.0.2.1:0")
            .expect_err("TEST-NET-1 must not be a local address");
        assert!(
            super::is_addr_not_available(&err),
            "expected AddrNotAvailable, got {:?}: {err}",
            err.kind()
        );
    }
}
