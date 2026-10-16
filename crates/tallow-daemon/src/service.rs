// Cross-platform service management for Tallow Daemon.
//
// Platform implementations:
//   - Windows: sc.exe (SCM — Service Control Manager)
//   - Linux:   systemd unit file + systemctl
//   - macOS:   launchd plist + launchctl

const SERVICE_NAME: &str = "TallowDaemon";
const DISPLAY_NAME: &str = "Tallow Daemon";

/// Install the daemon as a system service on the current platform.
pub fn install_service() {
    #[cfg(target_os = "windows")]
    windows::install();
    #[cfg(target_os = "linux")]
    linux::install_systemd();
    #[cfg(target_os = "macos")]
    macos::install_launchd();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    compile_error!("Unsupported platform for service management");
}

/// Uninstall the daemon service.
pub fn uninstall_service() {
    #[cfg(target_os = "windows")]
    windows::uninstall();
    #[cfg(target_os = "linux")]
    linux::uninstall_systemd();
    #[cfg(target_os = "macos")]
    macos::uninstall_launchd();
}

/// Start the system service.
pub fn start_service() {
    #[cfg(target_os = "windows")]
    windows::start();
    #[cfg(target_os = "linux")]
    linux::start();
    #[cfg(target_os = "macos")]
    macos::start();
}

/// Stop the system service.
pub fn stop_service() {
    #[cfg(target_os = "windows")]
    windows::stop();
    #[cfg(target_os = "linux")]
    linux::stop();
    #[cfg(target_os = "macos")]
    macos::stop();
}

/// Show system service status.
pub fn service_status() {
    #[cfg(target_os = "windows")]
    windows::status();
    #[cfg(target_os = "linux")]
    linux::status();
    #[cfg(target_os = "macos")]
    macos::status();
}

// ---------------------------------------------------------------------------
// Windows — Service Control Manager via sc.exe
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows {
    use std::process::Command;

    const SERVICE_NAME: &str = super::SERVICE_NAME;
    const DISPLAY_NAME: &str = super::DISPLAY_NAME;

    /// Run sc.exe with the given arguments, printing errors if any.
    fn run_sc(args: &[&str]) -> std::io::Result<std::process::Output> {
        Command::new("sc.exe").args(args).output()
    }

    pub fn install() {
        let exe = std::env::current_exe().expect("Failed to get current exe path");
        let bin_path = format!("\"{}\"", exe.display());

        println!("Installing '{}' as a Windows service...", DISPLAY_NAME);
        println!("  Binary: {}", exe.display());

        let output = run_sc(&[
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            DISPLAY_NAME,
        ]);

        match output {
            Ok(out) => {
                let msg = String::from_utf8_lossy(&out.stdout);
                let err = String::from_utf8_lossy(&out.stderr);
                if out.status.success() || msg.contains("[SC] CreateService") {
                    println!("Service '{}' installed successfully.", DISPLAY_NAME);
                    println!("Start with: sc start {}", SERVICE_NAME);
                    println!("Or: tallow-daemon start");
                } else {
                    eprintln!("Failed to install service:");
                    eprintln!("STDOUT: {}", msg);
                    eprintln!("STDERR: {}", err);
                    eprintln!();
                    eprintln!("Make sure you run this command as Administrator.");
                }
            }
            Err(e) => {
                eprintln!("Failed to run sc.exe: {e}");
                eprintln!("Make sure you run this command as Administrator.");
            }
        }
    }

    pub fn uninstall() {
        println!("Removing service '{}'...", DISPLAY_NAME);
        match run_sc(&["stop", SERVICE_NAME]) {
            Ok(_) => {} // May fail if not running — that's ok
            Err(_) => {}
        }
        match run_sc(&["delete", SERVICE_NAME]) {
            Ok(out) => {
                let msg = String::from_utf8_lossy(&out.stdout);
                if out.status.success() || msg.contains("[SC] DeleteService") {
                    println!("Service '{}' removed.", DISPLAY_NAME);
                } else {
                    eprintln!("Failed to remove service: {}", msg);
                }
            }
            Err(e) => eprintln!("Failed to run sc.exe: {e}"),
        }
    }

    pub fn start() {
        println!("Starting service '{}'...", DISPLAY_NAME);
        match run_sc(&["start", SERVICE_NAME]) {
            Ok(out) => {
                let msg = String::from_utf8_lossy(&out.stdout);
                println!("{}", msg.trim());
            }
            Err(e) => eprintln!("Failed to run sc.exe: {e}"),
        }
    }

    pub fn stop() {
        println!("Stopping service '{}'...", DISPLAY_NAME);
        match run_sc(&["stop", SERVICE_NAME]) {
            Ok(out) => {
                let msg = String::from_utf8_lossy(&out.stdout);
                println!("{}", msg.trim());
            }
            Err(e) => eprintln!("Failed to run sc.exe: {e}"),
        }
    }

    pub fn status() {
        match run_sc(&["query", SERVICE_NAME]) {
            Ok(out) => {
                let msg = String::from_utf8_lossy(&out.stdout);
                if out.status.success() {
                    // Extract relevant lines: STATE line
                    for line in msg.lines() {
                        let trimmed = line.trim();
                        if trimmed.contains("STATE") {
                            println!("Service '{}': {}", DISPLAY_NAME, trimmed);
                            return;
                        }
                    }
                    println!("Service '{}': unknown state", DISPLAY_NAME);
                } else {
                    println!("Service '{}': not installed", DISPLAY_NAME);
                }
            }
            Err(_) => println!("Service '{}': not installed", DISPLAY_NAME),
        }
    }
}

// ---------------------------------------------------------------------------
// Linux — systemd unit file
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;

    const UNIT_NAME: &str = super::SERVICE_NAME;
    const UNIT_PATH: &str = "/etc/systemd/system/tallow-daemon.service";

    fn generate_unit_file() -> String {
        let exe = std::env::current_exe().unwrap_or_else(|_| {
            std::path::PathBuf::from("/usr/local/bin/tallow-daemon")
        });
        let user = std::env::var("USER").unwrap_or_else(|_| "nobody".into());

        format!(
            r#"[Unit]
Description=Tallow Copy Daemon
After=network.target

[Service]
Type=simple
User={user}
ExecStart={exe} run
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=tallow_daemon=info

[Install]
WantedBy=multi-user.target
"#,
            user = user,
            exe = exe.display()
        )
    }

    pub fn install_systemd() {
        let unit = generate_unit_file();
        match std::fs::write(UNIT_PATH, &unit) {
            Ok(_) => {
                println!("Systemd unit installed at {}", UNIT_PATH);
                // Reload systemd
                let _ = Command::new("systemctl").args(["daemon-reload"]).status();
                println!("Enable with: sudo systemctl enable tallow-daemon");
                println!("Start with:  sudo systemctl start tallow-daemon");
            }
            Err(e) => {
                eprintln!("Failed to write unit file at {}: {e}", UNIT_PATH);
                eprintln!("Run with sudo to install the systemd unit.");
            }
        }
    }

    pub fn uninstall_systemd() {
        let _ = Command::new("systemctl").args(["stop", UNIT_NAME]).status();
        let _ = Command::new("systemctl").args(["disable", UNIT_NAME]).status();
        match std::fs::remove_file(UNIT_PATH) {
            Ok(_) => {
                let _ = Command::new("systemctl").args(["daemon-reload"]).status();
                println!("Systemd unit removed.");
            }
            Err(e) => eprintln!("Failed to remove unit file: {e}"),
        }
    }

    pub fn start() {
        println!("Starting systemd service '{}'...", UNIT_NAME);
        match Command::new("systemctl").args(["start", UNIT_NAME]).status() {
            Ok(s) if s.success() => println!("Service started."),
            Ok(_) => eprintln!("Failed to start service. Run with sudo."),
            Err(e) => eprintln!("Failed to run systemctl: {e}. Run with sudo."),
        }
    }

    pub fn stop() {
        println!("Stopping systemd service '{}'...", UNIT_NAME);
        match Command::new("systemctl").args(["stop", UNIT_NAME]).status() {
            Ok(s) if s.success() => println!("Service stopped."),
            Ok(_) => eprintln!("Failed to stop service."),
            Err(e) => eprintln!("Failed to run systemctl: {e}"),
        }
    }

    pub fn status() {
        match Command::new("systemctl")
            .args(["is-active", UNIT_NAME])
            .output()
        {
            Ok(output) => {
                let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
                println!("Service '{}': {}", UNIT_NAME, status);
            }
            Err(_) => {
                println!("systemctl not available — check daemon with 'tallow daemon status'");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS — launchd plist
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use std::process::Command;
    use std::path::PathBuf;

    const PLIST_NAME: &str = "com.tallow.daemon.plist";
    const LABEL: &str = "com.tallow.daemon";

    fn plist_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("Library/LaunchAgents")
            .join(PLIST_NAME)
    }

    fn generate_plist() -> String {
        let exe = std::env::current_exe().unwrap_or_else(|_| {
            PathBuf::from("/usr/local/bin/tallow-daemon")
        });
        let log_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("tallow/daemon");

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/tallow-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/tallow-daemon.err</string>
</dict>
</plist>"#,
            label = LABEL,
            exe = exe.display(),
            log_dir = log_dir.display(),
        )
    }

    pub fn install_launchd() {
        let plist = generate_plist();
        let path = plist_path();

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::write(&path, &plist) {
            Ok(_) => {
                println!("LaunchAgent installed at {}", path.display());
                println!("Load with: launchctl load {}", path.display());
            }
            Err(e) => eprintln!("Failed to write plist file: {e}"),
        }
    }

    pub fn uninstall_launchd() {
        let path = plist_path();
        if path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", &path.to_string_lossy()])
                .status();
            let _ = std::fs::remove_file(&path);
            println!("LaunchAgent removed.");
        } else {
            println!("No LaunchAgent found at {}", path.display());
        }
    }

    pub fn start() {
        let path = plist_path();
        if !path.exists() {
            eprintln!("LaunchAgent not installed. Run 'tallow-daemon install' first.");
            return;
        }
        match Command::new("launchctl")
            .args(["load", &path.to_string_lossy()])
            .status()
        {
            Ok(s) if s.success() => println!("LaunchAgent loaded."),
            Ok(_) => eprintln!("Failed to load LaunchAgent."),
            Err(e) => eprintln!("Failed to run launchctl: {e}"),
        }
    }

    pub fn stop() {
        let path = plist_path();
        if path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", &path.to_string_lossy()])
                .status();
        }
        let _ = Command::new("launchctl")
            .args(["remove", LABEL])
            .status();
        println!("LaunchAgent stopped.");
    }

    pub fn status() {
        let output = Command::new("launchctl").args(["list"]).output();
        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let running = text.contains(LABEL);
                println!(
                    "LaunchAgent '{}': {}",
                    LABEL,
                    if running { "running" } else { "not running" }
                );
            }
            Err(e) => eprintln!("Failed to run launchctl: {e}"),
        }
    }
}
