// tallow.process — Process management
//
// Shell execution requires can_execute in agent context.

/// Execute a shell command
fn exec(cmd: String) -> Result<Output> {
    // native: runs command in default shell
}

/// Execute with arguments
fn exec(cmd: String, args: []String) -> Result<Output> {
    // native: runs command with arguments
}

/// Command output
struct Output {
    stdout:    String,
    stderr:    String,
    exit_code: i32,
}

impl Output {
    fn success(self) -> bool {
        self.exit_code == 0
    }
}

/// Spawn a background process
fn spawn(cmd: String, args: []String) -> Result<Process> {
    // native: starts process without waiting
}

/// Process handle
struct Process {
    pid: u32,
}

impl Process {
    /// Wait for process to finish
    fn wait(self) -> Result<Output> {
        // native: blocks until process exits
    }

    /// Kill the process
    fn kill(self) -> Result<()> {
        // native: sends SIGKILL
    }

    /// Check if still running
    fn is_running(self) -> bool {
        // native: checks process status
    }
}

/// Exit current process with code
fn exit(code: i32) {
    // native: exits with status code
}

/// Get current process ID
fn pid() -> u32 {
    // native: returns current PID
}
