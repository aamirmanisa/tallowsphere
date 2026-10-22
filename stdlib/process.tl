// tallow.process — Process management
//
// Shell execution requires can_execute in agent context.

/// Execute a shell command
// native: runs command in default shell
native fn exec(cmd: String) -> Output

/// Execute with arguments
// native: runs command with arguments
native fn exec(cmd: String, args: []String) -> Output

/// Command output
struct Output {
    stdout:    String,
    stderr:    String,
    exit_code: i32,
    success:   bool,
}

impl Output {
    fn success(self) -> bool {
        self.exit_code == 0
    }
}

/// Spawn a background process
// native: starts process without waiting
native fn spawn(cmd: String, args: []String) -> Process

/// Process handle
struct Process {
    pid:     u32,
    running: bool,
}

impl Process {
    /// Wait for process to finish
    // native: blocks until process exits
    native fn wait(self) -> Output

    /// Kill the process
    // native: sends SIGKILL
    native fn kill(self)

    /// Check if still running
    // native: checks process status
    native fn is_running(self) -> bool
}

/// Exit current process with code
// native: exits with status code
native fn exit(code: i32)

/// Get current process ID
// native: returns current PID
native fn pid() -> u32
