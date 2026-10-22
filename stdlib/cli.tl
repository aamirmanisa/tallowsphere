// tallow.cli — CLI argument parsing

/// CLI application
struct App {
    name:        String,
    version:     String,
    description: String,
    commands:    []Command = [],
    flags:       []Flag = [],
}

/// CLI subcommand
struct Command {
    name:        String,
    description: String,
    flags:       []Flag = [],
    handler:     fn(Context) -> Result<()>,
}

/// CLI flag/option
struct Flag {
    name:        String,     // "--output"
    short:       char?,      // 'o'
    description: String,
    required:    bool = false,
    default:     String?,
}

/// Parsed CLI context
struct Context {
    args:  []String,
    flags: Map<String, String>,
}

impl Context {
    fn flag(self, name: String) -> String? {
        self.flags[name]
    }

    fn flag_or(self, name: String, default: String) -> String {
        self.flags[name] match {
            Some(v) -> v
            None    -> default
        }
    }

    fn has_flag(self, name: String) -> bool {
        self.flags.contains(name)
    }
}

impl App {
    // native: parses CLI args and dispatches to handler
    native fn run(self) -> Result<()>
}
