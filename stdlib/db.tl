// tallow.db — Database connections
//
// REGISTERED (FIX13, 2026-08-27): src/stdlib/db.rs is now a registered
// dispatch module. db.connect / db.open / db.memory continue to be served by
// the interpreter's inline handlers (they open real SQLite connections);
// db.sqlite / db.sqlite_memory return an honest "db bridge requires interp
// support" error until interp.rs exposes a DbConn accessor/constructor.
//
// Unified interface for PostgreSQL, SQLite, and Redis.
// All write operations require can_store in agent context.

/// Database connection
struct Connection {
    url:     String,
    driver:  Driver,
    pool_sz: u32 = 10,
}

/// Supported database drivers
enum Driver {
    Postgres,
    SQLite,
    Redis,
}

/// Connect to a database
fn connect(url: String) -> Result<Connection> {
    // native: opens connection pool
}

/// Query result row
struct Row {
    columns: Map<String, Value>,
}

impl Connection {
    /// Execute a query and return rows
    fn query(self, sql: String, params: []Value) -> Result<[]Row> {
        // native: executes parameterized query
    }

    /// Execute a query returning a single row
    fn query_one(self, sql: String, params: []Value) -> Result<Row> {
        // native: executes query, expects exactly one row
    }

    /// Execute a statement (INSERT, UPDATE, DELETE) returning affected rows
    fn execute(self, sql: String, params: []Value) -> Result<u64> {
        // native: executes parameterized statement
    }

    /// Begin a transaction
    fn begin(self) -> Result<Transaction> {
        // native: starts transaction
    }

    /// Close the connection
    fn close(self) -> Result<()> {
        // native: closes connection pool
    }

    /// Check connection health
    fn ping(self) -> Result<()> {
        // native: pings database
    }
}

/// Database transaction
struct Transaction {
    conn: Connection,
}

impl Transaction {
    fn query(self, sql: String, params: []Value) -> Result<[]Row> {
        // native: query within transaction
    }

    fn execute(self, sql: String, params: []Value) -> Result<u64> {
        // native: execute within transaction
    }

    fn commit(self) -> Result<()> {
        // native: commits transaction
    }

    fn rollback(self) -> Result<()> {
        // native: rolls back transaction
    }
}

/// SQLite-specific: open file database
fn sqlite(path: String) -> Result<Connection> {
    connect("sqlite://" + path)
}

/// SQLite-specific: in-memory database
fn sqlite_memory() -> Result<Connection> {
    connect("sqlite://:memory:")
}

/// Row helper methods
impl Row {
    fn get_string(self, col: String) -> Result<String> {
        // native: gets column as string
    }

    fn get_i64(self, col: String) -> Result<i64> {
        // native: gets column as i64
    }

    fn get_f64(self, col: String) -> Result<f64> {
        // native: gets column as f64
    }

    fn get_bool(self, col: String) -> Result<bool> {
        // native: gets column as bool
    }
}
