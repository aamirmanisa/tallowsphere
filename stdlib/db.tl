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
// native: opens connection pool
native fn connect(url: String) -> Result<Connection>

/// Query result row
struct Row {
    columns: Map<String, Value>,
}

impl Connection {
    /// Execute a query and return rows
    // native: executes parameterized query
    native fn query(self, sql: String, params: []Value) -> Result<[]Row>

    /// Execute a query returning a single row
    // native: executes query, expects exactly one row
    native fn query_one(self, sql: String, params: []Value) -> Result<Row>

    /// Execute a statement (INSERT, UPDATE, DELETE) returning affected rows
    // native: executes parameterized statement
    native fn execute(self, sql: String, params: []Value) -> Result<u64>

    /// Begin a transaction
    // native: starts transaction
    native fn begin(self) -> Result<Transaction>

    /// Close the connection
    // native: closes connection pool
    native fn close(self) -> Result<()>

    /// Check connection health
    // native: pings database
    native fn ping(self) -> Result<()>
}

/// Database transaction
struct Transaction {
    conn: Connection,
}

impl Transaction {
    // native: query within transaction
    native fn query(self, sql: String, params: []Value) -> Result<[]Row>

    // native: execute within transaction
    native fn execute(self, sql: String, params: []Value) -> Result<u64>

    // native: commits transaction
    native fn commit(self) -> Result<()>

    // native: rolls back transaction
    native fn rollback(self) -> Result<()>
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
    // native: gets column as string
    native fn get_string(self, col: String) -> Result<String>

    // native: gets column as i64
    native fn get_i64(self, col: String) -> Result<i64>

    // native: gets column as f64
    native fn get_f64(self, col: String) -> Result<f64>

    // native: gets column as bool
    native fn get_bool(self, col: String) -> Result<bool>
}
