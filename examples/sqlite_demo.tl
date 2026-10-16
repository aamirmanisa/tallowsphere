// Tallow SQLite Database Demo
// Demonstrates embedded SQLite with full CRUD operations

fn main() {
    // Open in-memory database (no file needed)
    let db = db.memory()
    print("Connected to SQLite (in-memory)")

    // Create table
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT, age INTEGER)")
    print("Created users table")

    // Insert rows
    db.execute("INSERT INTO users (name, email, age) VALUES (?, ?, ?)", "Alice", "alice@example.com", "30")
    db.execute("INSERT INTO users (name, email, age) VALUES (?, ?, ?)", "Bob", "bob@example.com", "25")
    db.execute("INSERT INTO users (name, email, age) VALUES (?, ?, ?)", "Charlie", "charlie@example.com", "35")
    print("Inserted 3 users")

    // Query all rows
    let rows = db.query("SELECT id, name, age FROM users ORDER BY name") match {
        Ok(r) -> r
        Err(e) -> { print("Query failed: {e}"); [] }
    }

    print("")
    print("All users ({rows.len} rows):")
    print("─────────────────────────────")
    rows.each { row: Row ->
        print("  [{row.id}] {row.name}, age {row.age}")
    }

    // Query single row
    let alice = db.query_row("SELECT name, email FROM users WHERE name = ?", "Alice") match {
        Ok(r) -> r
        Err(e) -> { print("Not found: {e}"); nil }
    }
    print("")
    print("Found: {alice.name} ({alice.email})")

    // Update
    let updated = db.execute("UPDATE users SET age = ? WHERE name = ?", "31", "Alice") match {
        Ok(v) -> v
        Err(e) -> 0
    }
    print("Updated {updated} row(s)")

    // Delete
    let deleted = db.execute("DELETE FROM users WHERE name = ?", "Bob") match {
        Ok(v) -> v
        Err(e) -> 0
    }
    print("Deleted {deleted} row(s)")

    // Verify final state
    let final_rows = db.query("SELECT name, age FROM users ORDER BY name") match {
        Ok(r) -> r
        Err(e) -> []
    }
    print("")
    print("Final state ({final_rows.len} users):")
    final_rows.each { row: Row ->
        print("  {row.name}, age {row.age}")
    }

    db.close()
    print("")
    print("Database closed.")
}
