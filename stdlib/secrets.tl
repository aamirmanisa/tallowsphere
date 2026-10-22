// tallow.secrets — API key manager and secrets store.
//
// Persistent key-value store for API keys, tokens, and credentials
// discovered during reconnaissance. Backed by JSON on disk.

struct SecretStore {
    path: String,
    count: Int,
    keys: []String,
}

// Open or create a secrets store at the given file path
fn SecretStore.open(path: String) -> SecretStore

// Store a key-value pair. Automatically saves to disk.
fn SecretStore.set(self, key: String, value: String) -> SecretStore

// Retrieve a value by key. Returns nil if not found.
fn SecretStore.get(self, key: String) -> String?

// Delete a key. Automatically saves to disk.
fn SecretStore.delete(self, key: String) -> SecretStore

// List all stored keys (values are hidden)
fn SecretStore.list(self) -> []String

// Export all secrets as a Map (keys and values)
fn SecretStore.export(self) -> Map<String, String>
