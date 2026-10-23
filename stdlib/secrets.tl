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
native fn SecretStore.open(path: String) -> SecretStore

// Store a key-value pair. Automatically saves to disk.
native fn SecretStore.set(self, key: String, value: String) -> SecretStore

// Retrieve a value by key. Returns nil if not found.
native fn SecretStore.get(self, key: String) -> String?

// Delete a key. Automatically saves to disk.
native fn SecretStore.delete(self, key: String) -> SecretStore

// List all stored keys (values are hidden)
native fn SecretStore.list(self) -> []String

// Export all secrets as a Map (keys and values)
native fn SecretStore.export(self) -> Map<String, String>
