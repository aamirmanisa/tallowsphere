// tallow.api — offline API-surface ingestion and comparison (N13/N14/N20/N21).
//
// Nothing here opens a socket, resolves a name, or reads a clock. Every document,
// schema and inventory is bytes or structs the caller supplied; a caller that
// wants a fresh one fetches it itself, under its own grant, and hands it here.
//
// N13 — a document URL is part of the finding.
//
// `openapi_load` parses a 2.0 (swagger) or 3.x document into an endpoint
// inventory. Every endpoint carries `source`, the `doc_url` it was parsed from;
// an empty `doc_url` is refused with `api:openapi-no-evidence`, because "the API
// has this endpoint" is a claim and "<url> states this endpoint" is evidence.
//
// The version is detected, never assumed. `swagger: "2.0"` and `openapi:
// "3.0.x"`/`"3.1.x"` are read; anything else — including a document carrying
// neither field — is refused with `api:openapi-version-unsupported`, naming what
// it saw. A templated path keeps its template (`/users/{id}`), never a filled-in
// value.
//
// Auth is recorded only when declared: a global `security` block applies to
// operations that do not override it, an operation-level `security: []` is
// *declared public* and renders "none", and no security block at all renders
// nil. Within one requirement scheme names are conjunctive ("a+b"); array
// members are alternatives ("a | b"). Request media types are a sorted,
// comma-joined set.

// One endpoint as stated by a document. `source` is that document's URL — a row
// without it is not evidence, and `openapi_load` will not produce one.
struct ApiEndpoint {
    method:       String,
    path:         String,
    auth:         String?,
    content_type: String?,
    source:       String,
}

// The inventory, with its own provenance: `doc_url` is the document every row's
// `source` came from, and `count` is the number of endpoints in it.
struct ApiInventory {
    doc_url:         String,
    openapi_version: String,
    count:           Int,
    endpoints:       []ApiEndpoint,
}

// Parse an OpenAPI 2.0 or 3.x document (JSON text) into an inventory. `doc_url`
// is the URL the caller fetched the text from, and it becomes the evidence on
// every endpoint. Refuses `api:openapi-version-unsupported`,
// `api:openapi-malformed`, `api:openapi-ref-unsupported` (a path item that is a
// `$ref` — this module resolves no references) and `api:openapi-no-evidence`.
native fn api.openapi_load(doc_json: String, doc_url: String) -> ApiInventory

// Render the inventory as `tallow.api.inventory.v1` JSON: the document URL, the
// version, the count, and one object per endpoint carrying `source`.
native fn api.endpoints_json(inventory: ApiInventory) -> String

// Build one endpoint by hand — for a caller assembling an inventory from
// something that is not an OpenAPI document. `method` is upper-cased.
native fn api.endpoint(method: String, path: String, auth: String?, content_type: String?, source: String) -> ApiEndpoint

// Build an inventory from endpoints the caller already holds. Endpoints are
// sorted by `(path, method)`, so the same input renders byte-identically.
native fn api.inventory(doc_url: String, openapi_version: String, endpoints: []ApiEndpoint) -> ApiInventory
