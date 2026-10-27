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

// ── N14: GraphQL SDL + introspection diff ─────────────────────────────────
//
// Both capture paths produce the same shape — types → fields → args, with the
// same kind vocabulary (`object`, `interface`, `input`, `enum`, `scalar`,
// `union`) — so a schema captured before a release can be compared with the same
// schema captured after it by a different mechanism.
//
// SDL is read by a small tokenizer, not a regex: GraphQL argument types nest
// (`f(filter: Filter { a: Int }): T`) and a pattern that stops at the first `}`
// truncates the field list silently. Field type text is kept as written
// (`[User!]!`) and compared as text, so `[User]` to `[User!]` is a change rather
// than a normalisation to equality. Refusals carry `api:graphql-parse` (with the
// line of an unterminated string) or `api:graphql-introspection-malformed`.

// One argument of a field. `type_name` is the type as written, including `!` and
// `[]` (`[String!]!`).
struct GraphqlArg {
    name:      String,
    type_name: String,
}

// One field of a type, with its arguments sorted by name. For an enum value,
// `type_name` is "enum" and `args` is empty, on both capture paths.
struct GraphqlField {
    name:      String,
    type_name: String,
    args:      []GraphqlArg,
}

// One type: `kind` is `object`, `interface`, `input`, `enum`, `scalar` or
// `union`. Fields are sorted by name.
struct GraphqlType {
    name:   String,
    kind:   String,
    fields: []GraphqlField,
}

// A parsed schema plus the mechanism that produced it: `origin` is "sdl" or
// "introspection". Both origins render the same `types`, so a diff across them
// is a diff of schemas, not of capture methods.
struct GraphqlSchema {
    origin:     String,
    type_count: Int,
    types:      []GraphqlType,
}

// One side of a type change. A field whose type changed is reported as a removal
// *and* an addition, and again here with both sides named.
struct GraphqlTypeChange {
    type_name: String,
    field:     String,
    old_type:  String,
    new_type:  String,
}

// What changed between two schemas. `removed_fields` is the loud list: a removed
// field is the breaking change. `breaking` is true when anything was removed.
struct GraphqlDiff {
    added_types:   []String,
    removed_types: []String,
    added_fields:  []String,
    removed_fields: []String,
    added_args:    []String,
    removed_args:  []String,
    type_changes:  []GraphqlTypeChange,
    breaking:      Bool,
}

// Parse GraphQL SDL text. Descriptions, comments and directives are skipped;
// `extend type` merges into the type rather than replacing it.
native fn api.graphql_from_sdl(text: String) -> GraphqlSchema

// Parse an introspection response — `{data:{__schema:{...}}}` or a bare
// `{__schema:{...}}`. `__`-prefixed meta-types are skipped: they are the
// introspection mechanism, not the schema under test.
native fn api.graphql_from_introspection(json: String) -> GraphqlSchema

// Compare two schemas. A changed field type appears in `removed_fields`,
// `added_fields` and `type_changes`; same for a changed argument type, named
// `Type.field(arg)`.
native fn api.graphql_diff(old_schema: GraphqlSchema, new_schema: GraphqlSchema) -> GraphqlDiff

// ── N20: object ids in paths ──────────────────────────────────────────────

// One exposure *signal* — never a finding. `signal` is always
// "object-id-in-path", `segment` is the literal path segment that matched, and
// `index` is its 0-based position among the path's non-empty segments.
struct ApiPathSignal {
    signal:  String,
    method:  String,
    path:    String,
    segment: String,
    index:   Int,
    kind:    String,   // "numeric" or "uuid"
}

// Flag endpoints whose path carries a literal numeric segment or a UUID-shaped
// segment. Sorted by (path, method, index), so the same input always renders the
// same order.
//
// This is an exposure signal, not a finding: an id in a path is ordinary REST
// design, and whether it is an authorization defect depends on a request that
// has not been made. Nothing here says "vulnerable", "BOLA" or "IDOR". A
// templated segment (`{id}`) carries no value and is not flagged — the template
// is the safe shape, a filled-in value is the one worth a second look. The UUID
// test is the canonical 8-4-4-4-12 shape, case-insensitive; it checks shape
// only, not the RFC 4122 version nibble, so a nil UUID also flags.
native fn api.identifiers(endpoints: []ApiEndpoint) -> []ApiPathSignal
