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

// ── N21: snapshot diff ────────────────────────────────────────────────────

// One changed field of a matched endpoint. `field` is "auth" or "content_type";
// `before` and `after` are the two classes, and nil means "not declared" (which
// is a different fact from "declared to require nothing", which renders "none").
struct ApiEndpointChange {
    method: String,
    path:   String,
    field:  String,
    before: String?,
    after:  String?,
}

// What changed between two snapshots. `removed` is the loud list; `breaking` is
// true when anything was removed or any auth class changed — a content-type
// change is reported but is not breaking on its own. `summary` renders the
// counts as one line. Matching is by (path template, method), so document order
// is not information and a reordered document is not a diff.
struct ApiInventoryDiff {
    doc_url_old:          String,
    doc_url_new:          String,
    added:                []ApiEndpoint,
    removed:              []ApiEndpoint,
    auth_changed:         []ApiEndpointChange,
    content_type_changed: []ApiEndpointChange,
    added_count:          Int,
    removed_count:        Int,
    unchanged:            Int,
    breaking:             Bool,
    summary:              String,
}

// Compare two inventories. Removal is the loud case; every entry names what
// changed and both sides.
native fn api.diff(old_inventory: ApiInventory, new_inventory: ApiInventory) -> ApiInventoryDiff

// ── N16: JS bundle route recovery ────────────────────────────────────────
//
// A bundle is read as TEXT. Nothing is evaluated: no eval, no Function, no
// DOM, no engine. A route is a claim about a file, so every record names the
// text it was read from (`source_url`) and where in it (`offset`, a byte
// offset to the opening quote).
//
// Recovered constructs: path-shaped string literals, template literals (whose
// `${...}` segments render as `{}` with `interpolated` true — the value is
// never read), and the first argument of `fetch(...)`, `axios.get|post|...`
// and `$.ajax({url: ...})`, which is named in `recovered_from`. A route built
// by concatenation is `partial` and carries the fragment that was actually
// seen: completing it would be inventing bytes the bundle does not contain.

// One recovered route. `route` is the path (`{}` for an interpolated
// segment). `recovered_from` is `string-literal`, `template-literal`,
// `fetch`, `axios.<method>` or `jquery.ajax`. A `partial` record holds only
// the `fragment` the scanner saw.
struct BundleRoute {
    route:          String,
    kind:           String,   // "literal" | "template"
    recovered_from: String,
    interpolated:   Bool,
    partial:        Bool,
    fragment:       String?,  // set exactly when `partial`
    source_url:     String,   // the bundle, or the map source that was used
    offset:         Int,      // byte offset into `source_url`'s text
    line:           Int,      // 1-based line in that same text
    map_applied:    Bool,
}

// One bundle read. `map_mode` is "bundle" (no map), "sources-content" (a map
// was applied) or "fallback" (a map was supplied but carried no text — the
// records are then bundle-derived and every one has `map_applied` false).
// `skipped_unlocated` counts path-shaped fragments that could not be cited;
// `skipped_non_route` counts strings that were file paths, not routes.
struct BundleScan {
    bundle_url:        String,
    map_mode:          String,
    map_applied:       Bool,
    map_reason:        String?,
    count:             Int,
    skipped_unlocated: Int,
    skipped_non_route: Int,
    routes:            []BundleRoute,
}

// Recover routes from a JavaScript bundle (N16). Refuses `api:bundle-not-js`
// when the first bytes are HTML — a page saved as `.js` — and
// `api:bundle-no-evidence` when `bundle_url` is empty.
native fn api.bundle_routes(source: String, bundle_url: String) -> BundleScan

// Recover routes using a v3 sourcemap (N17). With `sourcesContent` present the
// routes come from the ORIGINAL files: `source_url` is the map's source name
// and `offset`/`line` are positions in that file, and `map_applied` is true.
// Without it, the result falls back to the bundle text and says so —
// `map_mode` "fallback", `map_applied` false, `map_reason` naming what was
// missing. A map that is present but does not parse is refused with
// `api:sourcemap-unparsable` and the byte offset where parsing stopped.
//
// `mappings` is NOT decoded: no VLQ. Positions come from `sourcesContent`
// directly, which needs no mappings, and `map_reason` says so on every applied
// map. No decoded mapping is claimed.
native fn api.bundle_routes_with_map(source: String, bundle_url: String, sourcemap_json: String) -> BundleScan

// Render a scan as `tallow.api.bundle_routes.v1` JSON: the map state, the
// counts, and one object per route carrying `source_url`, `offset` and `line`.
native fn api.bundle_routes_json(scan: BundleScan) -> String

// Build one route record by hand. Argument order: route, kind, recovered_from,
// source_url, offset, line, interpolated, partial, fragment, map_applied.
native fn api.bundle_route(route: String, kind: String, recovered_from: String, source_url: String, offset: Int, line: Int, interpolated: Bool, partial: Bool, fragment: String?, map_applied: Bool) -> BundleRoute

// Build a scan from routes the caller holds. `count` is the number of routes,
// so it is not an argument; routes are sorted by (source_url, offset).
native fn api.bundle_scan(bundle_url: String, map_mode: String, map_applied: Bool, map_reason: String?, skipped_unlocated: Int, skipped_non_route: Int, routes: []BundleRoute) -> BundleScan
