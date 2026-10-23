// Tallow standard library: GraphQL auto-discovery and querying

struct GraphqlEndpoint {
    url: String,
    schema: String?,       // introspection result if available
    queries: []String,     // discovered query templates
}

struct GraphqlResult {
    endpoint: String,
    query: String,
    data: String,          // JSON response
}

/// Detect GraphQL endpoints on a page by inspecting network requests.
native fn graphql_detect(page_url: String) -> []GraphqlEndpoint

/// Run an introspection query against a GraphQL endpoint.
native fn graphql_introspect(endpoint_url: String) -> GraphqlEndpoint

/// Execute a GraphQL query (POST to endpoint).
native fn graphql_query(endpoint_url: String, query: String, variables: Map<String, String>) -> GraphqlResult
