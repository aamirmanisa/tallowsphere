//! Intelligence-grade data architecture for Tallow.
//!
//! Implements patterns from NSA XKeyscore (federated collection),
//! GCHQ Gaffer (graph entities), NSA Accumulo (cell-level access),
//! and Palantir (provenance tracking).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Security classification for individual data fields.
/// Based on NSA Accumulo's cell-level security labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Classification {
    /// Public data — can be displayed, logged, exported freely.
    Public,
    /// Personal data — GDPR Article 6 applies, requires legal basis.
    Personal,
    /// Sensitive personal — GDPR Article 9, health/biometric/racial.
    SensitivePersonal,
    /// Secret — credentials, API keys, tokens. Never log or export.
    Secret,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Classification::Public => write!(f, "PUBLIC"),
            Classification::Personal => write!(f, "PERSONAL"),
            Classification::SensitivePersonal => write!(f, "SENSITIVE"),
            Classification::Secret => write!(f, "SECRET"),
        }
    }
}

/// A single field with classification and provenance.
/// Every piece of scraped data carries its classification and origin.
#[derive(Debug, Clone)]
pub struct ClassifiedField {
    /// The actual value
    pub value: String,
    /// Security classification
    pub classification: Classification,
    /// Where this data came from
    pub provenance: ProvenanceRecord,
}

/// Provenance record: tracks where data came from and how it was transformed.
/// Based on Palantir's provenance tracking architecture.
#[derive(Debug, Clone)]
pub struct ProvenanceRecord {
    /// Source URL where the data was fetched
    pub source_url: String,
    /// Timestamp of collection (Unix seconds)
    pub collected_at: u64,
    /// The scraper/tool that collected it
    pub collector: String,
    /// Legal basis for collection (maps to @legal annotation)
    pub legal_basis: String,
    /// Chain of transformations applied
    pub transformations: Vec<String>,
    /// Hash of the original raw data (for integrity verification)
    pub source_hash: String,
}

impl ProvenanceRecord {
    /// Create a new provenance record for freshly scraped data.
    pub fn new(source_url: &str, collector: &str, legal_basis: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            source_url: source_url.to_string(),
            collected_at: now,
            collector: collector.to_string(),
            legal_basis: legal_basis.to_string(),
            transformations: Vec::new(),
            source_hash: String::new(),
        }
    }

    /// Record a transformation applied to the data.
    pub fn add_transformation(&mut self, desc: &str) {
        self.transformations.push(format!(
            "[{}] {}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            desc
        ));
    }
}

/// Entity in the graph: a product, store, brand, or price observation.
/// Based on GCHQ Gaffer's entity model.
#[derive(Debug, Clone)]
pub struct Entity {
    /// Unique entity ID
    pub id: String,
    /// Entity type (product, store, brand, price, category)
    pub entity_type: String,
    /// Classified properties
    pub properties: HashMap<String, ClassifiedField>,
    /// Relationships to other entities (edge_type -> target_id)
    pub edges: Vec<Edge>,
    /// When this entity was first seen
    pub first_seen: u64,
    /// When this entity was last updated
    pub last_updated: u64,
}

/// Edge connecting two entities in the graph.
#[derive(Debug, Clone)]
pub struct Edge {
    /// Type of relationship (e.g., "sold_at", "made_by", "in_category")
    pub edge_type: String,
    /// Target entity ID
    pub target_id: String,
    /// Optional properties on the edge (e.g., price, date)
    pub properties: HashMap<String, String>,
}

/// Entity graph: tracks relationships between scraped entities.
pub struct EntityGraph {
    entities: HashMap<String, Entity>,
    total_entities: AtomicU64,
    total_edges: AtomicU64,
}

impl EntityGraph {
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            total_entities: AtomicU64::new(0),
            total_edges: AtomicU64::new(0),
        }
    }

    /// Add or update an entity.
    pub fn upsert(&mut self, entity: Entity) {
        let is_new = !self.entities.contains_key(&entity.id);
        if is_new {
            self.total_entities.fetch_add(1, Ordering::Relaxed);
        }
        self.total_edges
            .fetch_add(entity.edges.len() as u64, Ordering::Relaxed);
        self.entities.insert(entity.id.clone(), entity);
    }

    /// Get an entity by ID.
    pub fn get(&self, id: &str) -> Option<&Entity> {
        self.entities.get(id)
    }

    /// Find all entities of a given type.
    pub fn find_by_type(&self, entity_type: &str) -> Vec<&Entity> {
        self.entities
            .values()
            .filter(|e| e.entity_type == entity_type)
            .collect()
    }

    /// Find entities connected to a given entity.
    pub fn neighbors(&self, id: &str) -> Vec<(&str, &Entity)> {
        let entity = match self.entities.get(id) {
            Some(e) => e,
            None => return Vec::new(),
        };
        entity
            .edges
            .iter()
            .filter_map(|edge| {
                self.entities
                    .get(&edge.target_id)
                    .map(|target| (edge.edge_type.as_str(), target))
            })
            .collect()
    }

    /// Total entities in the graph.
    pub fn entity_count(&self) -> u64 {
        self.total_entities.load(Ordering::Relaxed)
    }

    /// Total edges in the graph.
    pub fn edge_count(&self) -> u64 {
        self.total_edges.load(Ordering::Relaxed)
    }
}

/// Federated scraping node: one node in a distributed collection network.
/// Based on NSA XKeyscore's distributed architecture.
#[derive(Debug, Clone)]
pub struct ScrapingNode {
    /// Node identifier
    pub id: String,
    /// Node endpoint (e.g., SSH tunnel, cloud function URL)
    pub endpoint: String,
    /// Geographic region
    pub region: String,
    /// Whether this node is currently healthy
    pub healthy: bool,
    /// Total requests processed by this node
    pub requests_processed: u64,
    /// Average latency in milliseconds
    pub avg_latency_ms: u64,
}

/// Federated scraping coordinator.
/// Dispatches requests to multiple nodes, merges results.
pub struct FederatedScraper {
    nodes: Vec<ScrapingNode>,
    /// Round-robin counter
    counter: AtomicU64,
}

impl FederatedScraper {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            counter: AtomicU64::new(0),
        }
    }

    /// Add a scraping node.
    pub fn add_node(&mut self, node: ScrapingNode) {
        self.nodes.push(node);
    }

    /// Get the next healthy node for dispatching a request.
    pub fn next_node(&self) -> Option<&ScrapingNode> {
        let healthy: Vec<_> = self.nodes.iter().filter(|n| n.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % healthy.len();
        Some(healthy[idx])
    }

    /// Number of healthy nodes.
    pub fn healthy_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.healthy).count()
    }

    /// Total nodes.
    pub fn total_nodes(&self) -> usize {
        self.nodes.len()
    }
}

/// Scraper plugin interface.
/// Based on SpiderFoot's modular OSINT architecture.
/// Each store/source gets its own plugin with specific extraction logic.
pub trait ScraperPlugin: Send + Sync {
    /// Plugin name (e.g., "target", "heb", "kroger")
    fn name(&self) -> &str;

    /// Domains this plugin handles
    fn domains(&self) -> &[&str];

    /// Extract product data from raw HTML or JSON
    fn extract(&self, url: &str, body: &str) -> Vec<Entity>;

    /// Generate search URLs for product discovery
    fn search_urls(&self, query: &str) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_display() {
        assert_eq!(format!("{}", Classification::Public), "PUBLIC");
        assert_eq!(format!("{}", Classification::Secret), "SECRET");
    }

    #[test]
    fn test_provenance_record() {
        let mut pr = ProvenanceRecord::new("https://example.com", "tallow", "public_data");
        assert_eq!(pr.source_url, "https://example.com");
        pr.add_transformation("parsed HTML");
        assert_eq!(pr.transformations.len(), 1);
    }

    #[test]
    fn test_entity_graph() {
        let mut graph = EntityGraph::new();
        let entity = Entity {
            id: "product-123".into(),
            entity_type: "product".into(),
            properties: HashMap::new(),
            edges: vec![Edge {
                edge_type: "sold_at".into(),
                target_id: "store-heb".into(),
                properties: HashMap::new(),
            }],
            first_seen: 0,
            last_updated: 0,
        };
        graph.upsert(entity);
        assert_eq!(graph.entity_count(), 1);
        assert!(graph.get("product-123").is_some());
    }

    #[test]
    fn test_federated_scraper() {
        let mut fed = FederatedScraper::new();
        fed.add_node(ScrapingNode {
            id: "node-1".into(),
            endpoint: "socks5://1.2.3.4:1080".into(),
            region: "us-east".into(),
            healthy: true,
            requests_processed: 0,
            avg_latency_ms: 50,
        });
        assert_eq!(fed.healthy_count(), 1);
        assert!(fed.next_node().is_some());
    }

    #[test]
    fn test_classified_field() {
        let field = ClassifiedField {
            value: "secret-key-123".into(),
            classification: Classification::Secret,
            provenance: ProvenanceRecord::new("https://api.com", "tallow", "contract"),
        };
        assert_eq!(field.classification, Classification::Secret);
    }
}
