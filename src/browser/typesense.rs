//! Typesense search client for HackTheCart product search.
//!
//! Wraps the Typesense HTTP API to manage collections, index product
//! documents, and execute faceted search queries with typo tolerance.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Errors returned by the Typesense client.
#[derive(Debug)]
pub enum Error {
    Http(String),
    Api { status: u16, body: String },
    Serde(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Http(e) => write!(f, "http error: {e}"),
            Error::Api { status, body } => write!(f, "typesense api error {status}: {body}"),
            Error::Serde(e) => write!(f, "serde error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.to_string())
    }
}

/// Typesense client wrapper.
pub struct TypesenseClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Collection {
    pub name: String,
    pub fields: Vec<Field>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_sorting_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_nested_fields: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facet: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProductDocument {
    pub id: String,
    pub name: String,
    pub brand: String,
    pub category: String,
    pub size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    pub current_min_price_cents: i64,
    pub current_max_price_cents: i64,
    pub store_count: i32,
    pub popularity_score: f32,
    pub is_on_sale: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nutri_score: Option<String>,
    pub snap_eligible: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SearchParams {
    pub q: String,
    pub query_by: Vec<String>,
    pub filter_by: Option<String>,
    pub sort_by: Option<String>,
    pub facet_by: Option<Vec<String>>,
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    pub highlight_full_fields: Option<Vec<String>>,
    pub typo_tokens_threshold: Option<i32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SearchResult {
    pub found: i64,
    #[serde(default)]
    pub hits: Vec<Hit>,
    #[serde(default, rename = "facet_counts")]
    pub facet_counts: Vec<FacetCount>,
    #[serde(default)]
    pub search_time_ms: i64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Hit {
    pub document: ProductDocument,
    #[serde(default)]
    pub highlights: Vec<Highlight>,
    #[serde(default)]
    pub text_match: f64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Highlight {
    #[serde(default)]
    pub field: String,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub matched_tokens: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FacetCount {
    #[serde(default)]
    pub field_name: String,
    #[serde(default)]
    pub counts: Vec<FacetValue>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FacetValue {
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub count: i64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BulkResult {
    pub success: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

impl TypesenseClient {
    pub fn new(base_url: &str, api_key: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            http: reqwest::Client::new(),
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .header("X-TYPESENSE-API-KEY", &self.api_key)
    }

    async fn check(resp: reqwest::Response) -> Result<reqwest::Response, Error> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(Error::Api { status, body })
        }
    }

    pub async fn create_collection(&self, collection: &Collection) -> Result<(), Error> {
        let resp = self
            .req(reqwest::Method::POST, "/collections")
            .json(collection)
            .send()
            .await?;
        Self::check(resp).await?;
        Ok(())
    }

    pub async fn delete_collection(&self, name: &str) -> Result<(), Error> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/collections/{name}"))
            .send()
            .await?;
        Self::check(resp).await?;
        Ok(())
    }

    pub async fn index_document(
        &self,
        collection: &str,
        doc: &ProductDocument,
    ) -> Result<(), Error> {
        let resp = self
            .req(
                reqwest::Method::POST,
                &format!("/collections/{collection}/documents?action=upsert"),
            )
            .json(doc)
            .send()
            .await?;
        Self::check(resp).await?;
        Ok(())
    }

    pub async fn index_bulk(
        &self,
        collection: &str,
        docs: &[ProductDocument],
    ) -> Result<BulkResult, Error> {
        let mut body = String::new();
        for d in docs {
            body.push_str(&serde_json::to_string(d)?);
            body.push('\n');
        }
        let resp = self
            .req(
                reqwest::Method::POST,
                &format!("/collections/{collection}/documents/import?action=upsert"),
            )
            .header("Content-Type", "text/plain")
            .body(body)
            .send()
            .await?;
        let resp = Self::check(resp).await?;
        let text = resp.text().await.unwrap_or_default();
        let mut success = 0;
        let mut failed = 0;
        let mut errors = Vec::new();
        for line in text.lines() {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("success").and_then(|x| x.as_bool()).unwrap_or(false) {
                success += 1;
            } else {
                failed += 1;
                if let Some(e) = v.get("error").and_then(|x| x.as_str()) {
                    errors.push(e.to_string());
                }
            }
        }
        Ok(BulkResult {
            success,
            failed,
            errors,
        })
    }

    pub async fn delete_document(&self, collection: &str, id: &str) -> Result<(), Error> {
        let resp = self
            .req(
                reqwest::Method::DELETE,
                &format!("/collections/{collection}/documents/{id}"),
            )
            .send()
            .await?;
        Self::check(resp).await?;
        Ok(())
    }

    fn build_query(params: &SearchParams) -> Vec<(String, String)> {
        let mut q = vec![
            ("q".to_string(), params.q.clone()),
            ("query_by".to_string(), params.query_by.join(",")),
        ];
        if let Some(v) = &params.filter_by {
            q.push(("filter_by".into(), v.clone()));
        }
        if let Some(v) = &params.sort_by {
            q.push(("sort_by".into(), v.clone()));
        }
        if let Some(v) = &params.facet_by {
            q.push(("facet_by".into(), v.join(",")));
        }
        if let Some(v) = params.page {
            q.push(("page".into(), v.to_string()));
        }
        if let Some(v) = params.per_page {
            q.push(("per_page".into(), v.to_string()));
        }
        if let Some(v) = &params.highlight_full_fields {
            q.push(("highlight_full_fields".into(), v.join(",")));
        }
        if let Some(v) = params.typo_tokens_threshold {
            q.push(("typo_tokens_threshold".into(), v.to_string()));
        }
        q
    }

    pub async fn search(
        &self,
        collection: &str,
        params: &SearchParams,
    ) -> Result<SearchResult, Error> {
        let query = Self::build_query(params);
        let resp = self
            .req(
                reqwest::Method::GET,
                &format!("/collections/{collection}/documents/search"),
            )
            .query(&query)
            .send()
            .await?;
        let resp = Self::check(resp).await?;
        let result: SearchResult = resp.json().await?;
        Ok(result)
    }

    pub async fn multi_search(
        &self,
        collection: &str,
        queries: &[SearchParams],
    ) -> Result<Vec<SearchResult>, Error> {
        #[derive(Serialize)]
        struct MultiSearchBody<'a> {
            searches: Vec<serde_json::Value>,
            #[serde(skip)]
            _m: std::marker::PhantomData<&'a ()>,
        }

        let searches: Vec<serde_json::Value> = queries
            .iter()
            .map(|p| {
                let mut obj = serde_json::Map::new();
                obj.insert("collection".into(), serde_json::Value::String(collection.into()));
                for (k, v) in Self::build_query(p) {
                    obj.insert(k, serde_json::Value::String(v));
                }
                serde_json::Value::Object(obj)
            })
            .collect();

        let body = serde_json::json!({ "searches": searches });
        let resp = self
            .req(reqwest::Method::POST, "/multi_search")
            .json(&body)
            .send()
            .await?;
        let resp = Self::check(resp).await?;
        let v: serde_json::Value = resp.json().await?;
        let results = v
            .get("results")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for r in results {
            let sr: SearchResult = serde_json::from_value(r)?;
            out.push(sr);
        }
        Ok(out)
    }

    /// Create the HackTheCart products collection schema.
    pub fn products_schema() -> Collection {
        Collection {
            name: "products".into(),
            fields: vec![
                Field { name: "id".into(), field_type: "string".into(), facet: None, optional: None, sort: None, index: None },
                Field { name: "name".into(), field_type: "string".into(), facet: Some(false), optional: None, sort: Some(true), index: Some(true) },
                Field { name: "brand".into(), field_type: "string".into(), facet: Some(true), optional: None, sort: None, index: Some(true) },
                Field { name: "category".into(), field_type: "string".into(), facet: Some(true), optional: None, sort: None, index: Some(true) },
                Field { name: "size".into(), field_type: "string".into(), facet: Some(false), optional: None, sort: None, index: Some(false) },
                Field { name: "upc".into(), field_type: "string".into(), facet: Some(false), optional: Some(true), sort: None, index: Some(true) },
                Field { name: "image_url".into(), field_type: "string".into(), facet: Some(false), optional: Some(true), sort: None, index: Some(false) },
                Field { name: "current_min_price_cents".into(), field_type: "int64".into(), facet: Some(true), optional: None, sort: Some(true), index: None },
                Field { name: "current_max_price_cents".into(), field_type: "int64".into(), facet: Some(true), optional: None, sort: Some(true), index: None },
                Field { name: "store_count".into(), field_type: "int32".into(), facet: Some(true), optional: None, sort: Some(true), index: None },
                Field { name: "popularity_score".into(), field_type: "float".into(), facet: Some(false), optional: None, sort: Some(true), index: None },
                Field { name: "is_on_sale".into(), field_type: "bool".into(), facet: Some(true), optional: None, sort: Some(true), index: None },
                Field { name: "nutri_score".into(), field_type: "string".into(), facet: Some(true), optional: Some(true), sort: None, index: None },
                Field { name: "snap_eligible".into(), field_type: "bool".into(), facet: Some(true), optional: None, sort: None, index: None },
                Field { name: "tags".into(), field_type: "string[]".into(), facet: Some(true), optional: None, sort: None, index: Some(true) },
            ],
            default_sorting_field: Some("popularity_score".into()),
            enable_nested_fields: Some(false),
        }
    }
}
