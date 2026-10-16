//! Dead Letter Queue with Response Body (T3.21)
//!
//! Captures permanently failed scraping jobs with enough context to
//! diagnose the failure: response body snippet, headers, classified reason.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FailureCategory {
    NetworkError,
    Timeout,
    RateLimited,
    Blocked,
    CaptchaChallenge,
    SelectorBreak,
    ValidationFail,
    ServerError,
    Unknown,
}

impl FailureCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NetworkError => "NetworkError",
            Self::Timeout => "Timeout",
            Self::RateLimited => "RateLimited",
            Self::Blocked => "Blocked",
            Self::CaptchaChallenge => "CaptchaChallenge",
            Self::SelectorBreak => "SelectorBreak",
            Self::ValidationFail => "ValidationFail",
            Self::ServerError => "ServerError",
            Self::Unknown => "Unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "NetworkError" => Self::NetworkError,
            "Timeout" => Self::Timeout,
            "RateLimited" => Self::RateLimited,
            "Blocked" => Self::Blocked,
            "CaptchaChallenge" => Self::CaptchaChallenge,
            "SelectorBreak" => Self::SelectorBreak,
            "ValidationFail" => Self::ValidationFail,
            "ServerError" => Self::ServerError,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeadLetter {
    pub id: String,
    pub job_type: String,
    pub target: String,
    pub url: String,
    pub attempts: u32,
    pub final_error: String,
    pub last_http_status: Option<u16>,
    pub response_body_snippet: String,
    pub response_headers: HashMap<String, String>,
    pub failed_at: i64,
    pub reason_category: FailureCategory,
}

impl DeadLetter {
    fn to_json(&self) -> String {
        let headers = self
            .response_headers
            .iter()
            .map(|(k, v)| format!("{}:{}", js(k), js(v)))
            .collect::<Vec<_>>()
            .join(",");
        let status = self
            .last_http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"id\":{},\"job_type\":{},\"target\":{},\"url\":{},\"attempts\":{},\"final_error\":{},\"last_http_status\":{},\"response_body_snippet\":{},\"response_headers\":{{{}}},\"failed_at\":{},\"reason_category\":\"{}\"}}",
            js(&self.id),
            js(&self.job_type),
            js(&self.target),
            js(&self.url),
            self.attempts,
            js(&self.final_error),
            status,
            js(&self.response_body_snippet),
            headers,
            self.failed_at,
            self.reason_category.as_str()
        )
    }
}

fn js(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone)]
pub struct DlqStats {
    pub total_count: usize,
    pub by_category: HashMap<String, usize>,
    pub by_target: HashMap<String, usize>,
    pub oldest_failed_at: Option<i64>,
}

pub struct DeadLetterQueue {
    entries: Arc<Mutex<VecDeque<DeadLetter>>>,
    max_size: usize,
    #[allow(dead_code)]
    persist_path: Option<String>,
}

impl DeadLetterQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(VecDeque::with_capacity(max_size.min(1024)))),
            max_size,
            persist_path: None,
        }
    }

    pub fn add(&self, entry: DeadLetter) {
        let mut q = self.entries.lock().unwrap();
        while q.len() >= self.max_size {
            q.pop_front();
        }
        q.push_back(entry);
    }

    pub fn list(&self, limit: usize, category: Option<FailureCategory>) -> Vec<DeadLetter> {
        let q = self.entries.lock().unwrap();
        q.iter()
            .rev()
            .filter(|e| match &category {
                Some(c) => &e.reason_category == c,
                None => true,
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn clear(&self, category: Option<FailureCategory>) -> usize {
        let mut q = self.entries.lock().unwrap();
        match category {
            None => {
                let n = q.len();
                q.clear();
                n
            }
            Some(c) => {
                let before = q.len();
                q.retain(|e| e.reason_category != c);
                before - q.len()
            }
        }
    }

    pub fn stats(&self) -> DlqStats {
        let q = self.entries.lock().unwrap();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut by_target: HashMap<String, usize> = HashMap::new();
        let mut oldest: Option<i64> = None;
        for e in q.iter() {
            *by_category.entry(e.reason_category.as_str().to_string()).or_insert(0) += 1;
            *by_target.entry(e.target.clone()).or_insert(0) += 1;
            oldest = Some(match oldest {
                None => e.failed_at,
                Some(v) => v.min(e.failed_at),
            });
        }
        DlqStats {
            total_count: q.len(),
            by_category,
            by_target,
            oldest_failed_at: oldest,
        }
    }

    pub fn classify_error(error: &str, status: Option<u16>, body: &str) -> FailureCategory {
        if let Some(s) = status {
            if s == 429 {
                return FailureCategory::RateLimited;
            }
            if s == 403 {
                let lower = body.to_lowercase();
                if lower.contains("captcha") || lower.contains("verify you are human") || lower.contains("verify") {
                    return FailureCategory::CaptchaChallenge;
                }
                return FailureCategory::Blocked;
            }
            if (500..600).contains(&s) {
                return FailureCategory::ServerError;
            }
        }
        let e = error.to_lowercase();
        if e.contains("timeout") || e.contains("timed out") {
            return FailureCategory::Timeout;
        }
        if e.contains("connection") || e.contains("dns") || e.contains("refused") {
            return FailureCategory::NetworkError;
        }
        if e.contains("empty extraction") || e.contains("no fields") || e.contains("selector") {
            return FailureCategory::SelectorBreak;
        }
        if e.contains("validation") {
            return FailureCategory::ValidationFail;
        }
        FailureCategory::Unknown
    }

    pub fn save_to_disk(&self, path: &str) -> Result<(), String> {
        let q = self.entries.lock().unwrap();
        let mut out = String::from("[");
        for (i, e) in q.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&e.to_json());
        }
        out.push(']');
        fs::write(path, out).map_err(|e| e.to_string())
    }

    pub fn load_from_disk(path: &str) -> Result<Self, String> {
        // Minimal loader: we don't parse everything back — just construct an empty queue
        // with max_size inferred. For robust round-trip, upgrade to serde_json.
        let _ = fs::read_to_string(path).map_err(|e| e.to_string())?;
        Ok(Self::new(10_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(target: &str, cat: FailureCategory) -> DeadLetter {
        DeadLetter {
            id: format!("id-{}", target),
            job_type: "scrape".to_string(),
            target: target.to_string(),
            url: format!("https://{}/p", target),
            attempts: 3,
            final_error: "boom".to_string(),
            last_http_status: Some(500),
            response_body_snippet: "err".to_string(),
            response_headers: HashMap::new(),
            failed_at: 1_000_000,
            reason_category: cat,
        }
    }

    #[test]
    fn classify_by_status() {
        assert_eq!(
            DeadLetterQueue::classify_error("", Some(429), ""),
            FailureCategory::RateLimited
        );
        assert_eq!(
            DeadLetterQueue::classify_error("", Some(403), "please solve captcha"),
            FailureCategory::CaptchaChallenge
        );
        assert_eq!(
            DeadLetterQueue::classify_error("", Some(403), "forbidden"),
            FailureCategory::Blocked
        );
        assert_eq!(
            DeadLetterQueue::classify_error("", Some(503), ""),
            FailureCategory::ServerError
        );
    }

    #[test]
    fn classify_by_error() {
        assert_eq!(
            DeadLetterQueue::classify_error("operation timeout", None, ""),
            FailureCategory::Timeout
        );
        assert_eq!(
            DeadLetterQueue::classify_error("connection refused", None, ""),
            FailureCategory::NetworkError
        );
        assert_eq!(
            DeadLetterQueue::classify_error("empty extraction", None, ""),
            FailureCategory::SelectorBreak
        );
    }

    #[test]
    fn add_and_list() {
        let q = DeadLetterQueue::new(10);
        q.add(mk("a.com", FailureCategory::Blocked));
        q.add(mk("b.com", FailureCategory::Timeout));
        assert_eq!(q.list(10, None).len(), 2);
        assert_eq!(q.list(10, Some(FailureCategory::Timeout)).len(), 1);
    }

    #[test]
    fn bounded_capacity() {
        let q = DeadLetterQueue::new(2);
        q.add(mk("a", FailureCategory::Unknown));
        q.add(mk("b", FailureCategory::Unknown));
        q.add(mk("c", FailureCategory::Unknown));
        assert_eq!(q.stats().total_count, 2);
    }

    #[test]
    fn clear_by_category() {
        let q = DeadLetterQueue::new(10);
        q.add(mk("a", FailureCategory::Blocked));
        q.add(mk("b", FailureCategory::Timeout));
        assert_eq!(q.clear(Some(FailureCategory::Blocked)), 1);
        assert_eq!(q.stats().total_count, 1);
    }
}
