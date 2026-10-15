//! Locator receipts — `locator.scorecard` / `locator.refusal` on the
//! registry's v1 ledger (same format, same chain rules: RECEIPT-FORMAT-v1.md).

use crate::select::{DecisionRecord, Refusal};
use serde_json::{json, Value};
use tallow_registry::receipt::Receipt;

/// Receipt kind for a completed scorecard (a node was chosen).
pub const KIND_SCORECARD: &str = "locator.scorecard";
/// Receipt kind for a fail-close refusal (no compliant node).
pub const KIND_REFUSAL: &str = "locator.refusal";

/// Compact, deterministic scorecard body (top 3 + exclusion accounting).
pub fn scorecard_data(rec: &DecisionRecord) -> Value {
    let top: Vec<Value> = rec
        .ranked
        .iter()
        .take(3)
        .map(|r| {
            json!({
                "id": r.id,
                "country": r.country,
                "price_month_eur": r.price_month_eur,
                "score": r.score,
                "arch": r.arch,
            })
        })
        .collect();
    json!({
        "model": rec.model,
        "class": rec.class.as_str(),
        "considered": rec.considered,
        "compliant": rec.ranked.len(),
        "chosen": rec.chosen.as_ref().map(|c| json!({
            "id": c.id,
            "country": c.country,
            "price_month_eur": c.price_month_eur,
            "score": c.score,
        })),
        "top": top,
        "excluded_by_reason": excluded_map(rec),
    })
}

fn excluded_map(rec: &DecisionRecord) -> Value {
    let mut m = serde_json::Map::new();
    for e in &rec.excluded {
        let k = e.reason.clone();
        let cur = m.get(&k).and_then(Value::as_u64).unwrap_or(0);
        m.insert(k, json!(cur + 1));
    }
    Value::Object(m)
}

/// Refusal body.
pub fn refusal_data(class: &str, considered: usize, refusal: &Refusal) -> Value {
    json!({
        "model": crate::score::MODEL_V,
        "class": class,
        "considered": considered,
        "rule": refusal.rule,
        "excluded_by_reason": refusal.excluded_by_reason,
    })
}

/// Sign a `locator.scorecard` receipt (caller supplies chain position).
pub fn scorecard_receipt(
    seq: u64,
    actor: &str,
    prev: Option<String>,
    key: &ed25519_dalek::SigningKey,
    rec: &DecisionRecord,
) -> Receipt {
    let subject = rec.chosen.as_ref().map(|c| c.id.clone());
    Receipt::sign_new(
        seq,
        KIND_SCORECARD,
        actor,
        subject.as_deref(),
        scorecard_data(rec),
        prev,
        key,
    )
}

/// Sign a `locator.refusal` receipt.
pub fn refusal_receipt(
    seq: u64,
    actor: &str,
    prev: Option<String>,
    key: &ed25519_dalek::SigningKey,
    class: &str,
    considered: usize,
    refusal: &Refusal,
) -> Receipt {
    Receipt::sign_new(
        seq,
        KIND_REFUSAL,
        actor,
        None,
        refusal_data(class, considered, refusal),
        prev,
        key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{JobClass, Offer};
    use crate::score::ScoringModel;
    use crate::select::select;
    use tallow_registry::ledger::Ledger;
    use tallow_registry::receipt::dev_actor_key;

    fn offers() -> Vec<Offer> {
        vec![
            Offer {
                provider: "hetzner".into(),
                plan: "cx22".into(),
                region: "hel1".into(),
                city: "Helsinki".into(),
                country: "FI".into(),
                price_month_eur: 4.35,
                vcpu: 2,
                mem_mb: 4096,
                disk_gb: 40,
                arch: "x86_64".into(),
                source_id: "1".into(),
            },
            Offer {
                provider: "hetzner".into(),
                plan: "cx22".into(),
                region: "ash".into(),
                city: "Ashburn".into(),
                country: "US".into(),
                price_month_eur: 4.99,
                vcpu: 2,
                mem_mb: 4096,
                disk_gb: 40,
                arch: "x86_64".into(),
                source_id: "1".into(),
            },
        ]
    }

    #[test]
    fn signed_scorecard_verifies_and_chains() {
        let key = dev_actor_key();
        let rec = select(&offers(), JobClass::Privacy, &ScoringModel::default()).unwrap();
        let r = scorecard_receipt(1, "locator", None, &key, &rec);
        assert_eq!(r.kind, "locator.scorecard");
        assert!(r.verify(&key.verifying_key()).is_ok());

        // append to a real ledger and re-verify the chain
        let dir = std::env::temp_dir().join(format!("locator-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = Ledger::new(dir.join("receipts.jsonl"));
        ledger.append(&r).unwrap();
        let verdict = ledger.verify(&key.verifying_key());
        assert!(verdict.ok(), "ledger verdict: {verdict:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signed_refusal_verifies() {
        let key = dev_actor_key();
        let us_only = vec![offers().remove(1)];
        let rec = select(&us_only, JobClass::Privacy, &ScoringModel::default()).unwrap();
        let refusal = rec.refusal.as_ref().unwrap();
        let r = refusal_receipt(9, "locator", None, &key, "privacy", rec.considered, refusal);
        assert_eq!(r.kind, "locator.refusal");
        assert!(r.verify(&key.verifying_key()).is_ok());
        assert_eq!(r.data["rule"], "no_compliant_offer");
    }
}
