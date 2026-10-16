//! Selector with **fail-close** semantics.
//!
//! Given a set of offers, a class, and a model, produce an auditable
//! [`DecisionRecord`]: every considered offer lands either in `ranked`
//! (compliant, scored) or in `excluded` (with a reason). If nothing is
//! compliant — or the best total is below the model floor — the record is a
//! [`Refusal`]: **no fallback, no best-effort pick** (SPEC-v2 §11).

use crate::model::{JobClass, Offer};
use crate::score::{score_offer, Exclusion, ScoringModel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum SelectorError {
    #[error("no offers to consider")]
    Empty,
}

/// A scored, ranked offer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RankedOffer {
    pub id: String,
    pub provider: String,
    pub plan: String,
    pub region: String,
    pub city: String,
    pub country: String,
    pub price_month_eur: f64,
    pub vcpu: u32,
    pub mem_mb: u32,
    pub disk_gb: u32,
    pub arch: String,
    pub score: f64,
    pub score_detail: crate::score::Score,
}

/// An excluded offer + why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExcludedOffer {
    pub id: String,
    pub reason: String,
    pub detail: String,
}

/// Fail-close refusal — the job is refused, with full accounting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Refusal {
    pub rule: String,
    pub considered: usize,
    pub excluded_by_reason: BTreeMap<String, u32>,
}

/// The full auditable record of one selection run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub model: String,
    pub class: JobClass,
    pub considered: usize,
    pub ranked: Vec<RankedOffer>,
    pub excluded: Vec<ExcludedOffer>,
    pub chosen: Option<RankedOffer>,
    pub refusal: Option<Refusal>,
}

/// Deterministic ordering: score desc, then id asc (byte order).
fn rank_key(o: &RankedOffer) -> (std::cmp::Reverse<i64>, String) {
    (
        std::cmp::Reverse((o.score * 100.0).round() as i64),
        o.id.clone(),
    )
}

/// Run one selection. Never errors on "no compliant node" — that *is* a
/// refusal, which callers must treat as a stop (fail closed).
pub fn select(
    offers: &[Offer],
    class: JobClass,
    model: &ScoringModel,
) -> Result<DecisionRecord, SelectorError> {
    if offers.is_empty() {
        return Err(SelectorError::Empty);
    }
    let mut ranked: Vec<RankedOffer> = Vec::new();
    let mut excluded: Vec<ExcludedOffer> = Vec::new();
    let mut excluded_by_reason: BTreeMap<String, u32> = BTreeMap::new();

    for o in offers {
        match score_offer(o, class, model) {
            Ok(s) => ranked.push(RankedOffer {
                id: o.id(),
                provider: o.provider.clone(),
                plan: o.plan.clone(),
                region: o.region.clone(),
                city: o.city.clone(),
                country: o.country.clone(),
                price_month_eur: o.price_month_eur,
                vcpu: o.vcpu,
                mem_mb: o.mem_mb,
                disk_gb: o.disk_gb,
                arch: o.arch.clone(),
                score: s.total,
                score_detail: s,
            }),
            Err(e @ Exclusion::UnknownCountry(_))
            | Err(e @ Exclusion::Jurisdiction { .. })
            | Err(e @ Exclusion::Price { .. })
            | Err(e @ Exclusion::Capability { .. }) => {
                *excluded_by_reason.entry(e.key().to_string()).or_insert(0) += 1;
                excluded.push(ExcludedOffer {
                    id: o.id(),
                    reason: e.key().to_string(),
                    detail: e.detail(),
                });
            }
        }
    }

    ranked.sort_by_key(rank_key);
    let best = ranked.first().cloned();
    let refusal = match &best {
        None => Some(Refusal {
            rule: "no_compliant_offer".into(),
            considered: offers.len(),
            excluded_by_reason: excluded_by_reason.clone(),
        }),
        Some(b) if b.score < model.floors.min_score => Some(Refusal {
            rule: format!(
                "below_min_score (best {:.2} < {:.2})",
                b.score, model.floors.min_score
            ),
            considered: offers.len(),
            excluded_by_reason: excluded_by_reason.clone(),
        }),
        Some(_) => None,
    };

    Ok(DecisionRecord {
        model: crate::score::MODEL_V.into(),
        class,
        considered: offers.len(),
        ranked,
        excluded,
        chosen: if refusal.is_none() { best } else { None },
        refusal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::ScoringModel;

    fn offer(provider: &str, region: &str, country: &str, price: f64) -> Offer {
        Offer {
            provider: provider.into(),
            plan: "p1".into(),
            region: region.into(),
            city: "c".into(),
            country: country.into(),
            price_month_eur: price,
            vcpu: 2,
            mem_mb: 4096,
            disk_gb: 40,
            arch: "x86_64".into(),
            source_id: "1".into(),
        }
    }

    #[test]
    fn picks_best_eu_and_ranks_deterministically() {
        let offers = vec![
            offer("hetzner", "ash", "US", 4.0),
            offer("hetzner", "hel1", "FI", 4.35),
            offer("vultr", "fra", "DE", 6.0),
        ];
        let r = select(&offers, JobClass::Privacy, &ScoringModel::default()).unwrap();
        assert!(r.refusal.is_none());
        let chosen = r.chosen.as_ref().unwrap();
        assert_eq!(chosen.country, "FI");
        // determinism: same selection twice -> identical JSON
        let r2 = select(&offers, JobClass::Privacy, &ScoringModel::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            serde_json::to_string(&r2).unwrap()
        );
    }

    #[test]
    fn all_us_privacy_is_a_refusal_with_accounting() {
        let offers = vec![
            offer("hetzner", "ash", "US", 4.0),
            offer("vultr", "ewr", "US", 5.0),
        ];
        let r = select(&offers, JobClass::Privacy, &ScoringModel::default()).unwrap();
        assert!(r.chosen.is_none());
        let refusal = r.refusal.as_ref().unwrap();
        assert_eq!(refusal.rule, "no_compliant_offer");
        assert_eq!(refusal.considered, 2);
        assert_eq!(refusal.excluded_by_reason.get("jurisdiction"), Some(&2));
        assert_eq!(r.excluded.len(), 2);
        // relay class allows US -> chosen
        let r2 = select(&offers, JobClass::Relay, &ScoringModel::default()).unwrap();
        assert!(r2.chosen.is_some());
    }

    #[test]
    fn below_min_score_refuses() {
        // price 9.9 of max 10 -> cost ~0.01; jurisdiction FI 0.8; latency hel ~0.985
        let mut m = ScoringModel::default();
        m.floors.max_price_eur = 10.0;
        m.floors.min_score = 99.0; // impossible
        let offers = vec![offer("hetzner", "hel1", "FI", 4.35)];
        let r = select(&offers, JobClass::Privacy, &m).unwrap();
        assert!(r.chosen.is_none());
        assert!(r
            .refusal
            .as_ref()
            .unwrap()
            .rule
            .starts_with("below_min_score"));
    }

    #[test]
    fn empty_input_is_a_selector_error() {
        assert!(matches!(
            select(&[], JobClass::Privacy, &ScoringModel::default()),
            Err(SelectorError::Empty)
        ));
    }
}
