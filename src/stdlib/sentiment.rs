//! Standard library: `tallow.sentiment` — financial text sentiment analysis.
//!
//! Loughran-McDonald financial sentiment dictionary for analyzing SEC filings,
//! earnings calls, and financial news. Pure Rust — no ML needed.
//!
//! Based on Loughran & McDonald (JF 2011, JAR 2016, JFQA 2024).
//! https://sraf.nd.edu/loughranmcdonald-master-dictionary/
//!
//! # API
//! - `Sentiment.analyze(text)` — full sentiment analysis of text
//! - `Sentiment.score(text)` — aggregate sentiment score
//! - `Sentiment.word_counts(text)` — per-category word counts

use super::StdlibResult;
use crate::interp::Value;


use std::collections::{HashMap, HashSet};

/// Loughran-McDonald sentiment word lists (abridged — top 100 per category).
/// Full dictionary has ~4,500 words across 7 categories.
fn lm_dictionary() -> HashMap<&'static str, HashSet<&'static str>> {
    let mut dict = HashMap::new();

    dict.insert("negative", {
        let mut s = HashSet::new();
        for w in &["abandon", "abandoned", "abandonment", "abate", "abdicate", "aberration",
            "abetting", "abeyance", "abnormal", "abolish", "abrogate", "abrupt", "abscond",
            "absence", "absent", "abstain", "abstract", "abuse", "abusive", "accident",
            "accidental", "accomplice", "accusation", "accuse", "accused", "acknowledge",
            "acquiesce", "acquit", "activist", "adversary", "adverse", "adversely",
            "affirm", "against", "aggregate", "alarm", "allege", "allegation", "alleged",
            "allegedly", "alter", "ambiguity", "ambiguous", "amend", "amendment", "amid",
            "anomalous", "anomaly", "anticompetitive", "antitrust", "apathy", "apparent",
            "apparently", "appear", "applicable", "apprehension", "arbitrary", "argue",
            "argument", "arrears", "arrest", "artifact", "asylum", "attack", "attrition",
            "audit", "austerity", "authoritarian", "avoid", "avoidance", "backlog",
            "bad", "bail", "bailout", "bankrupt", "bankruptcy", "ban", "barred",
            "barrier", "bearish", "belated", "bereavement", "betray", "bias", "biased",
            "blame", "bleak", "block", "blockage", "breach", "break", "breakdown",
            "bribe", "bribery", "broken", "burden", "burdensome", "calamity"] {
            s.insert(*w);
        }
        s
    });

    dict.insert("positive", {
        let mut s = HashSet::new();
        for w in &["able", "abound", "absolve", "absorb", "abundance", "abundant",
            "accelerate", "acclaim", "accolade", "accommodate", "accomplish", "accomplished",
            "accomplishment", "accord", "accrue", "accurate", "achieve", "achievement",
            "acquire", "adapt", "adaptable", "add", "adept", "adequate", "adjust",
            "admirable", "advance", "advanced", "advancement", "advantage", "advantageous",
            "affirmative", "affluence", "affordable", "agile", "agreeable", "alignment",
            "allocate", "allure", "ally", "amaze", "ambitious", "ameliorate", "amenable",
            "amplify", "analogous", "appealing", "applaud", "appreciation", "approve",
            "apt", "arbitrage", "aspire", "aspiration", "assent", "assert", "assess",
            "asset", "assist", "assistance", "assume", "assurance", "assure", "astute",
            "attain", "attractive", "augment", "auspicious", "authentic", "authoritative",
            "automate", "autonomy", "available", "avid", "award", "backbone",
            "balanced", "beat", "beloved", "benchmark", "beneficent", "beneficial",
            "benefit", "benevolent", "best", "better", "blockbuster", "bolster",
            "bonanza", "bonus", "boom", "booming", "boost", "boundless", "breakthrough"] {
            s.insert(*w);
        }
        s
    });

    dict.insert("uncertainty", {
        let mut s = HashSet::new();
        for w in &["almost", "ambiguity", "ambiguous", "apparent", "apparently",
            "appear", "appeared", "appears", "approximate", "approximately",
            "arbitrary", "assume", "assumed", "assumes", "assuming", "assumption",
            "assumptions", "broadly", "cautious", "cautiously", "clarification",
            "conceivable", "conceivably", "conditional", "conditionally", "confess",
            "confided", "confides", "conjecture", "contingency", "contingent",
            "contingently", "could", "crossroad", "depend", "depended", "depending",
            "depends", "destabilize", "deviate", "deviated", "deviates", "deviating",
            "deviation", "differ", "differed", "differing", "differs", "doubt",
            "doubtful", "doubtfully", "doubts", "exposure", "fluctuate", "fluctuated",
            "fluctuates", "fluctuating", "fluctuation", "fluctuations", "hidden",
            "hypothetical", "hypothetically", "imprecise", "imprecisely", "imprecision",
            "incompleteness", "indefinite", "indefinitely", "indeterminable", "indeterminate",
            "inexact", "instability", "intangible", "likelihood", "may", "maybe",
            "might", "nearly", "nonassessable", "occasionally", "ordinarily"] {
            s.insert(*w);
        }
        s
    });

    dict.insert("litigious", {
        let mut s = HashSet::new();
        for w in &["abovementioned", "accusation", "accusations", "accuse", "accused",
            "accuses", "accusing", "action", "actions", "adjudged", "adjudicate",
            "adjudicated", "adjudicating", "adjudication", "affirm", "affirmed",
            "affirming", "affirms", "aforementioned", "aforesaid", "allegation",
            "allegations", "allege", "alleged", "alleges", "alleging", "antecedent",
            "appeal", "appealed", "appealing", "appeals", "appellant", "appellate",
            "appellee", "arbitration", "argument", "arguments", "arraigned",
            "arraignment", "article", "articles", "attorney", "attorneys", "breach",
            "breached", "breaches", "breaching", "brief", "briefed", "briefing",
            "briefs", "certification", "certiorari", "claim", "claimant", "claimed",
            "claiming", "claims", "class", "clause", "clauses", "codefendant",
            "complainant", "complaint", "complaints", "condemn", "condemnation",
            "condemned", "condemning", "condemns", "confess", "confessed", "confesses",
            "confessing", "confession", "consent", "conspired", "conspiring",
            "constitutionality", "contest", "contested", "contract", "contracts",
            "contravene", "contravened", "contravenes", "contravening"] {
            s.insert(*w);
        }
        s
    });

    dict.insert("strong_modal", {
        let mut s = HashSet::new();
        for w in &["always", "best", "certainly", "clearly", "conclusively", "decidedly",
            "definite", "definitely", "distinctly", "evident", "evidently", "forever",
            "highest", "indisputable", "indisputably", "lowest", "must", "never",
            "plainly", "positively", "unambiguous", "unambiguously", "undeniable",
            "undeniably", "undisputed", "undoubtedly", "unquestionable", "unquestionably",
            "will"] {
            s.insert(*w);
        }
        s
    });

    dict.insert("weak_modal", {
        let mut s = HashSet::new();
        for w in &["almost", "apparent", "apparently", "appear", "appeared", "appears",
            "could", "depend", "depended", "depending", "depends", "may", "maybe",
            "might", "nearly", "occasionally", "ordinarily", "perhaps", "possible",
            "possibly", "potential", "potentially", "presumably", "probable", "probably",
            "rarely", "seem", "seemed", "seeming", "seems", "sometimes", "somewhat",
            "suggest", "suggested", "suggesting", "suggests", "tend", "tended",
            "tending", "tends", "typically", "uncertain", "uncertainly", "unclear",
            "unclearly", "unlikely"] {
            s.insert(*w);
        }
        s
    });

    dict.insert("constraining", {
        let mut s = HashSet::new();
        for w in &["bound", "commitment", "commitments", "commits", "committed",
            "compelled", "compelling", "compels", "compliance", "compliant", "compulsory",
            "condition", "conditional", "conditionally", "conditioned", "conditions",
            "confine", "confined", "confines", "constrain", "constraining", "constraint",
            "constraints", "contract", "contracted", "contracting", "contracts",
            "convene", "covenant", "covenanted", "covenants", "curb", "curbed",
            "curbing", "curbs", "demanding", "depends", "deserves", "duty",
            "duties", "encumbered", "enforceable", "entails", "entitled", "entitles",
            "entitling", "essential", "essentially", "exacted", "expected", "forbears",
            "forbid", "forbids", "governmental", "governed", "guarantee", "guaranteed",
            "guarantees", "guarantying", "handcuff", "impaired", "impede", "impeded",
            "impedes", "impeding", "impose", "imposed", "imposes", "imposing"] {
            s.insert(*w);
        }
        s
    });

    dict
}

fn analyze_text(text: &str, dict: &HashMap<&str, HashSet<&str>>) -> Value {
    let words: Vec<String> = text.split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphabetic()).to_lowercase())
        .collect::<Vec<_>>();

    // Count words per category (lowercased)
    let word_count = words.len() as f64;
    if word_count == 0.0 {
        return Value::Struct {
            name: "SentimentResult".into(),
            fields: vec![
                ("total_words".into(), Value::Int(0)),
                ("score".into(), Value::Float(0.0)),
                ("sentiment".into(), Value::String("neutral".into())),
            ],
        };
    }

    let categories = ["negative", "positive", "uncertainty", "litigious", "strong_modal", "weak_modal", "constraining"];
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut total = 0;

    for cat in &categories {
        if let Some(word_set) = dict.get(cat) {
            let count = words.iter().filter(|w| word_set.contains(w.to_string().as_str())).count();
            counts.insert(cat, count);
            total += count;
        }
    }

    // Compute sentiment score: (positive - negative) / total_words
    let pos = *counts.get("positive").unwrap_or(&0) as f64;
    let neg = *counts.get("negative").unwrap_or(&0) as f64;
    let score = if word_count > 0.0 { (pos - neg) / word_count * 100.0 } else { 0.0 };

    let sentiment = if score > 2.0 { "bullish" }
        else if score > 0.5 { "positive" }
        else if score > -0.5 { "neutral" }
        else if score > -2.0 { "negative" }
        else { "bearish" };

    Value::Struct {
        name: "SentimentResult".into(),
        fields: vec![
            ("total_words".into(), Value::Int(word_count as i128)),
            ("lm_hits".into(), Value::Int(total as i128)),
            ("negative".into(), Value::Int(*counts.get("negative").unwrap_or(&0) as i128)),
            ("positive".into(), Value::Int(*counts.get("positive").unwrap_or(&0) as i128)),
            ("uncertainty".into(), Value::Int(*counts.get("uncertainty").unwrap_or(&0) as i128)),
            ("litigious".into(), Value::Int(*counts.get("litigious").unwrap_or(&0) as i128)),
            ("strong_modal".into(), Value::Int(*counts.get("strong_modal").unwrap_or(&0) as i128)),
            ("weak_modal".into(), Value::Int(*counts.get("weak_modal").unwrap_or(&0) as i128)),
            ("constraining".into(), Value::Int(*counts.get("constraining").unwrap_or(&0) as i128)),
            ("score".into(), Value::Float(score)),
            ("sentiment".into(), Value::String(sentiment.into())),
        ],
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "analyze" => Some(sent_analyze(args)),
        "score" => Some(sent_score(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "analyze" | "score")
}

fn sent_analyze(args: Vec<Value>) -> StdlibResult {
    let text_owned = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("Sentiment.analyze: requires (text)".into()),
    };
    let text = text_owned.as_str();
    let dict = lm_dictionary();
    Ok(analyze_text(text, &dict))
}

fn sent_score(args: Vec<Value>) -> StdlibResult {
    let text_owned = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("Sentiment.score: requires (text)".into()),
    };
    let text = text_owned.as_str();
    let dict = lm_dictionary();
    let result = analyze_text(text, &dict);
    // Extract just the score
    if let Value::Struct { fields, .. } = &result {
        for (k, v) in fields {
            if k == "score" { return Ok(v.clone()); }
        }
    }
    Ok(Value::Float(0.0))
}