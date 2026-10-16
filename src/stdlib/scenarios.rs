//! Standard library: `tallow.scenarios` — declarative browser automation scenarios.
//!
//! JSON-based multi-step CDP automation without writing .tl scripts.
//! Inspired by ScrapingBee's `js_scenario` and Browserless REST API.
//!
//! # Scenario Format
//! ```json
//! [{"action": "navigate", "url": "..."},
//!  {"action": "wait_for", "selector": "..."},
//!  {"action": "click", "selector": "..."},
//!  {"action": "type", "selector": "...", "text": "..."},
//!  {"action": "screenshot", "path": "..."},
//!  {"action": "extract", "selector": "..."},
//!  {"action": "evaluate", "js": "..."},
//!  {"action": "scroll", "to": "bottom"}]
//! ```
//!
//! # API
//! - `Scenario.create(json_or_name)` — create scenario from JSON string or preset name
//! - `Scenario.list_presets()` — list available preset scenarios
//! - `scenario.to_json()` — export scenario as JSON
//! - `scenario.steps()` — get step count and summary

use super::StdlibResult;
use crate::interp::{type_name, Value};

/// A single step in a browser scenario
#[derive(Debug, Clone)]
struct Scenario {
    name: String,
    steps: Vec<ScenarioStep>,
}

#[derive(Debug, Clone)]
struct ScenarioStep {
    action: String,
    params: Vec<(String, Value)>,
}

impl Scenario {
    fn presets() -> Vec<Scenario> {
        vec![
            Scenario {
                name: "login_form".into(),
                steps: vec![
                    ScenarioStep::new("navigate", vec![("url", Value::String("".into()))]),
                    ScenarioStep::new("wait_for", vec![("selector", Value::String("input[type='email']".into()))]),
                    ScenarioStep::new("type", vec![("selector", Value::String("input[type='email']".into())), ("text", Value::String("".into()))]),
                    ScenarioStep::new("type", vec![("selector", Value::String("input[type='password']".into())), ("text", Value::String("".into()))]),
                    ScenarioStep::new("click", vec![("selector", Value::String("button[type='submit']".into()))]),
                    ScenarioStep::new("wait_for", vec![("selector", Value::String("body".into()))]),
                    ScenarioStep::new("extract", vec![("selector", Value::String("body".into()))]),
                ],
            },
            Scenario {
                name: "product_scrape".into(),
                steps: vec![
                    ScenarioStep::new("navigate", vec![("url", Value::String("".into()))]),
                    ScenarioStep::new("wait_for", vec![("selector", Value::String(".product-title".into()))]),
                    ScenarioStep::new("extract", vec![("selector", Value::String(".product-title".into()))]),
                    ScenarioStep::new("extract", vec![("selector", Value::String(".price".into()))]),
                    ScenarioStep::new("extract", vec![("selector", Value::String(".description".into()))]),
                    ScenarioStep::new("screenshot", vec![("path", Value::String("/tmp/product.png".into()))]),
                ],
            },
            Scenario {
                name: "search_results".into(),
                steps: vec![
                    ScenarioStep::new("navigate", vec![("url", Value::String("".into()))]),
                    ScenarioStep::new("type", vec![("selector", Value::String("input[type='search'], input[name='q']".into())), ("text", Value::String("".into()))]),
                    ScenarioStep::new("click", vec![("selector", Value::String("button[type='submit'], input[type='submit']".into()))]),
                    ScenarioStep::new("wait_for", vec![("selector", Value::String(".search-result, .result, article, .listing".into()))]),
                    ScenarioStep::new("scroll", vec![("to", Value::String("bottom".into()))]),
                    ScenarioStep::new("extract", vec![("selector", Value::String(".search-result, .result, article".into()))]),
                ],
            },
            Scenario {
                name: "infinite_scroll".into(),
                steps: vec![
                    ScenarioStep::new("navigate", vec![("url", Value::String("".into()))]),
                    ScenarioStep::new("wait_for", vec![("selector", Value::String("body".into()))]),
                    ScenarioStep::new("scroll", vec![("to", Value::String("bottom".into()))]),
                    ScenarioStep::new("wait_for", vec![("ms", Value::Int(2000))]),
                    ScenarioStep::new("scroll", vec![("to", Value::String("bottom".into()))]),
                    ScenarioStep::new("wait_for", vec![("ms", Value::Int(2000))]),
                    ScenarioStep::new("scroll", vec![("to", Value::String("bottom".into()))]),
                    ScenarioStep::new("extract", vec![("selector", Value::String("body".into()))]),
                ],
            },
            Scenario {
                name: "bypass_captcha".into(),
                steps: vec![
                    ScenarioStep::new("navigate", vec![("url", Value::String("".into()))]),
                    ScenarioStep::new("wait_for", vec![("selector", Value::String("body".into()))]),
                    ScenarioStep::new("evaluate", vec![("js", Value::String("document.querySelector('iframe[src*=\"captcha\"]') ? 'captcha_detected' : 'no_captcha'".into()))]),
                ],
            },
        ]
    }
}

impl ScenarioStep {
    fn new(action: &str, params: Vec<(&str, Value)>) -> Self {
        ScenarioStep {
            action: action.to_string(),
            params: params.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        }
    }

    fn from_json(json: &str) -> Result<Vec<ScenarioStep>, String> {
        let steps_json: Vec<serde_json::Value> = serde_json::from_str(json)
            .map_err(|e| format!("Invalid JSON: {e}"))?;
        let mut steps = Vec::new();
        for step in steps_json {
            let action = step["action"].as_str().unwrap_or("unknown").to_string();
            let mut params = Vec::new();
            if let Some(obj) = step.as_object() {
                for (k, v) in obj {
                    if k != "action" {
                        let val = json_to_value(v);
                        params.push((k.clone(), val));
                    }
                }
            }
            steps.push(ScenarioStep { action, params });
        }
        Ok(steps)
    }
}

fn json_to_value(val: &serde_json::Value) -> Value {
    match val {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() { Value::Int(i as i128) }
            else if let Some(f) = n.as_f64() { Value::Float(f) }
            else { Value::String(n.to_string()) }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_value).collect()),
        serde_json::Value::Object(o) => {
            let entries: Vec<(Value, Value)> = o.iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_value(v)))
                .collect();
            Value::Map(entries)
        }
    }
}

fn scenario_to_value(s: &Scenario) -> Value {
    let steps: Vec<Value> = s.steps.iter().map(|step| {
        let mut fields: Vec<(String, Value)> = vec![("action".into(), Value::String(step.action.clone()))];
        for (k, v) in &step.params {
            fields.push((k.clone(), v.clone()));
        }
        Value::Struct { name: "ScenarioStep".into(), fields }
    }).collect();
    Value::Struct {
        name: "Scenario".into(),
        fields: vec![
            ("name".into(), Value::String(s.name.clone())),
            ("step_count".into(), Value::Int(s.steps.len() as i128)),
            ("steps".into(), Value::Array(steps)),
        ],
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "create" => Some(sc_create(args)),
        "list_presets" => Some(sc_list()),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "Scenario") {
        return None;
    }
    match method {
        "to_json" => {
            let steps: Vec<Value> = match object {
                Value::Struct { fields, .. } => {
                    fields.iter().find(|(n,_)| n == "steps")
                        .and_then(|(_, v)| if let Value::Array(a) = v { Some(a.clone()) } else { None })
                        .unwrap_or_default()
                }
                _ => return None,
            };
            let steps_json: Vec<serde_json::Value> = steps.iter().map(|step| {
                match step {
                    Value::Struct { fields, .. } => {
                        let mut obj = serde_json::Map::new();
                        for (k, v) in fields {
                            obj.insert(k.clone(), value_to_json(v));
                        }
                        serde_json::Value::Object(obj)
                    }
                    _ => serde_json::Value::Null,
                }
            }).collect();
            let json = serde_json::to_string_pretty(&steps_json).unwrap_or_default();
            Some(Ok(Value::String(json)))
        }
        "steps" => {
            let steps = match object {
                Value::Struct { fields, .. } => {
                    fields.iter().find(|(n,_)| n == "steps")
                        .and_then(|(_, v)| if let Value::Array(a) = v { Some(a.clone()) } else { None })
                        .unwrap_or_default()
                }
                _ => return None,
            };
            Some(Ok(Value::Array(steps)))
        }
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "create" | "list_presets")
}

fn sc_create(args: Vec<Value>) -> StdlibResult {
    let input = expect_first_str(&args, "input")?;

    // Check if it's a preset name
    for preset in Scenario::presets() {
        // FIX12 (2026-08-27): deref &String for comparison
        if preset.name == *input {
            return Ok(scenario_to_value(&preset));
        }
    }

    // Try parsing as JSON
    match ScenarioStep::from_json(input) {
        Ok(steps) => {
            let scenario = Scenario { name: "custom".into(), steps };
            Ok(scenario_to_value(&scenario))
        }
        Err(e) => {
            // Return available presets
            let names: Vec<String> = Scenario::presets().iter().map(|s| s.name.clone()).collect();
            Err(format!("{e}. Available presets: {}", names.join(", ")))
        }
    }
}

fn sc_list() -> StdlibResult {
    let presets: Vec<Value> = Scenario::presets().iter().map(|s| {
        Value::Struct {
            name: "ScenarioInfo".into(),
            fields: vec![
                ("name".into(), Value::String(s.name.clone())),
                ("action_count".into(), Value::Int(s.steps.len() as i128)),
                ("actions".into(), {
                    let acts: Vec<Value> = s.steps.iter()
                        .map(|step| Value::String(step.action.clone()))
                        .collect();
                    Value::Array(acts)
                }),
            ],
        }
    }).collect();
    Ok(Value::Array(presets))
}

fn value_to_json(val: &Value) -> serde_json::Value {
    match val {
        Value::Nil => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(i) => serde_json::Value::Number((*i as i64).into()),
        Value::Float(f) => {
            serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(value_to_json).collect()),
        Value::Map(entries) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    Value::String(s) => s.clone(),
                    _ => format!("{}", type_name(k)),
                };
                obj.insert(key, value_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        Value::Struct { fields, .. } => {
            let mut obj = serde_json::Map::new();
            for (k, v) in fields {
                obj.insert(k.clone(), value_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}
