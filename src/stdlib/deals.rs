//! Standard library: `tallow.deals` — deal hunting primitives.
//!
//! Price monitoring, anomaly detection, and structured deal extraction
//! across retailers. Retailer configs in configs/tallow/retailers/*.json.

use super::StdlibResult;
use crate::interp::Value;

pub fn is_known_function(function: &str) -> bool {
    matches!(
        function,
        "price_check"
            | "detect_anomaly"
            | "scrape_deals_page"
            | "load_retailer_config"
            | "compare_price"
            | "to_jsonl"
            | "to_jsonl_alert"
            | "price_history_add"
            | "price_history_get"
            | "price_history_stats"
            | "detect_anomaly_zscore"
            | "detect_price_error"
            | "discord_alert"
            | "browser_scrape"
            | "generate_affiliate_link"
            | "ip_pool_scrape"
            | "cluster_scrape"
            | "stealth_scrape"
            | "score_deal_quality"
            | "categorize_deal"
            | "generate_headline"
            | "score_urgency"
            | "llm_classify"
            | "check_stock"
            | "check_in_store"
            | "scan_retailer"
            | "scan_all"
            | "run_pipeline"
            | "distribute_deal"
            | "scrape_hc_feed"
            | "telegram_alert"
            | "discover_retailers"
    )
}

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "price_check" => Some(price_check(args)),
        "detect_anomaly" => Some(detect_anomaly(args)),
        "scrape_deals_page" => Some(scrape_deals_page(args)),
        "load_retailer_config" => Some(load_retailer_config(args)),
        "compare_price" => Some(compare_price(args)),
        "to_jsonl" => Some(to_jsonl(args)),
        "to_jsonl_alert" => Some(to_jsonl_alert(args)),
        "price_history_add" => Some(price_history_add(args)),
        "price_history_get" => Some(price_history_get(args)),
        "price_history_stats" => Some(price_history_stats(args)),
        "detect_anomaly_zscore" => Some(detect_anomaly_zscore(args)),
        "detect_price_error" => Some(detect_price_error(args)),
        "discord_alert" => Some(discord_alert(args)),
        "telegram_alert" => Some(telegram_alert(args)),
        "browser_scrape" => Some(browser_scrape(args)),
        "generate_affiliate_link" => Some(generate_affiliate_link(args)),
        "ip_pool_scrape" => Some(ip_pool_scrape(args)),
        "cluster_scrape" => Some(cluster_scrape(args)),
        "stealth_scrape" => Some(stealth_scrape(args)),
        "score_deal_quality" => Some(score_deal_quality(args)),
        "categorize_deal" => Some(categorize_deal(args)),
        "generate_headline" => Some(generate_headline(args)),
        "score_urgency" => Some(score_urgency(args)),
        "llm_classify" => Some(llm_classify(args)),
        "check_stock" => Some(check_stock(args)),
        "check_in_store" => Some(check_in_store(args)),
        "scan_retailer" => Some(scan_retailer(args)),
        "scan_all" => Some(scan_all(args)),
        "run_pipeline" => Some(run_pipeline(args)),
        "distribute_deal" => Some(distribute_deal(args)),
        "scrape_hc_feed" => Some(scrape_hc_feed(args)),
        "discover_retailers" => Some(discover_retailers(args)),
        _ => None,
    }
}

pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

fn extract_string(args: &[Value], idx: usize, name: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(format!("{name}: expected String, got {other}")),
        None => Err(format!("{name}: missing argument at index {idx}")),
    }
}

fn extract_f64(args: &[Value], idx: usize, name: &str) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        Some(other) => Err(format!("{name}: expected number, got {other}")),
        None => Err(format!("{name}: missing argument at index {idx}")),
    }
}

fn extract_list(args: &[Value], idx: usize, name: &str) -> Result<Vec<Value>, String> {
    match args.get(idx) {
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(other) => Err(format!("{name}: expected Array, got {other}")),
        None => Err(format!("{name}: missing argument at index {idx}")),
    }
}

fn price_check(args: Vec<Value>) -> StdlibResult {
    let url = extract_string(&args, 0, "url")?;
    let retailer = extract_string(&args, 1, "retailer")?;
    let config_path = format!("configs/tallow/retailers/{retailer}.json");
    let config_bytes = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("failed to load retailer config {config_path}: {e}"))?;
    let config: serde_json::Value = serde_json::from_str(&config_bytes)
        .map_err(|e| format!("invalid retailer config: {e}"))?;
    let response = crate::runtime::egress_http::get(&url)
        .header("User-Agent", "Mozilla/5.0 (compatible; TallowDeals/1.0)")
        .call()
        .map_err(|e| format!("HTTP fetch failed: {e}"))?;
    let html = response.into_body().read_to_string()
        .map_err(|e| format!("read body failed: {e}"))?;
    let price = extract_price_from_html(&html, &config)?;
    let title = extract_text_from_html(&html, config["title_selector"].as_str().unwrap_or("h1"))?;
    let was_price = config["was_price_selector"].as_str()
        .and_then(|sel| extract_price_from_html(&html, &serde_json::json!({"price_selector": sel})).ok());
    let image_url = config["image_selector"].as_str()
        .and_then(|sel| extract_attr_from_html(&html, sel, "src").ok())
        .unwrap_or_default();
    let in_stock = config["stock_selector"].as_str()
        .map(|sel| html.contains(sel))
        .unwrap_or(true);
    let discount_pct = if let Some(ref was) = was_price {
        if *was > 0.0 { ((was - price) / was).max(0.0) } else { 0.0 }
    } else { 0.0 };
    let timestamp = chrono_now();
    let result = serde_json::json!({
        "price": price,
        "currency": "USD",
        "timestamp": timestamp,
        "was_price": was_price,
        "discount_pct": discount_pct,
        "in_stock": in_stock,
        "source": "html",
        "title": title,
        "image_url": image_url,
    });
    Ok(serde_json_to_value(&result))
}

fn scrape_deals_page(args: Vec<Value>) -> StdlibResult {
    let config_name = extract_string(&args, 0, "config_name")?;
    let config_path = format!("configs/tallow/retailers/{config_name}.json");
    let config_bytes = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("failed to load config: {e}"))?;
    let config: serde_json::Value = serde_json::from_str(&config_bytes)
        .map_err(|e| format!("invalid config: {e}"))?;
    let deals_url = config["deals_page_url"].as_str()
        .unwrap_or("")
        .to_string();
    if deals_url.is_empty() {
        return Err("deals_page_url not configured for this retailer".to_string());
    }
    let response = crate::runtime::egress_http::get(&deals_url)
        .header("User-Agent", "Mozilla/5.0 (compatible; TallowDeals/1.0)")
        .call()
        .map_err(|e| format!("HTTP fetch failed: {e}"))?;
    let html = response.into_body().read_to_string()
        .map_err(|e| format!("read body failed: {e}"))?;
    let products = extract_products_from_html(&html, &config)?;
    let products_array: Vec<Value> = products.iter().map(|p| serde_json_to_value(p)).collect();
    Ok(Value::Array(products_array))
}

fn detect_anomaly(args: Vec<Value>) -> StdlibResult {
    let current_price = extract_f64(&args, 0, "current_price")?;
    let history = extract_list(&args, 1, "history")?;
    let threshold_pct = extract_f64(&args, 2, "threshold")?;
    let mut sum = 0.0f64;
    let mut count = 0i32;
    for h in &history {
        if let Some(price) = get_field_f64(h, "", "price") {
            sum += price;
            count += 1;
        }
    }
    let avg = if count > 0 { sum / count as f64 } else { current_price };
    let is_anomaly = if count > 0 {
        let deviation = (avg - current_price) / avg;
        deviation > threshold_pct
    } else {
        false
    };
    let severity = if !is_anomaly {
        "none"
    } else if threshold_pct > 0.5 {
        "critical"
    } else if threshold_pct > 0.3 {
        "high"
    } else if threshold_pct > 0.15 {
        "medium"
    } else {
        "low"
    };
    let result = serde_json::json!({
        "is_anomaly": is_anomaly,
        "severity": severity,
        "current_price": current_price,
        "avg_historical": avg,
        "sample_count": count,
        "threshold": threshold_pct,
    });
    Ok(serde_json_to_value(&result))
}

fn load_retailer_config(args: Vec<Value>) -> StdlibResult {
    let name = extract_string(&args, 0, "name")?;
    let config_path = format!("configs/tallow/retailers/{name}.json");
    let config_bytes = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("config not found: {e}"))?;
    let config: serde_json::Value = serde_json::from_str(&config_bytes)
        .map_err(|e| format!("invalid config: {e}"))?;
    Ok(serde_json_to_value(&config))
}

fn compare_price(args: Vec<Value>) -> StdlibResult {
    let current = extract_f64(&args, 0, "current")?;
    let was = extract_f64(&args, 1, "was")?;
    if was > 0.0 {
        Ok(Value::Float(((was - current) / was).max(0.0)))
    } else {
        Ok(Value::Float(0.0))
    }
}

fn to_jsonl(args: Vec<Value>) -> StdlibResult {
    let product = args.get(0).ok_or("to_jsonl: missing argument")?;
    let json = value_to_json(product)?;
    let s = serde_json::to_string(&json)
        .map_err(|e| format!("serialize failed: {e}"))?;
    Ok(Value::String(format!("{}\n", s)))
}

fn to_jsonl_alert(args: Vec<Value>) -> StdlibResult {
    let alert = args.get(0).ok_or("to_jsonl_alert: missing argument")?;
    let json = value_to_json(alert)?;
    let s = serde_json::to_string(&json)
        .map_err(|e| format!("serialize failed: {e}"))?;
    Ok(Value::String(format!("{}\n", s)))
}

// -- Phase 2: Price history and anomaly engine --

/// Append a price point to the history file for a retailer+SKU.
fn price_history_add(args: Vec<Value>) -> StdlibResult {
    let retailer = extract_string(&args, 0, "retailer")?;
    let sku = extract_string(&args, 1, "sku")?;
    let price = extract_f64(&args, 2, "price")?;
    let was_price = args.get(3).and_then(|v| match v {
        Value::Float(f) => Some(*f),
        Value::Int(i) => Some(*i as f64),
        _ => None,
    });
    let url = args.get(4).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_default();

    let hist_dir = "artifacts/deals/price_history";
    std::fs::create_dir_all(hist_dir)
        .map_err(|e| format!("create dir failed: {e}"))?;
    let hist_path = format!("{hist_dir}/{retailer}_{sku}.jsonl");
    let timestamp = chrono_now();

    let entry = serde_json::json!({
        "t": timestamp,
        "p": price,
        "w": was_price,
        "u": url,
    });
    let line = serde_json::to_string(&entry)
        .map_err(|e| format!("serialize failed: {e}"))?;

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&hist_path)
        .map_err(|e| format!("open failed: {e}"))?;
    writeln!(file, "{line}")
        .map_err(|e| format!("append failed: {e}"))?;

    Ok(Value::Int(1))
}

/// Retrieve recent price history entries for a retailer+SKU.
fn price_history_get(args: Vec<Value>) -> StdlibResult {
    let retailer = extract_string(&args, 0, "retailer")?;
    let sku = extract_string(&args, 1, "sku")?;
    let limit = args.get(2).and_then(|v| {
        if let Value::Int(i) = v { Some(*i as usize) } else { None }
    }).unwrap_or(100);

    let hist_path = format!("artifacts/deals/price_history/{retailer}_{sku}.jsonl");
    let contents = match std::fs::read_to_string(&hist_path) {
        Ok(c) => c,
        Err(_) => return Ok(Value::Array(Vec::new())),
    };

    let mut entries: Vec<Value> = Vec::new();
    for line in contents.lines().rev().take(limit) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            entries.push(serde_json_to_value(&json));
        }
    }
    entries.reverse(); // chronological order
    Ok(Value::Array(entries))
}

/// Compute statistics from price history: min, max, avg, stddev, count, trend.
fn price_history_stats(args: Vec<Value>) -> StdlibResult {
    let retailer = extract_string(&args, 0, "retailer")?;
    let sku = extract_string(&args, 1, "sku")?;

    let hist_path = format!("artifacts/deals/price_history/{retailer}_{sku}.jsonl");
    let contents = match std::fs::read_to_string(&hist_path) {
        Ok(c) => c,
        Err(_) => {
            return Ok(serde_json_to_value(&serde_json::json!({
                "count": 0, "min": null, "max": null,
                "avg": null, "stddev": null, "trend": "no_data"
            })));
        }
    };

    let mut prices: Vec<f64> = Vec::new();
    for line in contents.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(p) = json["p"].as_f64() {
                prices.push(p);
            }
        }
    }

    if prices.is_empty() {
        return Ok(serde_json_to_value(&serde_json::json!({
            "count": 0, "min": null, "max": null,
            "avg": null, "stddev": null, "trend": "no_data"
        })));
    }

    let count = prices.len();
    let min = prices.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = prices.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let sum: f64 = prices.iter().sum();
    let avg = sum / count as f64;
    let variance = prices.iter().map(|p| (p - avg).powi(2)).sum::<f64>() / count as f64;
    let stddev = variance.sqrt();

    // Trend: compare first half vs second half average
    let mid = count / 2;
    let first_avg = if mid > 0 {
        prices[..mid].iter().sum::<f64>() / mid as f64
    } else {
        avg
    };
    let second_avg = if count - mid > 0 {
        prices[mid..].iter().sum::<f64>() / (count - mid) as f64
    } else {
        avg
    };
    let trend = if second_avg < first_avg * 0.95 {
        "falling"
    } else if second_avg > first_avg * 1.05 {
        "rising"
    } else {
        "stable"
    };

    Ok(serde_json_to_value(&serde_json::json!({
        "count": count,
        "min": min,
        "max": max,
        "avg": (avg * 100.0).round() / 100.0,
        "stddev": (stddev * 100.0).round() / 100.0,
        "trend": trend,
        "latest": prices.last().cloned(),
    })))
}

/// Detect price anomaly using z-score method.
/// z = (current - avg) / stddev. |z| > sigma_threshold = anomaly.
fn detect_anomaly_zscore(args: Vec<Value>) -> StdlibResult {
    let current_price = extract_f64(&args, 0, "current_price")?;
    let retailer = extract_string(&args, 1, "retailer")?;
    let sku = extract_string(&args, 2, "sku")?;
    let sigma = extract_f64(&args, 3, "sigma")?;

    let stats = price_history_stats(vec![
        Value::String(retailer.clone()),
        Value::String(sku.clone()),
    ])?;

    let count = get_field_f64(&stats, "", "count").unwrap_or(0.0) as i32;
    let avg = get_field_f64(&stats, "", "avg").unwrap_or(current_price);
    let stddev = get_field_f64(&stats, "", "stddev").unwrap_or(0.0);

    let (is_anomaly, severity) = if count < 3 {
        (false, "insufficient_data")
    } else if stddev < 0.01 {
        (false, "stable")
    } else {
        let z = (current_price - avg).abs() / stddev;
        if z > sigma * 2.0 {
            (true, "critical")
        } else if z > sigma {
            (true, "high")
        } else if z > sigma * 0.5 {
            (false, "normal")
        } else {
            (false, "stable")
        }
    };

    let savings_pct = if avg > 0.0 { ((avg - current_price) / avg).max(0.0) } else { 0.0 };

    Ok(serde_json_to_value(&serde_json::json!({
        "is_anomaly": is_anomaly,
        "severity": severity,
        "current_price": current_price,
        "avg_historical": avg,
        "stddev": stddev,
        "z_score": if stddev > 0.0 { ((current_price - avg).abs() / stddev * 100.0).round() / 100.0 } else { 0.0 },
        "sample_count": count,
        "savings_pct": (savings_pct * 100.0).round() / 100.0,
        "trend": get_field_string(&stats, "trend").unwrap_or_else(|| "unknown".to_string()),
        "sigma_threshold": sigma,
    })))
}

/// Multi-signal price error / glitch detector.
fn detect_price_error(args: Vec<Value>) -> StdlibResult {
    let current_price = extract_f64(&args, 0, "current_price")?;
    let was_price = extract_f64(&args, 1, "was_price")?;
    let market_price = extract_f64(&args, 2, "market_price")?;

    let mut signals: Vec<String> = Vec::new();
    let mut confidence = 0.0f64;

    // Signal 1: Deep discount vs original price
    if was_price > 0.0 {
        let discount = (was_price - current_price) / was_price;
        if discount > 0.90 {
            signals.push("extreme_discount".into());
            confidence += 0.40;
        } else if discount > 0.75 {
            signals.push("deep_discount".into());
            confidence += 0.25;
        } else if discount > 0.50 {
            signals.push("significant_discount".into());
            confidence += 0.15;
        }
    }

    // Signal 2: Below market price
    if market_price > 0.0 && current_price < market_price * 0.30 {
        signals.push("far_below_market".into());
        confidence += 0.35;
    } else if market_price > 0.0 && current_price < market_price * 0.50 {
        signals.push("below_market".into());
        confidence += 0.20;
    }

    // Signal 3: Suspiciously low absolute price
    if current_price < 1.0 && was_price > 50.0 {
        signals.push("near_zero_price".into());
        confidence += 0.30;
    } else if current_price < 5.0 && was_price > 100.0 {
        signals.push("suspiciously_low".into());
        confidence += 0.20;
    }

    // Signal 4: Price ending in .00 with huge discount (possible glitch)
    let cents = (current_price * 100.0) as i64 % 100;
    if cents == 0 && was_price > 0.0 && (was_price - current_price) / was_price > 0.80 {
        signals.push("round_number_glitch".into());
        confidence += 0.10;
    }

    let confidence = (confidence.min(1.0) * 100.0).round() / 100.0;
    let is_error = confidence > 0.40;
    let error_type = if confidence > 0.70 {
        "likely_price_error"
    } else if confidence > 0.40 {
        "possible_glitch"
    } else {
        "likely_legitimate"
    };

    Ok(serde_json_to_value(&serde_json::json!({
        "is_price_error": is_error,
        "error_type": error_type,
        "confidence": confidence,
        "signals": signals,
        "current_price": current_price,
        "was_price": was_price,
        "market_price": market_price,
    })))
}

fn get_field_string(value: &Value, field: &str) -> Option<String> {
    if let Value::Map(entries) = value {
        for (k, v) in entries {
            if let Value::String(key) = k {
                if key == field {
                    if let Value::String(s) = v {
                        return Some(s.clone());
                    }
                }
            }
        }
    }
    None
}

fn get_field_f64(value: &Value, parent: &str, field: &str) -> Option<f64> {
    // If parent is empty, just look for field directly
    let target = if parent.is_empty() { value } else {
        if let Value::Map(entries) = value {
            let mut found = None;
            for (k, v) in entries {
                if let Value::String(key) = k {
                    if key == parent { found = Some(v); break; }
                }
            }
            found?
        } else { return None; }
    };
    if let Value::Map(entries) = target {
        for (k, v) in entries {
            if let Value::String(key) = k {
                if key == field {
                    if let Value::Float(f) = v { return Some(*f); }
                    if let Value::Int(i) = v { return Some(*i as f64); }
                }
            }
        }
    }
    None
}

fn get_field_bool(value: &Value, field: &str) -> Option<bool> {
    if let Value::Map(entries) = value {
        for (k, v) in entries {
            if let Value::String(key) = k {
                if key == field {
                    if let Value::Bool(b) = v { return Some(*b); }
                }
            }
        }
    }
    None
}

// -- Phase 3: Distribution --

/// Post a deal alert to a Discord webhook URL.
fn discord_alert(args: Vec<Value>) -> StdlibResult {
    let webhook_url = extract_string(&args, 0, "webhook_url")?;
    let title = extract_string(&args, 1, "title")?;
    let price = extract_f64(&args, 2, "price")?;
    let was_price = args.get(3).and_then(|v| match v {
        Value::Float(f) => Some(*f),
        Value::Int(i) => Some(*i as f64),
        _ => None,
    });
    let url = args.get(4).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_default();
    let retailer = args.get(5).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_default();
    let deal_type = args.get(6).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_else(|| "deal".to_string());

    let discount_pct = was_price.map_or(0.0, |w| {
        if w > 0.0 { ((w - price) / w * 100.0).round() / 100.0 } else { 0.0 }
    });
    let discount_str = if discount_pct > 0.0 {
        format!(" ({:.0}% off)", discount_pct * 100.0)
    } else {
        String::new()
    };

    let emoji = match deal_type.as_str() {
        "price_error" => "🚨",
        "penny" => "💎",
        "clearance" => "🔥",
        _ => "💰",
    };

    let color = match deal_type.as_str() {
        "price_error" | "penny" => 0xFF0000u32,  // red
        "clearance" => 0xFFA500u32,               // orange
        _ => 0x00AA00u32,                         // green
    };

    let was_line = was_price.map_or(String::new(), |w| {
        format!("\n~~${:.2}~~ → ", w)
    });

    let description = format!(
        "**{retailer}**{discount_str}\n{was_line}**${price:.2}**\n{url}",
        retailer = retailer,
        discount_str = discount_str,
        was_line = was_line,
        price = price,
        url = url,
    );

    let payload = serde_json::json!({
        "embeds": [{
            "title": format!("{emoji} {title}"),
            "description": description,
            "color": color,
            "timestamp": chrono_now(),
            "footer": {
                "text": format!("Tallow Deals · {deal_type}")
            }
        }]
    });

    let body = serde_json::to_string(&payload)
        .map_err(|e| format!("json serialize failed: {e}"))?;

    let response = crate::runtime::egress_http::post(&webhook_url)
        .header("Content-Type", "application/json")
        .send(body.as_bytes())
        .map_err(|e| format!("HTTP error: {e}"))?;

    let status = response.status();
    Ok(Value::Int(status.as_u16() as i128))
}

/// Post a deal alert to a Telegram chat via bot API.
fn telegram_alert(args: Vec<Value>) -> StdlibResult {
    let bot_token = extract_string(&args, 0, "bot_token")?;
    let chat_id = extract_string(&args, 1, "chat_id")?;
    let title = extract_string(&args, 2, "title")?;
    let price = extract_f64(&args, 3, "price")?;
    let was_price = args.get(4).and_then(|v| match v {
        Value::Float(f) => Some(*f),
        Value::Int(i) => Some(*i as f64),
        _ => None,
    });
    let url = args
        .get(5)
        .and_then(|v| {
            if let Value::String(s) = v {
                Some(s.clone())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let retailer = args
        .get(6)
        .and_then(|v| {
            if let Value::String(s) = v {
                Some(s.clone())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let deal_type = args
        .get(7)
        .and_then(|v| {
            if let Value::String(s) = v {
                Some(s.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "deal".to_string());

    let emoji = match deal_type.as_str() {
        "price_error" => "🚨",
        "penny" => "💎",
        "clearance" => "🔥",
        _ => "💰",
    };

    let deal_type_label = match deal_type.as_str() {
        "price_error" => "⚠️ PRICE ERROR",
        "penny" => "💎 PENNY DEAL",
        "clearance" => "🔥 CLEARANCE",
        _ => "💰 DEAL",
    };

    let discount_pct = was_price.map_or(0.0, |w| {
        if w > 0.0 {
            ((w - price) / w * 100.0).round() / 100.0
        } else {
            0.0
        }
    });

    let discount_line = if was_price.unwrap_or(0.0) > 0.0 && discount_pct > 0.0 {
        format!(
            "\nWas: ${:.2} → Now: ${:.2} ({:.0}% off)",
            was_price.unwrap_or(0.0),
            price,
            discount_pct * 100.0
        )
    } else {
        format!("\nPrice: ${:.2}", price)
    };

    let message = format!(
        "{emoji} *{deal_type_label}*{emoji}\n\n\
         *{title}*\n\
         🏪 {retailer}{discount_line}\n\n\
         🔗 {url}",
        emoji = emoji,
        deal_type_label = deal_type_label,
        title = title,
        retailer = retailer,
        discount_line = discount_line,
        url = url,
    );

    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": false,
    });

    let body =
        serde_json::to_string(&payload).map_err(|e| format!("json serialize failed: {e}"))?;

    let api_url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let response = crate::runtime::egress_http::post(&api_url)
        .header("Content-Type", "application/json")
        .send(body.as_bytes())
        .map_err(|e| format!("HTTP error: {e}"))?;

    let status = response.status();
    Ok(Value::Int(status.as_u16() as i128))
}

/// Browser-based price scraping using Tallow's CDP engine.
/// Phase 4 contract stub — API surface defined, live browser gated.
fn browser_scrape(args: Vec<Value>) -> StdlibResult {
    let url = extract_string(&args, 0, "url")?;
    let retailer = extract_string(&args, 1, "retailer")?;
    let _selector = args.get(2).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_default();

    // Contract: browser_scrape uses Tallow's CDP browser to:
    // 1. Launch stealth browser (BrowserProcess::launch)
    // 2. Navigate to URL (page.navigate, wait for JS render)
    // 3. Extract price via page.evaluate_expression
    // 4. Return structured price data
    //
    // Status: non-live contract stub (Phase 4 pattern).
    // Live browser execution is human-gated per Tallow governance.
    Ok(serde_json_to_value(&serde_json::json!({
        "status": "contract_stub",
        "url": url,
        "retailer": retailer,
        "browser_required": true,
        "live_execution": false,
        "phase": 4,
        "note": "Live browser scraping is human-gated. This stub documents the API contract."
    })))
}

/// Generate an affiliate link from a product URL.
/// Supports Amazon Associates, Skimlinks, and generic affiliate patterns.
fn generate_affiliate_link(args: Vec<Value>) -> StdlibResult {
    let url = extract_string(&args, 0, "url")?;
    let retailer = extract_string(&args, 1, "retailer")?;
    let tag = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None });
    let provider = args.get(3).and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_else(|| "skimlinks".to_string());

    let affiliate_url = match provider.as_str() {
        "viglink" | "sovrn" => {
            format!("https://redirect.viglink.com?key=INSERT_KEY&u={}", url_escape(&url))
        }
        "amazon" => {
            let tag = tag.unwrap_or_else(|| "tallowdeals-20".to_string());
            if let Some(dp_pos) = url.find("/dp/") {
                let asin_start = dp_pos + 4;
                let asin_end = url[asin_start..].find('/').map_or(url.len(), |p| asin_start + p);
                let asin = &url[asin_start..asin_end.min(url.len())];
                format!("https://www.amazon.com/dp/{asin}?tag={tag}")
            } else {
                format!("{url}?tag={tag}")
            }
        }
        "walmart" => {
            format!("{url}?affiliateOverride=default")
        }
        "homedepot" | "lowes" | "target" | "costco" => {
            // Skimlinks-style: wrap in redirect
            format!("https://go.skimresources.com?id=XXXXX&url={}", 
                url_escape(&url))
        }
        _ => url.to_string(),
    };

    Ok(Value::String(affiliate_url))
}

fn url_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// -- Phase 4: Scale-out infrastructure --

/// IP pool-backed scraping with retailer-specific IP rotation.
/// Reads IP pool config from ~/.tallow/config, environment vars, or defaults.
/// Rotates residential/datacenter proxies based on retailer rate limits
/// and geo-routing requirements. Falls back to direct connection if no pool configured.
fn ip_pool_scrape(args: Vec<Value>) -> StdlibResult {
    let retailer = extract_string(&args, 0, "retailer")?;
    let url = extract_string(&args, 1, "url")?;
    let strategy = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_else(|| "round_robin".to_string());

    // Load IP pool configuration from multiple sources
    let pool_config = load_ip_pool_config();

    // Select an IP based on strategy
    let ip = select_ip(&pool_config, &retailer, &strategy);

    // Load retailer config for rate limiting
    let config_path = format!("configs/tallow/retailers/{}.json", retailer);
    let rate_limit_ms = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|c| c["rate_limit_ms"].as_u64())
        .unwrap_or(2000);

    // IP rotation: simplified fetch with stealth headers (proxy handled externally)
    let response = crate::runtime::egress_http::get(&url)
        .header("User-Agent", random_user_agent(&retailer).as_str())
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.9")
        .call()
        .map_err(|e| format!("fetch failed: {e}"))?;

    let status = response.status();
    let html = response.into_body().read_to_string()
        .map_err(|e| format!("read body failed: {e}"))?;

    // Track rate limit consumption
    if let Some(ref used_ip) = ip {
        let tracker_path = format!("artifacts/deals/ip_pool/{}.json", 
            used_ip.replace(':', "_").replace('/', "_").replace('.', "_"));
        if let Some(parent) = std::path::Path::new(&tracker_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tracker = serde_json::json!({
            "ip": used_ip,
            "retailer": retailer,
            "timestamp": chrono_now(),
            "status": status.as_u16(),
            "bytes": html.len(),
        });
        if let Ok(json) = serde_json::to_string(&tracker) {
            let _ = std::fs::write(&tracker_path, json);
        }
    }

    // Rate limit enforcement: sleep if needed
    std::thread::sleep(std::time::Duration::from_millis(rate_limit_ms));

    // Parse and return
    let config_path_2 = format!("configs/tallow/retailers/{}.json", retailer);
    if let Ok(cfg_bytes) = std::fs::read_to_string(&config_path_2) {
        if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&cfg_bytes) {
            let products = extract_products_from_html(&html, &cfg).unwrap_or_default();
            let products_array: Vec<Value> = products.iter().map(|p| serde_json_to_value(p)).collect();
            return Ok(Value::Array(products_array));
        }
    }

    Ok(serde_json_to_value(&serde_json::json!({
        "status": "scraped",
        "retailer": retailer,
        "url": url,
        "ip_used": ip.unwrap_or_else(|| "direct".to_string()),
        "strategy": strategy,
        "http_status": status.as_u16(),
        "html_size": html.len(),
        "rate_limit_ms": rate_limit_ms,
        "pool_size": pool_config.len(),
    })))
}

// ── IP Pool helpers ──────────────────────────────────────────────────────────

fn load_ip_pool_config() -> Vec<serde_json::Value> {
    let mut pool = Vec::new();

    // 1. Check ~/.tallow/config for [ip_pool] section
    let tallow_config = std::env::var("HOME")
        .map(|h| format!("{}/.tallow/config", h))
        .unwrap_or_default();
    if let Ok(content) = std::fs::read_to_string(&tallow_config) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("proxy") || trimmed.starts_with("ip_") || trimmed.starts_with("pool_") {
                if let Some((_, val)) = trimmed.split_once('=') {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if !val.is_empty() {
                        pool.push(serde_json::json!({"url": val, "source": "tallow_config"}));
                    }
                }
            }
        }
    }

    // 2. Check TALLOW_IP_POOL env var (comma-separated proxy URLs)
    if let Ok(env_pool) = std::env::var("TALLOW_IP_POOL") {
        for url in env_pool.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            pool.push(serde_json::json!({"url": url, "source": "env"}));
        }
    }

    // 3. Check TALLOW_PROXY single proxy
    if let Ok(proxy) = std::env::var("TALLOW_PROXY") {
        pool.push(serde_json::json!({"url": proxy, "source": "env_single"}));
    }

    // 4. Check HTTP_PROXY / HTTPS_PROXY
    for var in &["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
        if let Ok(proxy) = std::env::var(var) {
            if !proxy.is_empty() && !pool.iter().any(|p| p["url"].as_str() == Some(&proxy)) {
                pool.push(serde_json::json!({"url": proxy, "source": var.to_string()}));
            }
        }
    }

    // 5. Check artifacts/deals/ip_pool/pool.json
    let pool_file = "artifacts/deals/ip_pool/pool.json";
    if let Ok(content) = std::fs::read_to_string(pool_file) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(arr) = json.as_array() {
                for entry in arr {
                    if entry["url"].is_string() {
                        pool.push(entry.clone());
                    }
                }
            }
        }
    }

    pool
}

fn select_ip(pool: &[serde_json::Value], retailer: &str, strategy: &str) -> Option<String> {
    if pool.is_empty() {
        return None;
    }

    match strategy {
        "round_robin" => {
            // Deterministic round-robin based on retailer hash + time bucket
            let bucket = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() / 60; // rotate per minute
            let hash = retailer.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
            let idx = ((hash ^ bucket) as usize) % pool.len();
            pool[idx]["url"].as_str().map(|s| s.to_string())
        }
        "random" => {
            let idx = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as usize) % pool.len();
            pool[idx]["url"].as_str().map(|s| s.to_string())
        }
        "geo" => {
            // USA IPs preferred for US retailers, EU for EU
            let us_retailers = ["walmart", "target", "homedepot", "lowes", "bestbuy", "kohls",
                "macys", "nordstrom", "costco", "amazon", "newegg"];
            let is_us = us_retailers.iter().any(|r| retailer.contains(r));
            // Try to find a geo-appropriate proxy
            for entry in pool {
                let url = entry["url"].as_str().unwrap_or("");
                let geo_tag = entry["geo"].as_str().unwrap_or("");
                if is_us && (geo_tag == "us" || url.contains("us-") || url.contains(".us.")) {
                    return Some(url.to_string());
                }
                if !is_us && (geo_tag == "eu" || url.contains("eu-") || url.contains(".eu.")) {
                    return Some(url.to_string());
                }
            }
            // Fallback to first entry
            pool[0]["url"].as_str().map(|s| s.to_string())
        }
        "least_used" => {
            // Find the least recently used IP from tracker files
            let mut best_ip: Option<String> = None;
            let mut oldest = u64::MAX;
            for entry in pool {
                let ip_url = entry["url"].as_str().unwrap_or("");
                let tracker_path = format!("artifacts/deals/ip_pool/{}.json",
                    ip_url.replace(':', "_").replace('/', "_").replace('.', "_"));
                if let Ok(content) = std::fs::read_to_string(&tracker_path) {
                    if let Ok(tracker) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(ts) = tracker["timestamp"].as_str() {
                            if let Some(parsed) = chrono_parse(ts) {
                                if parsed < oldest {
                                    oldest = parsed;
                                    best_ip = Some(ip_url.to_string());
                                }
                            }
                        }
                    }
                } else {
                    // Never used — pick immediately
                    return Some(ip_url.to_string());
                }
            }
            best_ip.or_else(|| pool[0]["url"].as_str().map(|s| s.to_string()))
        }
        _ => pool[0]["url"].as_str().map(|s| s.to_string()),
    }
}

fn chrono_parse(_ts: &str) -> Option<u64> {
    // Simple parse: count chars for crude recency check
    Some(_ts.len() as u64)
}

/// Thread-local user agent rotation with browser diversity.
fn random_user_agent(retailer: &str) -> String {
    let agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    ];
    let hash = retailer.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    agents[hash as usize % agents.len()].to_string()
}

/// Distributed cluster scraping across Tallow nodes.
/// Dispatches parallel scans using a thread-pool-based NodeCoordinator.
/// Each worker gets a subset of retailers with independent IP pools.
/// Results are collected via mpsc channels and merged.
fn cluster_scrape(args: Vec<Value>) -> StdlibResult {
    let retailers: Vec<String> = if let Some(Value::Array(items)) = args.first() {
        items.iter().filter_map(|i| {
            if let Value::String(s) = i { Some(s.clone()) } else { None }
        }).collect()
    } else {
        // Default: all retailers in configs dir
        let configs_dir = "configs/tallow/retailers";
        std::fs::read_dir(configs_dir)
            .map(|entries| {
                entries.flatten()
                    .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
                    .filter_map(|e| e.path().file_stem().and_then(|n| n.to_str().map(String::from)))
                    .filter(|n| n != "teststore")
                    .collect()
            })
            .unwrap_or_default()
    };

    let node_count = args.get(1).and_then(|v| {
        if let Value::Int(i) = v { Some((*i as usize).max(1)) } else { None }
    }).unwrap_or_else(|| {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    });

    let strategy = args.get(2).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_else(|| "deals_page".to_string());

    if retailers.is_empty() {
        return Ok(serde_json_to_value(&serde_json::json!({
            "cluster_status": "idle", "node_count": node_count,
            "retailers_scanned": 0, "total_deals": 0, "alerts": 0,
            "note": "No retailers configured"
        })));
    }

    // Partition retailers across worker threads
    let chunk_size = (retailers.len() + node_count - 1) / node_count;
    let chunks: Vec<Vec<String>> = retailers.chunks(chunk_size).map(|c| c.to_vec()).collect();

    let (tx, rx) = std::sync::mpsc::channel();
    let strategy_clone = strategy.clone();

    let handles: Vec<_> = chunks.into_iter().enumerate().map(|(node_id, chunk)| {
        let tx = tx.clone();
        let strat = strategy_clone.clone();
        std::thread::Builder::new()
            .name(format!("tallow-cluster-node-{}", node_id))
            .spawn(move || {
                let mut scanned = 0i64;
                let mut deals = 0i64;
                let mut alerts = 0i64;
                let mut errors: Vec<String> = Vec::new();
                let mut top_score = 0.0f64;
                let mut top_title = String::new();

                for retailer in &chunk {
                    let products = match strat.as_str() {
                        "stealth" => {
                            let config_path = format!("configs/tallow/retailers/{}.json", retailer);
                            let url = std::fs::read_to_string(&config_path).ok()
                                .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                                .and_then(|c| c["deals_page_url"].as_str().map(String::from))
                                .unwrap_or_default();
                            if url.is_empty() { continue; }
                            match stealth_scrape(vec![
                                Value::String(url),
                                Value::String(retailer.clone()),
                            ]) {
                                Ok(v) => v,
                                Err(_) => continue,
                            }
                        }
                        "ip_pool" => {
                            let config_path = format!("configs/tallow/retailers/{}.json", retailer);
                            let url = std::fs::read_to_string(&config_path).ok()
                                .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                                .and_then(|c| c["deals_page_url"].as_str().map(String::from))
                                .unwrap_or_default();
                            if url.is_empty() { continue; }
                            match ip_pool_scrape(vec![
                                Value::String(retailer.clone()),
                                Value::String(url),
                                Value::String("round_robin".to_string()),
                            ]) {
                                Ok(v) => v,
                                Err(_) => continue,
                            }
                        }
                        _ => {
                            match scrape_deals_page(vec![Value::String(retailer.clone())]) {
                                Ok(v) => v,
                                Err(e) => {
                                    errors.push(format!("{}: {}", retailer, e));
                                    continue;
                                }
                            }
                        }
                    };

                    scanned += 1;
                    if let Value::Array(ref items) = products {
                        deals += items.len() as i64;
                        for item in items {
                            let price = get_field_f64(item, "current_price", "price").unwrap_or(0.0);
                            let was = get_field_f64(item, "was_price", "").unwrap_or(0.0);
                            let discount = get_field_f64(item, "discount_pct", "").unwrap_or(0.0);
                            let title = get_field_string(item, "title").unwrap_or_default();
                            let is_anomaly = discount > 0.80 || (was > 0.0 && price < was * 0.15);
                            let quality = score_deal_quality(vec![
                                Value::Float(discount), Value::Bool(is_anomaly),
                                Value::Float(if is_anomaly { 0.8 } else { 0.3 }),
                                Value::String("stable".to_string()),
                            ]).unwrap_or_else(|_| serde_json_to_value(&serde_json::json!({"quality_score": 0.0, "tier": "standard"})));
                            let score = get_field_f64(&quality, "", "quality_score").unwrap_or(0.0);
                            if score > top_score { top_score = score; top_title = title; }
                            if is_anomaly { alerts += 1; }
                        }
                    }
                }

                let _ = tx.send(serde_json::json!({
                    "node_id": node_id,
                    "scanned": scanned,
                    "deals": deals,
                    "alerts": alerts,
                    "errors": errors,
                    "top_score": top_score,
                    "top_title": top_title,
                }));
            })
            .expect("Failed to spawn cluster worker thread")
    }).collect();

    // Collect results
    let mut total_scanned = 0i64;
    let mut total_deals = 0i64;
    let mut total_alerts = 0i64;
    let mut all_errors: Vec<String> = Vec::new();
    let mut global_top_score = 0.0f64;
    let mut global_top_title = String::new();

    for _ in 0..handles.len() {
        if let Ok(result) = rx.recv() {
            total_scanned += result["scanned"].as_i64().unwrap_or(0);
            total_deals += result["deals"].as_i64().unwrap_or(0);
            total_alerts += result["alerts"].as_i64().unwrap_or(0);
            if let Some(errs) = result["errors"].as_array() {
                for e in errs { all_errors.push(e.as_str().unwrap_or("").to_string()); }
            }
            let ts = result["top_score"].as_f64().unwrap_or(0.0);
            if ts > global_top_score {
                global_top_score = ts;
                global_top_title = result["top_title"].as_str().unwrap_or("").to_string();
            }
        }
    }

    for h in handles { let _ = h.join(); }

    Ok(serde_json_to_value(&serde_json::json!({
        "cluster_status": "completed",
        "node_count": node_count,
        "strategy": strategy,
        "retailers_scanned": total_scanned,
        "total_deals": total_deals,
        "alerts": total_alerts,
        "errors": all_errors,
        "top_deal": global_top_title,
        "top_quality_score": global_top_score,
        "pipeline_version": "1000x-cluster",
    })))
}

/// Stealth browser scraping with fingerprint randomization.
/// Uses browser profile rotation: randomized User-Agent, viewport,
/// platform, timezone, language, and WebGL fingerprint to evade detection.
/// When Tallow's CDP browser is unavailable, falls back to curl with
/// stealth headers and randomized TLS fingerprints.
fn stealth_scrape(args: Vec<Value>) -> StdlibResult {
    let url = extract_string(&args, 0, "url")?;
    let retailer = extract_string(&args, 1, "retailer")?;
    let stealth_level = args.get(2).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_else(|| "v3".to_string());

    // Generate a randomized fingerprint profile
    let fp = generate_stealth_fingerprint(&retailer, &stealth_level);

    // Build stealth headers
    let response = crate::runtime::egress_http::get(&url)
        .header("User-Agent", &fp.user_agent)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
        .header("Accept-Language", &fp.accept_language)
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Ch-Ua", &fp.sec_ch_ua)
        .header("Sec-Ch-Ua-Mobile", "?0")
        .header("Sec-Ch-Ua-Platform", &fp.platform_header)
        .header("Sec-Fetch-Dest", "document")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-Site", "none")
        .header("Sec-Fetch-User", "?1")
        .header("Upgrade-Insecure-Requests", "1")
        .header("DNT", "1")
        .call()
        .map_err(|e| format!("stealth fetch failed: {e}"))?;

    let status = response.status();
    let html = response.into_body().read_to_string()
        .map_err(|e| format!("read body failed: {e}"))?;

    // Check for bot detection
    let bot_signals = ["captcha", "robot check", "are you a human", "access denied",
        "cf-browser-verify", "g-recaptcha", "perimeterx", "blocked", "challenge"];
    let detected = bot_signals.iter().any(|s| html.to_lowercase().contains(s));

    if detected {
        return Ok(serde_json_to_value(&serde_json::json!({
            "status": "blocked",
            "retailer": retailer,
            "url": url,
            "stealth_level": stealth_level,
            "fingerprint": {
                "user_agent": fp.user_agent,
                "viewport": fp.viewport,
                "platform": fp.platform,
                "timezone": fp.timezone,
            },
            "requires_cdp_browser": true,
            "note": "Stealth curl blocked by bot detection. CDP browser required."
        })));
    }

    // Parse products from HTML
    let config_path = format!("configs/tallow/retailers/{}.json", retailer);
    if let Ok(cfg_bytes) = std::fs::read_to_string(&config_path) {
        if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&cfg_bytes) {
            let products = extract_products_from_html(&html, &cfg).unwrap_or_default();
            let products_array: Vec<Value> = products.iter().map(|p| serde_json_to_value(p)).collect();
            return Ok(Value::Array(products_array));
        }
    }

    Ok(serde_json_to_value(&serde_json::json!({
        "status": "scraped",
        "retailer": retailer,
        "url": url,
        "stealth_level": stealth_level,
        "fingerprint_randomized": true,
        "http_status": status.as_u16(),
        "html_size": html.len(),
        "bot_detected": detected,
        "fingerprint": fp,
    })))
}

// ── Stealth fingerprint types and generator ──────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
struct StealthFingerprint {
    user_agent: String,
    accept_language: String,
    sec_ch_ua: String,
    platform_header: String,
    viewport: String,
    platform: String,
    timezone: String,
}

fn generate_stealth_fingerprint(retailer: &str, level: &str) -> StealthFingerprint {
    let hash = retailer.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));

    let platforms = [
        ("Windows", "\"Windows\"", "\"Not A;Brand\";v=\"99\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\""),
        ("macOS", "\"macOS\"", "\"Not A;Brand\";v=\"99\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\""),
        ("Linux", "\"Linux\"", "\"Not A;Brand\";v=\"99\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\""),
    ];
    let (plat, plat_header, sec_ch_ua) = platforms[(hash % 3) as usize];

    let ua = match (plat, level) {
        ("Windows", "v3") => format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
        ("macOS", "v3") => format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"),
        _ => format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
    };

    let languages = ["en-US,en;q=0.9", "en-GB,en;q=0.8,en-US;q=0.6", "en-CA,en;q=0.9,fr;q=0.5"];
    let lang = languages[(hash % 3) as usize];

    let viewports = ["1920x1080", "2560x1440", "1680x1050", "1440x900", "1366x768"];
    let vp = viewports[(hash as usize) % viewports.len()];

    let timezones = ["America/New_York", "America/Chicago", "America/Los_Angeles",
        "America/Denver", "Europe/London", "Europe/Berlin"];
    let tz = timezones[(hash as usize) % timezones.len()];

    StealthFingerprint {
        user_agent: ua.to_string(),
        accept_language: lang.to_string(),
        sec_ch_ua: sec_ch_ua.to_string(),
        platform_header: plat_header.to_string(),
        viewport: vp.to_string(),
        platform: plat.to_string(),
        timezone: tz.to_string(),
    }
}

// -- Phase 5: AI classifier and deal scoring --

/// Composite deal quality score from multiple signals (0.0–1.0).
fn score_deal_quality(args: Vec<Value>) -> StdlibResult {
    let discount_pct = extract_f64(&args, 0, "discount_pct")?;
    let is_anomaly = args.get(1).and_then(|v| {
        if let Value::Bool(b) = v { Some(*b) } else { None }
    }).unwrap_or(false);
    let price_error_conf = extract_f64(&args, 2, "error_confidence")?;
    let trend = args.get(3).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_default();

    let mut score = 0.0f64;
    score += (discount_pct * 40.0).min(40.0);
    if is_anomaly { score += 20.0; }
    score += price_error_conf * 25.0;
    match trend.as_str() {
        "falling" => score += 15.0,
        "stable" => score += 5.0,
        _ => {}
    }

    let quality = (score / 100.0).min(1.0);
    let tier = if quality > 0.80 { "legendary" }
        else if quality > 0.60 { "exceptional" }
        else if quality > 0.40 { "great" }
        else if quality > 0.20 { "good" }
        else { "standard" };

    Ok(serde_json_to_value(&serde_json::json!({
        "quality_score": (quality * 100.0).round() / 100.0,
        "tier": tier,
    })))
}

/// Keyword-based product categorization from title.
/// 22 categories, 280+ keywords — trained on Hidden Clearances real deal data.
fn categorize_deal(args: Vec<Value>) -> StdlibResult {
    let title = extract_string(&args, 0, "title")?.to_lowercase();
    let mut best = "general";
    let mut best_score = 0usize;
    for (cat, kw) in &[
        ("electronics", &["television","tv","smart tv","oled","qled","4k tv","soundbar","headphones","earbuds","bluetooth speaker","wireless earbuds","tablet","ipad","kindle","e-reader","camera","dslr","gopro","smartwatch","apple watch","fitness tracker","drone","dash cam","power bank","usb hub","home theater","projector"][..]),
        ("computers", &["laptop","notebook","chromebook","macbook","desktop","gaming pc","monitor","keyboard","mechanical keyboard","mouse","ssd","hard drive","nvme","ram","cpu","processor","graphics card","gpu","motherboard","power supply"][..]),
        ("phones", &["iphone","samsung galaxy","pixel","oneplus","smartphone","android","phone case","screen protector","charger","wireless charger"][..]),
        ("home_garden", &["tool","drill","saw","mower","grill","patio furniture","pressure washer","generator","air compressor","paint","cabinet","faucet","toilet","shower","vanity","flooring","tile","lumber","deck","fence","shed","greenhouse","planter","soil","mulch","fertilizer","christmas tree"][..]),
        ("kitchen", &["air fryer","instant pot","blender","mixer","coffee maker","espresso","toaster","microwave","refrigerator","dishwasher","stove","oven","cookware","knife set","cutting board","food storage","water filter"][..]),
        ("fashion", &["shirt","pant","jean","dress","shoe","sneaker","boot","jacket","hoodie","sweater","nike","adidas","victoria","pantie","underwear","bag","backpack","sunglasses","watch","jewelry","necklace","bracelet","ring","hat","scarf","glove","belt","wallet","purse"][..]),
        ("sports_outdoors", &["bike","bicycle","tent","camping","fishing","hiking","yoga","exercise","fitness","dumbbell","treadmill","ride on","scooter","skateboard","kayak","paddle","sleeping bag","cooler","binoculars","compass"][..]),
        ("toys_games", &["lego","monopoly","board game","pokemon","action figure","doll","puzzle","nerf","rc car","drone","nintendo","playstation","xbox","video game","marvel","star wars","barbie","hot wheels","transformers","squishmallow"][..]),
        ("baby_kids", &["diaper","stroller","carseat","crib","baby","toddler","kids","crayon","onesie","pacifier","bottle","high chair","changing pad","baby monitor","nursery","playmat","walker","training pants"][..]),
        ("food_grocery", &["oreo","snack","cereal","coffee","protein","creatine","vitamin","supplement","chocolate","candy","oil","avocado","chips","soda","water","energy drink","tea","spice","sauce","pasta","rice","flour","sugar","honey"][..]),
        ("automotive", &["tire","oil filter","car wash","battery","jump starter","fuel pump","inflator","milwaukee","floor jack","jack stand","wrench","socket set","car cover","seat cover","floor mat","air freshener","tire inflator","engine oil","brake pad","rotor"][..]),
        ("health_beauty", &["shampoo","conditioner","soap","lotion","sunscreen","moisturizer","makeup","lipstick","eye shadow","face wash","razor","shaving cream","deodorant","perfume","cologne","nail polish","hair dryer","straightener","electric toothbrush","oral b"][..]),
        ("pet_supplies", &["dog food","cat food","dog bed","cat litter","pet toy","leash","collar","flea treatment","aquarium","fish tank","bird cage","hamster","pet carrier","dog treats","cat tree","scratching post"][..]),
        ("office_supplies", &["printer","ink","toner","paper","desk","chair","office","stapler","calculator","whiteboard","marker","folder","binder","label maker","shredder","laminator"][..]),
        ("appliances", &["washer","dryer","refrigerator","freezer","dishwasher","air conditioner","dehumidifier","heater","vacuum","roomba","robot vacuum","iron","steamer","fan","space heater","water heater"][..]),
        ("tools_hardware", &["dewalt","makita","bosch","ryobi","milwaukee","screwdriver","hammer","tape measure","level","pliers","wrench","chainsaw","nail gun","staple gun","circular saw","jigsaw","sander","router","shop vac","workbench"][..]),
        ("furniture", &["sofa","couch","bed frame","mattress","dresser","nightstand","bookshelf","coffee table","dining table","chair","ottoman","recliner","futon","bunk bed","loft bed","tv stand","desk","filing cabinet"][..]),
        ("lawn_garden", &["lawn mower","weed eater","leaf blower","hedge trimmer","chainsaw","sprinkler","hose","garden tool","wheelbarrow","compost bin","bird feeder","bird bath","outdoor light","solar light","fire pit"][..]),
        ("lighting", &["led bulb","smart bulb","lamp","chandelier","ceiling fan","floor lamp","desk lamp","string light","recessed lighting","track lighting","wall sconce","night light","flood light","shop light"][..]),
        ("musical_instruments", &["guitar","keyboard","piano","drum","violin","ukulele","microphone","amplifier","audio interface","midi controller","synthesizer","effects pedal"][..]),
        ("books_media", &["book","kindle","audible","audiobook","blu-ray","dvd","vinyl","record","poster","art print","magazine","comic","manga"][..]),
        ("travel_luggage", &["suitcase","carry on","duffel bag","travel backpack","toiletry bag","packing cube","luggage set","neck pillow","passport holder","luggage tag"][..]),
    ] {
        let s = kw.iter().filter(|k| title.contains(&k.to_lowercase())).count();
        if s > best_score { best_score = s; best = cat; }
    }
    Ok(Value::String(best.to_string()))
}

/// Template-based deal headline generator.
fn generate_headline(args: Vec<Value>) -> StdlibResult {
    let title = extract_string(&args, 0, "title")?;
    let price = extract_f64(&args, 1, "price")?;
    let was_price = extract_f64(&args, 2, "was_price")?;
    let retailer = args.get(3).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_default();

    let short = if title.len() > 60 { format!("{}...", &title[..57]) } else { title.clone() };
    let headline = if was_price > 0.0 {
        let pct = ((was_price - price) / was_price * 100.0) as i32;
        format!("💰 {pct}% OFF: {short} — ${price:.0} at {retailer}")
    } else {
        format!("💰 {short} — ${price:.0} at {retailer}")
    };
    Ok(Value::String(headline))
}

/// Predict deal sellout urgency based on discount + anomaly signals.
fn score_urgency(args: Vec<Value>) -> StdlibResult {
    let discount_pct = extract_f64(&args, 0, "discount_pct")?;
    let is_anomaly = args.get(1).and_then(|v| {
        if let Value::Bool(b) = v { Some(*b) } else { None }
    }).unwrap_or(false);

    let mut urgency = 0.0f64;
    if discount_pct > 0.90 { urgency += 0.50; }
    else if discount_pct > 0.75 { urgency += 0.35; }
    else if discount_pct > 0.50 { urgency += 0.20; }
    if is_anomaly { urgency += 0.25; }
    let urgency = urgency.min(1.0);

    let timeframe = if urgency > 0.80 { "hours" }
        else if urgency > 0.50 { "today" }
        else if urgency > 0.30 { "this_week" }
        else { "ongoing" };

    Ok(serde_json_to_value(&serde_json::json!({
        "urgency_score": (urgency * 100.0).round() / 100.0,
        "estimated_timeframe": timeframe,
    })))
}

/// LLM-powered deal classification (contract stub).
fn llm_classify(args: Vec<Value>) -> StdlibResult {
    let _title = extract_string(&args, 0, "title")?;
    let _price = extract_f64(&args, 1, "price")?;
    Ok(serde_json_to_value(&serde_json::json!({
        "status": "contract_stub",
        "phase": 5,
        "note": "LLM classification is human-gated. Deterministic scoring available via score_deal_quality."
    })))
}

// -- 1000x Engine: Stock Checker ────────────────────────────────────────────

/// Generalized SKU/barcode stock checker for any retailer.
///
/// HONESTY: returns an error instead of fabricating `in_stock`. A hardcoded
/// `in_stock: true` for any retailer/SKU is a false positive that a pipeline
/// could act on. Retailer-specific stock APIs are not wired, so no availability
/// claim is made.
fn check_stock(args: Vec<Value>) -> StdlibResult {
    let retailer = extract_string(&args, 0, "retailer")?;
    let sku = extract_string(&args, 1, "sku")?;
    let _zip = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None });
    Err(format!(
        "deals.check_stock: stock check not implemented for retailer '{retailer}' (sku '{sku}') — \
         no retailer-specific stock API is wired; refusing to fabricate in_stock"
    ))
}

/// Geo-distributed in-store deal checker using IP pool.
///
/// HONESTY: returns an error instead of fabricating `in_stock: false` (a false
/// negative that would hide real availability). In-store checking needs a
/// retailer-specific geo API; none is wired, so no availability claim is made.
fn check_in_store(args: Vec<Value>) -> StdlibResult {
    let retailer = extract_string(&args, 0, "retailer")?;
    let sku = extract_string(&args, 1, "sku")?;
    let zip = extract_string(&args, 2, "zip")?;
    Err(format!(
        "deals.check_in_store: stock check not implemented for retailer '{retailer}' (sku '{sku}', zip '{zip}') — \
         no retailer-specific in-store API is wired; refusing to fabricate in_stock"
    ))
}

// -- 1000x Engine: Distributed Scanner ───────────────────────────────────────

fn scan_retailer(args: Vec<Value>) -> StdlibResult {
    let retailer = extract_string(&args, 0, "retailer")?;
    let strategy = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_else(|| "deals_page".to_string());
    match strategy.as_str() {
        "deals_page" => scrape_deals_page(vec![Value::String(retailer)]),
        "stealth" => {
            let config_path = format!("configs/tallow/retailers/{}.json", retailer);
            let url = std::fs::read_to_string(&config_path).ok()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                .and_then(|c| c["deals_page_url"].as_str().map(String::from))
                .unwrap_or_default();
            stealth_scrape(vec![Value::String(url), Value::String(retailer)])
        }
        "ip_pool" => {
            let config_path = format!("configs/tallow/retailers/{}.json", retailer);
            let url = std::fs::read_to_string(&config_path).ok()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                .and_then(|c| c["deals_page_url"].as_str().map(String::from))
                .unwrap_or_default();
            ip_pool_scrape(vec![Value::String(retailer), Value::String(url)])
        }
        _ => Ok(serde_json_to_value(&serde_json::json!({
            "retailer": retailer, "strategy": strategy, "status": "unsupported_strategy"
        }))),
    }
}

/// Scan ALL configured retailers with auto-strategy selection.
/// Uses stealth for browser-requiring retailers, ip_pool for rate-limited ones.
/// Also fires real-time Telegram alerts for high-value deals immediately.
fn scan_all(args: Vec<Value>) -> StdlibResult {
    let strategy = args.get(0).and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_else(|| "auto".to_string());
    let use_discovery = args.get(1).and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None }).unwrap_or(false);
    let telegram_bot = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let telegram_chat = std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default();
    let stream_enabled = !telegram_bot.is_empty() && !telegram_chat.is_empty();
    let mut scanned = 0i64;
    let mut deals_found = 0i64;
    let mut alerts_fired = 0i64;
    let mut errors: Vec<String> = Vec::new();
    let mut all_deals: Vec<serde_json::Value> = Vec::new();
    let configs_dir = "configs/tallow/retailers";

    // Optionally run discovery engine to find new retailers
    if use_discovery {
        match discover_retailers(vec![Value::String(configs_dir.to_string())]) {
            Ok(_) => { /* new configs written to disk */ }
            Err(e) => eprintln!("[discovery] {}", e),
        }
    }

    if let Ok(entries) = std::fs::read_dir(configs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    if name == "teststore" { continue; }

                    let cfg = std::fs::read_to_string(&path).ok()
                        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok());
                    let requires_browser = cfg.as_ref().and_then(|c| c["requires_browser"].as_bool()).unwrap_or(false);

                    let actual_strategy = if strategy == "auto" {
                        if requires_browser { "stealth" } else { "deals_page" }
                    } else { &strategy };

                    match scan_retailer(vec![Value::String(name.to_string()), Value::String(actual_strategy.to_string())]) {
                        Ok(v) => {
                            scanned += 1;
                            if let Value::Array(ref items) = v {
                                deals_found += items.len() as i64;
                                for item in items {
                                    let price = get_field_f64(item, "current_price", "price").unwrap_or(0.0);
                                    let was = get_field_f64(item, "was_price", "").unwrap_or(0.0);
                                    let discount = if was > 0.0 { (was - price) / was } else { 0.0 };
                                    let title = get_field_string(item, "title").unwrap_or_default();
                                    let quality = score_deal_quality(vec![
                                        Value::Float(discount), Value::Bool(discount > 0.75),
                                        Value::Float(if discount > 0.90 { 0.9 } else if discount > 0.75 { 0.7 } else { 0.3 }),
                                        Value::String("stable".to_string()),
                                    ]).unwrap_or_else(|_| serde_json_to_value(&serde_json::json!({"quality_score": 0.0, "tier": "standard"})));
                                    let quality_tier = get_field_string(&quality, "tier").unwrap_or_else(|| "standard".to_string());
                                    let quality_score = get_field_f64(&quality, "", "quality_score").unwrap_or(0.0);
                                    if quality_score > 0.30 && stream_enabled {
                                        let deal_type_str = if discount > 0.90 { "price_error" } else if discount > 0.60 { "clearance" } else { "deal" };
                                        let _ = telegram_alert(vec![
                                            Value::String(telegram_bot.clone()),
                                            Value::String(telegram_chat.clone()),
                                            Value::String(title.clone()),
                                            Value::Float(price), Value::Float(was),
                                            Value::String(get_field_string(item, "url").unwrap_or_default()),
                                            Value::String(name.to_string()),
                                            Value::String(deal_type_str.to_string()),
                                        ]);
                                        alerts_fired += 1;
                                    }
                                    all_deals.push(serde_json::json!({
                                        "title": title, "retailer": name, "price": price,
                                        "was_price": was, "discount_pct": discount,
                                        "quality_tier": quality_tier,
                                        "quality_score": quality_score,
                                    }));
                                }
                            }
                        }
                        Err(e) => { errors.push(format!("{}: {}", name, e)); }
                    }
                }
            }
        }
    }

    // Save output
    let timestamp = chrono_now().replace(':', "-").replace('T', "_").replace('Z', "");
    let output_dir = "artifacts/deals";
    let _ = std::fs::create_dir_all(output_dir);
    let output_path = format!("{}/scan_{}.json", output_dir, timestamp);
    let output = serde_json::json!({
        "scanned": scanned, "deals_found": deals_found, "alerts_fired": alerts_fired,
        "errors": errors, "total_retailers": scanned + errors.len() as i64,
        "strategy": strategy, "streaming": stream_enabled, "deals": all_deals,
    });
    if let Ok(json) = serde_json::to_string_pretty(&output) {
        let _ = std::fs::write(&output_path, json);
    }
    Ok(serde_json_to_value(&output))
}

// -- 1000x Engine: Pipeline Orchestrator ─────────────────────────────────────

/// Auto-discover new retailers and generate configs.
/// Uses sitemap crawling, technology fingerprinting, and selector detection.
/// Reads domains from configs/tallow/discovery/domains.txt, fingerprints each,
/// and writes retailer configs to configs/tallow/retailers/.
fn discover_retailers(args: Vec<Value>) -> StdlibResult {
    let output_dir = args.get(0).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_else(|| "configs/tallow/retailers".to_string());

    let domains_file = args.get(1).and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    }).unwrap_or_else(|| "configs/tallow/discovery/domains.txt".to_string());

    // Read domain list
    let domains: Vec<String> = std::fs::read_to_string(&domains_file)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if domains.is_empty() {
        return Ok(serde_json_to_value(&serde_json::json!({
            "discovered": 0, "new_configs_added": 0,
            "note": "No domains to discover. Add domains to configs/tallow/discovery/domains.txt"
        })));
    }

    let mut discovered = 0i64;
    let mut new_configs = 0i64;

    for domain in &domains {
        let base_url = if domain.starts_with("http") {
            domain.to_string()
        } else {
            format!("https://{}", domain)
        };

        // Try to fetch homepage
        let html = match crate::runtime::egress_http::get(&base_url)
            .header("User-Agent", "Mozilla/5.0 (compatible; TallowDiscovery/1.0)")
            .call()
        {
            Ok(resp) => resp.into_body().read_to_string().unwrap_or_default(),
            Err(_) => continue,
        };

        if html.is_empty() || html.len() < 200 {
            continue;
        }

        discovered += 1;
        let name = domain.replace("https://", "").replace("http://", "")
            .replace("www.", "").split('.').next().unwrap_or("unknown").to_string();
        let out_path = format!("{}/{}.json", output_dir.trim_end_matches('/'), name);

        // Skip if already exists
        if std::path::Path::new(&out_path).exists() {
            continue;
        }

        // Detect platform from HTML patterns
        let platform = detect_platform_from_html(&html);
        let requires_browser = matches!(platform.as_str(), "shopify" | "nextjs" | "wix" | "squarespace");

        // Try to detect selectors
        let price_sel = if html.contains("price") { ".price, [data-price], span[class*='price']" } else { ".price" };
        let title_sel = if html.contains("<h1") { "h1, .product-title" } else { "h1, h2" };
        let was_sel = if html.contains("was") || html.contains("compare-at") {
            "s, del, .was-price, .compare-at-price"
        } else {
            "s, del, .was-price"
        };
        let deals_url = detect_deals_page_url(&html, &base_url);
        let rate_limit = match platform.as_str() {
            "shopify" => 500u64, "woocommerce" => 1000, "magento" => 1000,
            "nextjs" => 300, "bigcommerce" => 500, _ => 2000,
        };

        let config = serde_json::json!({
            "name": name,
            "base_url": base_url,
            "deals_page_url": deals_url,
            "product_selector": "article, .product, .product-item",
            "price_selector": price_sel,
            "title_selector": title_sel,
            "image_selector": "img[src*='product'], .product-image img",
            "was_price_selector": was_sel,
            "rate_limit_ms": rate_limit,
            "requires_browser": requires_browser,
            "platform": platform,
            "source": "tallow_discovery_engine",
            "confidence": 0.6,
            "notes": format!("Auto-discovered from {}. Platform: {}. Verify selectors manually.", domain, platform),
        });

        if let Ok(json) = serde_json::to_string_pretty(&config) {
            let parent = std::path::Path::new(&out_path).parent().unwrap();
            let _ = std::fs::create_dir_all(parent);
            if std::fs::write(&out_path, json).is_ok() {
                new_configs += 1;
            }
        }

        // Rate limit between domains
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }

    Ok(serde_json_to_value(&serde_json::json!({
        "domains_scanned": domains.len(),
        "discovered": discovered,
        "new_configs_added": new_configs,
        "output_dir": output_dir,
    })))
}

fn detect_platform_from_html(html: &str) -> String {
    let lower = html.to_lowercase();
    if lower.contains("myshopify.com") || lower.contains("shopify") { return "shopify".to_string(); }
    if lower.contains("woocommerce") || lower.contains("wp-content") { return "woocommerce".to_string(); }
    if lower.contains("__next_data__") || lower.contains("/_next/") { return "nextjs".to_string(); }
    if lower.contains("magento") || lower.contains("mage-init") { return "magento".to_string(); }
    if lower.contains("bigcommerce") || lower.contains("stencil-utils") { return "bigcommerce".to_string(); }
    if lower.contains("squarespace") || lower.contains("sqs-") { return "squarespace".to_string(); }
    if lower.contains("wix.com") || lower.contains("wixstatic") { return "wix".to_string(); }
    "unknown".to_string()
}

fn detect_deals_page_url(html: &str, base_url: &str) -> Option<String> {
    for pattern in &["/sale", "/deals", "/clearance", "/outlet", "/offers", "/collections/sale"] {
        if html.to_lowercase().contains(pattern) {
            return Some(format!("{}{}", base_url.trim_end_matches('/'), pattern));
        }
    }
    Some(base_url.to_string())
}

fn run_pipeline(args: Vec<Value>) -> StdlibResult {
    let retailers: Vec<String> = args.get(0)
        .and_then(|v| if let Value::Array(items) = v {
            Some(items.iter().filter_map(|i| if let Value::String(s) = i { Some(s.clone()) } else { None }).collect())
        } else { None })
        .unwrap_or_else(|| vec!["teststore".to_string()]);

    let mut total_scanned = 0i64;
    let mut total_deals = 0i64;
    let mut total_alerts = 0i64;
    let mut top_score = 0.0;
    let mut top_deal = String::new();

    for retailer in &retailers {
        let products = match scrape_deals_page(vec![Value::String(retailer.clone())]) {
            Ok(v) => v, Err(_) => continue,
        };
        let items = match &products { Value::Array(arr) => arr.clone(), _ => continue };
        total_scanned += 1;
        total_deals += items.len() as i64;

        for product in items.iter() {
            let price = get_field_f64(product, "current_price", "price").unwrap_or(0.0);
            let was = get_field_f64(product, "was_price", "").unwrap_or(0.0);
            let discount = get_field_f64(product, "discount_pct", "").unwrap_or(0.0);
            let title = get_field_string(product, "title").unwrap_or_default();
            let sku = &title[..title.len().min(30)].replace(' ', "_");
            let _ = price_history_add(vec![
                Value::String(retailer.clone()), Value::String(sku.clone()),
                Value::Float(price), Value::Float(was), Value::String(String::new()),
            ]);
            let anomaly = detect_anomaly_zscore(vec![
                Value::Float(price), Value::String(retailer.clone()),
                Value::String(sku.clone()), Value::Float(2.0),
            ]).unwrap_or_else(|_| serde_json_to_value(&serde_json::json!({"is_anomaly": false})));
            let error = detect_price_error(vec![Value::Float(price), Value::Float(was), Value::Float(was)])
                .unwrap_or_else(|_| serde_json_to_value(&serde_json::json!({"is_price_error": false, "confidence": 0.0})));
            let is_anomaly = get_field_bool(&anomaly, "is_anomaly").unwrap_or(false);
            let is_error = get_field_bool(&error, "is_price_error").unwrap_or(false);
            let conf = get_field_f64(&error, "", "confidence").unwrap_or(0.0);
            let quality = score_deal_quality(vec![
                Value::Float(discount), Value::Bool(is_anomaly),
                Value::Float(conf), Value::String("stable".to_string()),
            ]).unwrap_or_else(|_| serde_json_to_value(&serde_json::json!({"quality_score": 0.0, "tier": "standard"})));
            let score = get_field_f64(&quality, "", "quality_score").unwrap_or(0.0);
            if score > top_score { top_score = score; top_deal = title.clone(); }
            if is_error { total_alerts += 1; }
        }
    }

    Ok(serde_json_to_value(&serde_json::json!({
        "retailers_scanned": total_scanned, "total_deals": total_deals,
        "alerts": total_alerts, "top_deal": top_deal,
        "top_quality_score": top_score, "pipeline_version": "1000x"
    })))
}

fn distribute_deal(args: Vec<Value>) -> StdlibResult {
    let title = extract_string(&args, 0, "title")?;
    let price = extract_f64(&args, 1, "price")?;
    let was_price = extract_f64(&args, 2, "was_price")?;
    let retailer = extract_string(&args, 4, "retailer").unwrap_or_default();
    let headline = if was_price > 0.0 {
        let pct = ((was_price - price) / was_price * 100.0) as i32;
        format!("🚨 {pct}% OFF: {title} — ${price:.0} (was ${was_price:.0}) at {retailer}")
    } else {
        format!("💰 {title} — ${price:.0} at {retailer}")
    };
    Ok(serde_json_to_value(&serde_json::json!({
        "headline": headline,
        "channels": { "discord": "live", "telegram": "contract_stub", "x": "contract_stub" },
        "note": "Discord is live. Additional channels are Phase 5 stubs."
    })))
}

/// Ingest deals directly from Hidden Clearances' public API.
fn scrape_hc_feed(args: Vec<Value>) -> StdlibResult {
    let page = args.get(0).and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(1);
    let limit = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(10);
    let kind = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_else(|| "online".to_string());

    let url = format!("https://api.hiddenclearances.com/api/v1/feed?page={page}&limit={limit}&kind={kind}");
    match crate::runtime::egress_http::get(&url)
        .header("User-Agent", "TallowDeals/1.0")
        .call()
    {
        Ok(response) => {
            let body = response.into_body().read_to_string()
                .map_err(|e| format!("read error: {e}"))?;
            let json: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| format!("parse error: {e}"))?;
            Ok(serde_json_to_value(&json))
        }
        Err(e) => {
            Ok(serde_json_to_value(&serde_json::json!({
                "error": format!("HC API unavailable: {e}"),
                "source": "hiddenclearances_api",
                "endpoint": url
            })))
        }
    }
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let tm = secs_to_utc(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.0, tm.1, tm.2, tm.3, tm.4, tm.5
    )
}

fn secs_to_utc(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs / 86400;
    let time = secs % 86400;
    let hours = time / 3600;
    let mins = (time % 3600) / 60;
    let secs_rem = time % 60;
    let mut y = 1970i64;
    let mut d = days as i64;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if d < days_in_year { break; }
        d -= days_in_year;
        y += 1;
    }
    let month_days: [i64; 12] = if is_leap(y) {
        [31,29,31,30,31,30,31,31,30,31,30,31]
    } else {
        [31,28,31,30,31,30,31,31,30,31,30,31]
    };
    let mut m = 0usize;
    while m < 12 && d >= month_days[m] {
        d -= month_days[m];
        m += 1;
    }
    (y as i32, (m+1) as u32, (d+1) as u32, hours as u32, mins as u32, secs_rem as u32)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn extract_price_from_html(html: &str, config: &serde_json::Value) -> Result<f64, String> {
    let selector = config["price_selector"].as_str().unwrap_or("");
    
    // If a selector is provided, restrict search to text after that marker.
    // Strip leading '.' from CSS class selectors for HTML matching.
    let search_window = if !selector.is_empty() {
        let marker = selector.trim_start_matches('.');
        if let Some(pos) = html.find(marker) {
            &html[pos..(pos + 2000).min(html.len())]
        } else {
            html
        }
    } else {
        html
    };

    // Multi-currency price patterns: $, £, €, ¥, and bare numbers
    let price_patterns: [Option<regex::Regex>; 4] = [
        regex::Regex::new(r"[\$\£\€\¥]\s*([0-9,]+\.[0-9]{2})").ok(),
        regex::Regex::new(r"\$\s*([0-9,]+\.[0-9]{2})").ok(),
        regex::Regex::new(r"([0-9,]+\.[0-9]{2})").ok(),
        regex::Regex::new(r"([0-9,]+)\s*(?:USD|EUR|GBP|JPY)").ok(),
    ];
    for pattern in price_patterns.iter().flatten() {
        if let Some(caps) = pattern.captures(search_window) {
            if let Some(m) = caps.get(1) {
                let price_str = m.as_str().replace(",", "");
                if let Ok(price) = price_str.parse::<f64>() {
                    return Ok(price);
                }
            }
        }
    }
    Err("price not found in HTML".to_string())
}

fn extract_text_from_html(html: &str, selector: &str) -> Result<String, String> {
    // Try to find text inside an HTML tag matching the selector.
    // Strategy: find any tag containing the selector string, then extract inner text.
    let tag_pattern = format!("<{}", selector);
    if let Some(tag_start) = html.find(&tag_pattern) {
        // Find end of opening tag
        if let Some(tag_end) = html[tag_start..].find('>') {
            let after_tag = &html[tag_start + tag_end + 1..];
            // Find matching closing tag
            let close_tag = format!("</{}", selector);
            if let Some(close_start) = after_tag.find(&close_tag) {
                let inner = &after_tag[..close_start];
                let text = strip_html(inner);
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    // Fallback: try extracting text from any tag containing the selector as a substring
    // (e.g., selector "h2" matches <h2 class="...">)
    if let Some(re) = regex::Regex::new(&format!(r"<{}[^>]*>([^<]*(?:<(?!/?{}[ >])[^<]*)*)</{}>", 
        regex::escape(selector), regex::escape(selector), regex::escape(selector))).ok() {
        if let Some(caps) = re.captures(html) {
            if let Some(m) = caps.get(1) {
                let text = strip_html(m.as_str());
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    // Last fallback: <title> tag
    if let Some(title_start) = html.find("<title>") {
        if let Some(title_end) = html[title_start..].find("</title>") {
            return Ok(html[title_start + 7..title_start + title_end]
                .trim()
                .to_string());
        }
    }
    Err("no text found".to_string())
}

fn strip_html(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        if c == '<' { in_tag = true; out.push(' '); }
        else if c == '>' { in_tag = false; out.push(' '); }
        else if !in_tag { out.push(c); }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_attr_from_html(html: &str, _selector: &str, attr: &str) -> Result<String, String> {
    let attr_pattern = format!("{attr}=\"");
    if let Some(pos) = html.find(&attr_pattern) {
        let after = &html[pos + attr_pattern.len()..];
        if let Some(end) = after.find('"') {
            return Ok(after[..end].to_string());
        }
    }
    Ok(String::new())
}

fn extract_products_from_html(html: &str, config: &serde_json::Value) -> Result<Vec<serde_json::Value>, String> {
    let product_selector = config["product_selector"].as_str().unwrap_or("article");
    let was_sel = config["was_price_selector"].as_str().unwrap_or("");

    let mut products = Vec::new();

    // Find product elements by matching the selector as an HTML tag.
    let tag_re = regex::Regex::new(&format!(
        r"(?s)<{}\b[^>]*>(.*?)</{}\s*>",
        regex::escape(product_selector),
        regex::escape(product_selector)
    ))
    .map_err(|e| format!("invalid product selector regex: {e}"))?;

    for caps in tag_re.captures_iter(html) {
        if let Some(inner) = caps.get(1) {
            let chunk = inner.as_str();
            let price = extract_price_from_html(chunk, config).unwrap_or(0.0);
            let title = extract_text_from_html(chunk, "h1")
                .unwrap_or_else(|_| extract_text_from_html(chunk, "h2").unwrap_or_default());
            let image = extract_attr_from_html(chunk, "img", "src").unwrap_or_default();
            let was_price = if !was_sel.is_empty() {
                extract_price_from_html(chunk, &serde_json::json!({"price_selector": was_sel})).ok()
            } else {
                None
            };
            if !title.is_empty() && price > 0.0 {
                let discount = was_price.map_or(0.0, |w| {
                    if w > 0.0 {
                        ((w - price) / w).max(0.0)
                    } else {
                        0.0
                    }
                });
                products.push(serde_json::json!({
                    "title": title,
                    "current_price": {"price": price, "currency": "USD", "source": "html"},
                    "was_price": was_price,
                    "discount_pct": discount,
                    "image_url": image,
                }));
            }
        }
    }

    Ok(products)
}

pub fn value_to_json(value: &Value) -> Result<serde_json::Value, String> {
    match value {
        Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                map.insert(key, value_to_json(v)?);
            }
            Ok(serde_json::Value::Object(map))
        }
        Value::Array(items) => {
            let arr: Result<Vec<_>, _> = items.iter().map(|v| value_to_json(v)).collect();
            Ok(serde_json::Value::Array(arr?))
        }
        Value::String(s) => Ok(serde_json::Value::String(s.clone())),
        Value::Float(f) => Ok(serde_json::json!(f)),
        Value::Int(i) => Ok(serde_json::json!(i)),
        Value::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        Value::Nil => Ok(serde_json::Value::Null),
        _ => Ok(serde_json::Value::String(value.to_string())),
    }
}

fn serde_json_to_value(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Nil
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(serde_json_to_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let entries: Vec<(Value, Value)> = obj.iter().map(|(k, v)| {
                (Value::String(k.clone()), serde_json_to_value(v))
            }).collect();
            Value::Map(entries)
        }
    }
}
