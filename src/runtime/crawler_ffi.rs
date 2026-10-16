//! Runtime FFI: `Crawler.from_links`.
//!
//! # Shape
//!
//! `Crawler` is `{seed_url: String, sitemap_url: String, strategy: String,
//! max_depth: i32, max_pages: i32, pages_crawled: i32, rate_limit_ms: i32}`
//! (`stdlib/browser.tl:381`) — three strings and four integers. The integers come
//! back through one **out buffer** in declaration order, the two constant strings
//! through out-params, and the seed (validated, so it is the one field the
//! runtime must produce rather than echo) is the return value. Codegen allocates
//! `%struct.Crawler` itself.
//!
//! Returning a struct pointer from here would couple the LLVM struct layout to a
//! hand-written Rust `#[repr(C)]`, which then breaks *silently* on any field
//! reorder, width change or padding difference. Out-params keep layout owned by
//! codegen, the same trade `tallow_page_cache_create` and
//! `tallow_gzip_decompress(ptr, i64, ptr)` make.
//!
//! # Contract
//!
//! A non-null return means every out-parameter was written; a null return means
//! they must not be read and `tallow_last_error` is set. Nothing is written until
//! every allocation has succeeded, so a partial write cannot be observed.
//!
//! The values come from `stdlib::browser::crawler_from_links_plan`, the same
//! function the interpreter's `Crawler.from_links` arm and the `crawler_from_links`
//! facade call, so native and interpreted results cannot disagree — including the
//! refusals (blank seed, negative depth).

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};
use crate::interp::Value;
use crate::stdlib::browser::crawler_from_links_plan;

/// Integer fields written into the `out_fields` buffer, in declaration order:
/// `max_depth`, `max_pages`, `pages_crawled`, `rate_limit_ms`.
pub const CRAWLER_INT_FIELDS: usize = 4;

/// `Crawler.from_links(url, max_depth?) -> Crawler`.
///
/// `has_max_depth` is 0 when the argument was omitted, and the shared default
/// (3) then applies. Returns the validated `seed_url` string (null on refusal),
/// writing `sitemap_url` and `strategy` through out-params and the four integers
/// into `out_fields`.
///
/// A null out-parameter is a codegen bug and is refused rather than written
/// through.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_crawler_from_links(
    seed_url: *const c_char,
    has_max_depth: i32,
    max_depth: i64,
    out_sitemap_url: *mut *mut c_char,
    out_strategy: *mut *mut c_char,
    out_fields: *mut i64,
) -> *mut c_char {
    if out_sitemap_url.is_null() || out_strategy.is_null() || out_fields.is_null() {
        set_last_error("crawler_from_links: missing out-parameter slot".to_string());
        return std::ptr::null_mut();
    }
    let Some(seed) = (unsafe { cstr_to_str(seed_url) }) else {
        set_last_error("crawler_from_links: expected a seed URL string argument".to_string());
        return std::ptr::null_mut();
    };
    let depth = if has_max_depth != 0 {
        Some(max_depth)
    } else {
        None
    };
    let plan = match crawler_from_links_plan(seed, depth) {
        Ok(plan) => plan,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };

    // Allocate every string first: the contract says a null return means nothing
    // was written, so a late failure must not leave the out-params half-filled.
    let sitemap_url = string_to_cstr(&plan.sitemap_url);
    let strategy = string_to_cstr(&plan.strategy);
    let seed_out = string_to_cstr(&plan.seed_url);
    if sitemap_url.is_null() || strategy.is_null() || seed_out.is_null() {
        set_last_error("crawler_from_links: could not allocate an output string".to_string());
        return std::ptr::null_mut();
    }

    let values = [
        plan.max_depth,
        plan.max_pages,
        plan.pages_crawled,
        plan.rate_limit_ms,
    ];
    // SAFETY: the caller allocated at least CRAWLER_INT_FIELDS slots, and every
    // pointer was checked non-null above. `values.len()` is that constant.
    unsafe {
        for (i, value) in values.iter().enumerate() {
            *out_fields.add(i) = *value;
        }
        *out_sitemap_url = sitemap_url;
        *out_strategy = strategy;
    }
    seed_out
}

/// `Crawler.from_sitemap(url) -> Crawler`.
///
/// **Network discovery.** Delegates to `stdlib::browser::crawler_from_sitemap`, the same
/// function the interpreter's `Crawler.from_sitemap` arm calls — which fetches through
/// `browser::sitemap::SitemapParser` and `runtime::egress_http` (Tor by default, refusing
/// rather than falling back to the box IP). This binding adds no capability the interpreter
/// did not already have; it removes the asymmetry where one engine fetched while the other
/// silently fell back to the interpreter.
///
/// Returns the discovered `seed_url` (the FIRST parsed entry; empty for an empty sitemap,
/// which is a valid "nothing found" rather than an invented URL), writing the echoed
/// `sitemap_url` and the constant `strategy` through out-params and the four integers into
/// `out_fields`. Null on refusal, with `tallow_last_error` set and nothing written.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_crawler_from_sitemap(
    sitemap_url: *const c_char,
    out_sitemap_url: *mut *mut c_char,
    out_strategy: *mut *mut c_char,
    out_fields: *mut i64,
) -> *mut c_char {
    if out_sitemap_url.is_null() || out_strategy.is_null() || out_fields.is_null() {
        set_last_error("crawler_from_sitemap: missing out-parameter slot".to_string());
        return std::ptr::null_mut();
    }
    let Some(url) = (unsafe { cstr_to_str(sitemap_url) }) else {
        set_last_error(
            "Crawler.from_sitemap: expected a sitemap URL string argument".to_string(),
        );
        return std::ptr::null_mut();
    };
    let fields = match crate::stdlib::browser::crawler_from_sitemap(vec![Value::String(
        url.to_string(),
    )]) {
        Ok(Value::Struct { fields, .. }) => fields,
        Ok(other) => {
            set_last_error(format!(
                "crawler_from_sitemap: expected a Struct, got {}",
                crate::interp::type_name(&other)
            ));
            return std::ptr::null_mut();
        }
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };

    // Read by NAME, never by position: a reordered field would otherwise shift silently.
    let seed_url = match string_field(&fields, "seed_url") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    let echoed = match string_field(&fields, "sitemap_url") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    let strategy = match string_field(&fields, "strategy") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    let values = match int_fields(
        &fields,
        &["max_depth", "max_pages", "pages_crawled", "rate_limit_ms"],
    ) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };

    // Allocate every string first: a null return means nothing was written, so a late
    // failure must not leave the out-params half-filled.
    let sitemap_out = string_to_cstr(&echoed);
    let strategy_out = string_to_cstr(&strategy);
    let seed_out = string_to_cstr(&seed_url);
    if sitemap_out.is_null() || strategy_out.is_null() || seed_out.is_null() {
        set_last_error("crawler_from_sitemap: could not allocate an output string".to_string());
        return std::ptr::null_mut();
    }

    unsafe {
        for (i, value) in values.iter().enumerate() {
            *out_fields.add(i) = *value;
        }
        *out_sitemap_url = sitemap_out;
        *out_strategy = strategy_out;
    }
    seed_out
}

/// The named field as a string, or a refusal naming the field that is wrong.
fn string_field(fields: &[(String, Value)], name: &str) -> Result<String, String> {
    match fields.iter().find(|(k, _)| k == name).map(|(_, v)| v) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(format!(
            "crawler_from_sitemap: field {name:?} must be a string, got {}",
            crate::interp::type_name(other)
        )),
        None => Err(format!("crawler_from_sitemap: no field named {name:?}")),
    }
}

/// The named integer fields in the given order. `max_pages` is the number of discovered
/// entries, so it is the one field carrying a discovered value.
fn int_fields(fields: &[(String, Value)], names: &[&str]) -> Result<Vec<i64>, String> {
    names
        .iter()
        .map(|name| match fields.iter().find(|(k, _)| k == name).map(|(_, v)| v) {
            Some(Value::Int(n)) => i64::try_from(*n).map_err(|_| {
                format!("crawler_from_sitemap: field {name:?} does not fit in an i64")
            }),
            Some(other) => Err(format!(
                "crawler_from_sitemap: field {name:?} must be an integer, got {}",
                crate::interp::type_name(other)
            )),
            None => Err(format!("crawler_from_sitemap: no field named {name:?}")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    /// The message the runtime stored for the last refusal, read through the real
    /// C-ABI accessor — there is no Rust-side getter.
    fn last_error() -> String {
        let p = crate::runtime::tallow_last_error();
        if p.is_null() {
            return String::new();
        }
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .unwrap_or("")
            .to_string()
    }

    /// Call the FFI the way codegen does. `Ok` carries `(seed, sitemap, strategy,
    /// int fields)`; `Err` carries the refusal message.
    fn crawler(seed: &str, depth: Option<i64>) -> Result<(String, String, String, Vec<i64>), String> {
        let c = CString::new(seed).unwrap();
        let mut sitemap: *mut c_char = std::ptr::null_mut();
        let mut strategy: *mut c_char = std::ptr::null_mut();
        let mut slots = [0i64; CRAWLER_INT_FIELDS];
        let ptr = tallow_crawler_from_links(
            c.as_ptr(),
            depth.is_some() as i32,
            depth.unwrap_or(0),
            &mut sitemap,
            &mut strategy,
            slots.as_mut_ptr(),
        );
        if ptr.is_null() {
            return Err(last_error());
        }
        let s = |p: *mut c_char| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        Ok((s(ptr), s(sitemap), s(strategy), slots.to_vec()))
    }

    /// The interpreter's contract for a supplied depth (probe + the interpreter's
    /// `test_crawler_from_links`): seed echoed, strategy "link_follow", one page
    /// (the seed itself), nothing crawled, no rate limit.
    #[test]
    fn supplied_depth_matches_the_interpreter_contract() {
        let (seed, sitemap, strategy, ints) = crawler("https://example.com", Some(5)).unwrap();
        assert_eq!(seed, "https://example.com");
        assert_eq!(sitemap, "");
        assert_eq!(strategy, "link_follow");
        // [max_depth, max_pages, pages_crawled, rate_limit_ms]
        assert_eq!(ints, vec![5, 1, 0, 0]);
    }

    /// The optional argument's shared default is 3 — the behavior the
    /// interpreter's struct-static arm has always had.
    #[test]
    fn omitted_depth_takes_the_default_of_three() {
        let (_, _, _, ints) = crawler("https://example.com", None).unwrap();
        assert_eq!(ints[0], 3);
    }

    /// A blank seed is refused, not turned into a crawler that cannot crawl. This
    /// is the validation the canonical facade always had and the interpreter arm
    /// did not; both now share it.
    #[test]
    fn blank_seed_is_refused() {
        let err = crawler("   ", Some(1)).unwrap_err();
        assert!(err.contains("must not be empty"), "{err}");
        assert!(crawler("", Some(1)).is_err());
    }

    /// A negative depth is refused rather than cast to `u32` (which would wrap).
    #[test]
    fn negative_depth_is_refused() {
        let err = crawler("https://example.com", Some(-1)).unwrap_err();
        assert!(err.contains("non-negative"), "{err}");
    }

    /// Null out-parameters are a codegen bug: refuse, never write through them.
    #[test]
    fn null_out_params_fail_closed() {
        let c = CString::new("https://example.com").unwrap();
        let mut strategy: *mut c_char = std::ptr::null_mut();
        let mut slots = [0i64; CRAWLER_INT_FIELDS];
        assert!(
            tallow_crawler_from_links(
                c.as_ptr(),
                0,
                0,
                std::ptr::null_mut(),
                &mut strategy,
                slots.as_mut_ptr(),
            )
            .is_null()
        );
        assert!(
            tallow_crawler_from_links(
                c.as_ptr(),
                0,
                0,
                &mut strategy,
                &mut strategy,
                std::ptr::null_mut(),
            )
            .is_null()
        );
    }
}
