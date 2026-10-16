use std::process::Command;

use serde_json::Value;

const REQUIRED_SURFACES: &[&str] = &[
    // SCRAPER_CRITICAL_STDLIB_SURFACE: http.get
    "http.get",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: http.post
    "http.post",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: http.batch
    "http.batch",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: Response.text
    "Response.text",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: Response.json
    "Response.json",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: json.parse
    "json.parse",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: html.parse
    "html.parse",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: HtmlDocument.select
    "HtmlDocument.select",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: HtmlDocument.text
    "HtmlDocument.text",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: HtmlElement.text
    "HtmlElement.text",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: HtmlElement.attr
    "HtmlElement.attr",
    // SCRAPER_CRITICAL_STDLIB_SURFACE: time.now
    "time.now",
];

#[test]
fn doctor_stdlib_scraper_reports_required_surface_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["doctor", "--stdlib-scraper"])
        .output()
        .expect("run tallow doctor --stdlib-scraper");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "doctor should emit machine report on stdout without stderr noise: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["schema_version"], "tallow.doctor.stdlib_scraper.v1");
    assert_eq!(report["passed"], true);
    assert_eq!(
        report["summary"]["total"].as_u64(),
        Some(REQUIRED_SURFACES.len() as u64)
    );
    assert_eq!(report["summary"]["fail"], 0);

    let surfaces = report["surfaces"]
        .as_array()
        .expect("surfaces array in report");

    for name in REQUIRED_SURFACES {
        let surface = surfaces
            .iter()
            .find(|entry| entry["name"] == *name)
            .unwrap_or_else(|| panic!("missing scraper-critical surface {name}"));
        assert_eq!(surface["status"], "pass", "surface {name} should pass");
        assert_eq!(
            surface["checks"]["runtime_dispatch"]["passed"], true,
            "surface {name} should have runtime dispatch"
        );
        assert_eq!(
            surface["checks"]["declaration"]["passed"], true,
            "surface {name} should have stdlib declaration"
        );
        assert_eq!(
            surface["checks"]["tests"]["passed"], true,
            "surface {name} should have tests"
        );
    }
}
