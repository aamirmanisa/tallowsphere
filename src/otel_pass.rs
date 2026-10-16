//! Observability & telemetry compiler pass — @observable annotation validation.
//!
//! Validates `@observable` annotations on functions:
//!
//! - E2400: @observable function missing `metric_name` argument
//! - W2400: Observable function without `slo_target` annotation argument

use crate::ast::*;
use crate::error::Diagnostics;

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct OtelPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
}

impl<'a> OtelPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
        }
    }

    /// Run the observability pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_fn(m);
                    }
                }
                _ => {}
            }
        }
        self.diags
    }

    fn check_fn(&mut self, f: &FnDecl) {
        for ann in &f.annotations {
            if ann.name == "observable" {
                self.validate_observable(ann, f);
            }
        }
    }

    fn validate_observable(&mut self, ann: &Annotation, _f: &FnDecl) {
        // E2400: metric_name is required
        let has_metric_name = ann
            .args
            .iter()
            .any(|a| a.name == "metric_name");
        if !has_metric_name {
            self.diags.error(
                "E2400",
                "@observable annotation missing required `metric_name` argument",
                ann.span,
            );
        }

        // W2400: warn if no slo_target argument
        let has_slo_target = ann
            .args
            .iter()
            .any(|a| a.name == "slo_target");
        if !has_slo_target {
            self.diags.warning(
                "W2400",
                "observable function without `slo_target` annotation — consider adding slo_target for SLO tracking",
                ann.span,
            );
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;

    fn check_src(src: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(src);
        let program = Parser::parse(tokens).unwrap();
        OtelPass::new(&program).check()
    }

    #[test]
    fn test_otel_pass_missing_metric_name() {
        let src = r#"
@observable(purpose: "test")
fn handle_request() {
    print("handling")
}
"#;
        let diags = check_src(src);
        assert!(
            diags.items.iter().any(|d| d.code == "E2400"),
            "should emit E2400 for missing metric_name"
        );
    }

    #[test]
    fn test_otel_pass_valid() {
        let src = r#"
@observable(metric_name: "request_duration", slo_target: 0.999)
fn handle_request() {
    print("handling")
}
"#;
        let diags = check_src(src);
        assert!(
            !diags.has_errors(),
            "should not emit errors for valid @observable"
        );
        assert_eq!(diags.warning_count(), 0, "should not emit warnings");
    }

    #[test]
    fn test_otel_pass_missing_slo_target() {
        let src = r#"
@observable(metric_name: "request_duration")
fn handle_request() {
    print("handling")
}
"#;
        let diags = check_src(src);
        assert!(
            !diags.has_errors(),
            "should not emit errors"
        );
        assert!(
            diags.items.iter().any(|d| d.code == "W2400"),
            "should emit W2400 warning for missing slo_target"
        );
    }

    #[test]
    fn test_otel_pass_no_annotation() {
        let src = r#"
fn normal_function() {
    print("nothing to see")
}
"#;
        let diags = check_src(src);
        assert!(!diags.has_errors());
        assert_eq!(diags.warning_count(), 0);
    }

    #[test]
    fn test_otel_pass_impl_methods() {
        let src = r#"
struct Server {
    name: String
}

impl Server {
    @observable(metric_name: "server_latency", slo_target: 0.99)
    fn handle(self) {
        print("ok")
    }
}
"#;
        let diags = check_src(src);
        assert!(!diags.has_errors());
        assert_eq!(diags.warning_count(), 0);
    }

    #[test]
    fn test_otel_pass_impl_method_missing_metric_name() {
        let src = r#"
struct Server {
    name: String
}

impl Server {
    @observable(purpose: "monitoring")
    fn handle(self) {
        print("ok")
    }
}
"#;
        let diags = check_src(src);
        assert!(
            diags.items.iter().any(|d| d.code == "E2400"),
            "should emit E2400 for impl method missing metric_name"
        );
    }
}
