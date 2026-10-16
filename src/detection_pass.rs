//! Detection engineering compiler pass — @detection annotation validation.
//!
//! Validates `@detection` annotations on threat hunting / detection functions:
//!
//! - E2300: @detection function missing `detection_id` argument
//! - W2300: Detection function without `test_coverage` annotation argument

use crate::ast::*;
use crate::error::Diagnostics;

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct DetectionPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
}

impl<'a> DetectionPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
        }
    }

    /// Run the detection pass. Returns diagnostics.
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
            if ann.name == "detection" {
                self.validate_detection(ann, f);
            }
        }
    }

    fn validate_detection(&mut self, ann: &Annotation, _f: &FnDecl) {
        // E2300: detection_id is required
        let has_detection_id = ann
            .args
            .iter()
            .any(|a| a.name == "detection_id");
        if !has_detection_id {
            self.diags.error(
                "E2300",
                "@detection annotation missing required `detection_id` argument",
                ann.span,
            );
        }

        // W2300: warn if no test_coverage argument
        let has_test_coverage = ann
            .args
            .iter()
            .any(|a| a.name == "test_coverage");
        if !has_test_coverage {
            self.diags.warning(
                "W2300",
                "detection function without `test_coverage` annotation — consider adding test_coverage: true",
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
        DetectionPass::new(&program).check()
    }

    #[test]
    fn test_detection_pass_missing_detection_id() {
        let src = r#"
@detection(purpose: "test")
fn detect_malware() {
    print("scanning")
}
"#;
        let diags = check_src(src);
        assert!(
            diags.items.iter().any(|d| d.code == "E2300"),
            "should emit E2300 for missing detection_id"
        );
    }

    #[test]
    fn test_detection_pass_valid() {
        let src = r#"
@detection(detection_id: "DET-001", test_coverage: true)
fn detect_malware() {
    print("scanning")
}
"#;
        let diags = check_src(src);
        assert!(
            !diags.has_errors(),
            "should not emit errors for valid @detection"
        );
        assert_eq!(diags.warning_count(), 0, "should not emit warnings");
    }

    #[test]
    fn test_detection_pass_missing_test_coverage() {
        let src = r#"
@detection(detection_id: "DET-001")
fn detect_malware() {
    print("scanning")
}
"#;
        let diags = check_src(src);
        assert!(
            !diags.has_errors(),
            "should not emit errors"
        );
        assert!(
            diags.items.iter().any(|d| d.code == "W2300"),
            "should emit W2300 warning for missing test_coverage"
        );
    }

    #[test]
    fn test_detection_pass_no_annotation() {
        let src = r#"
fn normal_function() {
    print("nothing to see")
}
"#;
        let diags = check_src(src);
        assert!(!diags.has_errors());
        assert_eq!(diags.warning_count(), 0);
    }
}
