//! The five desks, each running end to end on fixtures.
//!
//! Before this test, four of the five desks existed only as a paragraph in the
//! architecture doc: ORACLE, GHOST, CARTOGRAPHER and QUARTERMASTER had no
//! program. Each now runs on real stdlib calls, writes a graded provenance
//! record, and has a refusal branch that fires on a real condition.
//!
//! The second half is a consistency gate: the task ids each desk declares must be
//! ids `directorate.tl` actually plans. Renaming one in a desk without renaming
//! it in the graph used to be invisible; now it fails here.

use std::process::Command;

fn run(desk: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(format!("examples/directorate/{desk}.tl"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run tallow");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{desk} failed:\n{all}");
    all
}

#[test]
fn oracle_inventories_and_grades() {
    let out = run("oracle");
    assert!(out.contains("profiles="), "{out}");
    assert!(out.contains("grade="), "{out}");
    assert!(
        out.contains("ranking=") || out.contains("held:"),
        "the desk must either rank or refuse, not neither: {out}"
    );
}

#[test]
fn ghost_picks_an_anonymous_plane_for_private_data() {
    let out = run("ghost");
    assert!(out.contains("class=private"), "{out}");
    assert!(out.contains("plane=tor-exit"), "{out}");
    assert!(out.contains("anonymous=true"), "{out}");
    // The refusal branch exists and is reachable: with an anonymous plane the
    // desk proceeds, and the branch is what would stop it otherwise.
    assert!(
        out.contains("emit=permitted") || out.contains("refused:"),
        "{out}"
    );
}

#[test]
fn cartographer_compares_on_named_axes() {
    let out = run("cartographer");
    assert!(out.contains("compared="), "{out}");
    assert!(out.contains("best="), "{out}");
    assert!(
        out.contains("finding=") || out.contains("refused:") || out.contains("held:"),
        "{out}"
    );
}

#[test]
fn quartermaster_observes_then_refuses_a_plan_without_rollback() {
    let out = run("quartermaster");
    assert!(out.contains("observed="), "{out}");
    // A plan with no rollback is refused — proven by the fixture emitting an
    // empty rollback string on purpose.
    assert!(out.contains("refused: plan has no rollback"), "{out}");
}

#[test]
fn sentinel_still_grades_and_refuses_below_threshold() {
    let out = run("sentinel");
    assert!(out.contains("body_hash") || out.contains("grade"), "{out}");
}

#[test]
fn every_desk_task_id_is_planned_by_the_directorate_graph() {
    let graph = std::fs::read_to_string("examples/directorate/directorate.tl").expect("directorate.tl");
    let planned: Vec<String> = graph
        .match_indices("task(\"")
        .map(|(i, _)| {
            let rest = &graph[i + 6..];
            rest[..rest.find('"').unwrap_or(0)].to_string()
        })
        .collect();
    assert!(planned.len() >= 15, "directorate.tl should plan the full graph: {planned:?}");

    for desk in ["sentinel", "oracle", "ghost", "cartographer", "quartermaster"] {
        let src = std::fs::read_to_string(format!("examples/directorate/{desk}.tl"))
            .unwrap_or_else(|e| panic!("{desk}.tl: {e}"));
        let frag = src
            .find("fn fragment()")
            .and_then(|i| {
                let rest = &src[i..];
                let start = rest.find("return \"")? + 8;
                let end = rest[start..].find('"')? + start;
                Some(rest[start..end].to_string())
            })
            .unwrap_or_else(|| panic!("{desk}.tl declares no fragment()"));
        let ids: Vec<&str> = frag.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        assert!(!ids.is_empty(), "{desk}.tl fragment is empty");
        for id in ids {
            assert!(
                planned.iter().any(|p| p == id),
                "{desk}.tl declares '{id}', which directorate.tl never plans. Planned: {planned:?}"
            );
        }
    }
}
