// QUARTERMASTER — observation, diagnosis, and a plan with a rollback.
//
// The desk runs a real command, records what actually happened, and refuses to
// enact a plan that has no rollback: an action nobody can undo is not a plan.
//
// Run: tallow run examples/directorate/quartermaster.tl

@cra_class(.default)
@legal(
    basis:         .public_data,
    purpose:       "observe the host, diagnose one condition, and emit a plan with a rollback",
    personal_data: false
)
fn main() {
    // A real observation: the exit status and the stdout are the evidence, not
    // the desk's description of them.
    let uname = process.exec("uname", ["-s"])
    let observed = uname.stdout.trim() + ":exit=" + uname.exit_code.to_string()
    let digest = provenance.hash_body(observed)

    let rec = provenance.record(
        "local://quartermaster/observe",
        "local",
        "local",
        if uname.success { 200 } else { 500 },
        digest
    )
    let ran = provenance.add_validator(rec, "ran", uname.success, 0.30, "command completed")
    let graded = provenance.grade(ran)

    print("observed=" + observed)
    print("grade=" + graded.grade)

    // Refusal branch 1: a failed observation is not a diagnosis. Say so.
    if !uname.success {
        print("refused: observation failed; nothing to diagnose")
        return
    }

    // Refusal branch 2: an action without a rollback is not a plan.
    let rollback = ""
    if rollback == "" {
        print("refused: plan has no rollback; not enacting")
        return
    }

    print("plan=" + "no-op (observation only)")
}

fn fragment() -> String {
    return "quartermaster.observe,quartermaster.diagnose,quartermaster.plan,quartermaster.execute"
}
