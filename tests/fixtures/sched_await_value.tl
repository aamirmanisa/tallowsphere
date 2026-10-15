// F1 repro/after fixture: `.await` on a spawned task handle.
//
// Legacy (default) mode: `await` is a synchronous pass-through, so this prints
// the HANDLE (0) and emits the once-per-run "await ... synchronous" note.
// Coop mode (TALLOW_SCHED=coop): `.await` joins the task through the
// interpreter-side scheduler and prints the task's value (50).
fn worker(x: i32) -> i32 {
    x * 10
}

fn main() {
    let h = spawn worker(5)
    let v = h.await
    print(v)
}
