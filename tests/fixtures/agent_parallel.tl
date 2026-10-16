@agent_task(id: "t1", timeout: 60.seconds, max_requests: 100, can_write: false, can_store: false, can_spawn: false)
fn task_a(x: i32) -> i32 { x * 10 }

@agent_task(id: "t2", timeout: 60.seconds, max_requests: 100, can_write: false, can_store: false, can_spawn: false)
fn task_b(x: i32) -> i32 { x + 100 }

fn main() {
    print("pstart")
    let h1 = spawn_agent_async("task_a", 5)
    let h2 = spawn_agent_async("task_b", 7)
    print("spawned")
    let r1 = spawn_await(h1)
    let r2 = spawn_await(h2)
    print("a:")
    print(r1)
    print("b:")
    print(r2)
    print("pend")
}
