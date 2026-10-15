// Stdlib Codegen Parity Test
// Exercises ALL codegen-supported stdlib functions with deterministic output.
// Used by codegen_interpreter_parity test to verify compiled == interpreted.

fn main() {
    // === Math ===
    print(math.sin(0.0))
    print(math.cos(0.0))
    print(math.tan(0.0))
    print(math.sqrt(4.0))
    print(math.pow(2.0, 10.0))
    print(math.abs(-42.5))
    print(math.floor(3.7))
    print(math.ceil(3.2))
    print(math.round(3.5))
    print(math.log(1.0))
    print(math.pi)
    print(math.e)

    // === Env ===
    // env.get returns a string — just print it to verify it works
    let path = env.get("PATH")
    print("env_path_ok")
    let cwd = env.cwd()
    print("env_cwd_ok")

    // === FS ===
    fs.write_file("__codegen_test_tmp.txt", "hello from tallow codegen")
    let content = fs.read_file("__codegen_test_tmp.txt")
    print(content)
    let exists = fs.exists("__codegen_test_tmp.txt")
    print(exists)
    fs.remove("__codegen_test_tmp.txt")
    let gone = fs.exists("__codegen_test_tmp.txt")
    print(gone)
}
