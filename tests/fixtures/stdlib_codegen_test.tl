// Stdlib codegen test: math, env, time

// Math trig/log functions
print(math.sin(0.0))
print(math.cos(0.0))
print(math.tan(0.0))
print(math.sqrt(4.0))
print(math.pow(2.0, 3.0))
print(math.abs(-5.0))
print(math.floor(3.7))
print(math.ceil(3.2))
print(math.round(3.5))
print(math.log2(8.0))
print(math.log10(1000.0))
print(math.min(3.0, 7.0))
print(math.max(3.0, 7.0))
print(math.pi)
print(math.e)

// Env functions
let path = env.get("PATH")
if path != nil {
    print("PATH exists")
}
let cwd = env.cwd()
print("cwd ok")
let home = env.home()
if home != nil {
    print("home ok")
}

// Time
let t = time.now()
if t > 0 {
    print("time ok")
}
