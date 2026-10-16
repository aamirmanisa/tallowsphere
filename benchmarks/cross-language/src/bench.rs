// Tallow benchmark — workload reference implementation (Rust).
// Workloads: mandelbrot | vec_sum | alloc_churn | str_build | startup
// Build variants (see driver): default -C opt-level=3, and the M1 candidate
// -C opt-level=3 -C lto=fat -C codegen-units=1 (the [profile.max] shape).
use std::env;
use std::hint::black_box;
use std::time::Instant;

const W: i64 = 1200;
const H: i64 = 900;
const MAXIT: i32 = 200;

#[inline(never)]
fn mandelbrot(pixels: i64) -> f64 {
    let mut acc: i64 = 0;
    for p in 0..pixels {
        let x = (p % W) as f64;
        let y = ((p / W) % H) as f64;
        let cr = x * 4.0 / W as f64 - 2.0;
        let ci = y * 4.0 / H as f64 - 2.0;
        let (mut zr, mut zi) = (0.0f64, 0.0f64);
        let mut i = 0i32;
        while i < MAXIT {
            let zr2 = zr * zr;
            let zi2 = zi * zi;
            if zr2 + zi2 > 4.0 {
                break;
            }
            zi = 2.0 * zr * zi + ci;
            zr = zr2 - zi2 + cr;
            i += 1;
        }
        acc += i as i64;
    }
    acc as f64
}

#[inline(never)]
fn vec_sum(n: usize) -> f64 {
    let mut a: Vec<f64> = Vec::with_capacity(n);
    for i in 0..n {
        a.push((i % 1000) as f64 * 0.5);
    }
    let mut s = 0.0f64;
    for v in a.iter() {
        s += v * v;
    }
    s
}

struct Obj {
    a: i64,
    b: i64,
    c: i64,
}

#[inline(never)]
fn alloc_churn(n: usize) -> i64 {
    let mut acc: i64 = 0;
    let mut sink: usize = 0;
    for i in 0..n {
        let o = Box::new(Obj {
            a: i as i64,
            b: i as i64 * 2,
            c: i as i64 * 3,
        });
        acc += o.a + o.b + o.c;
        // observable escape: without this, fat-LTO proves the Box never
        // escapes and deletes the whole loop (it did, in the first run —
        // 200M allocations in 2.1 ms).
        sink ^= black_box(o.as_ref() as *const Obj as usize);
        drop(o);
    }
    black_box(sink);
    acc
}

#[inline(never)]
fn str_build(n: usize) -> i64 {
    let mut buf = String::with_capacity(n * 12 + 1);
    for i in 0..n {
        use std::fmt::Write;
        let _ = write!(buf, "{},", i);
    }
    (buf.len() + buf.capacity()) as i64
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let w = args.get(1).map(|s| s.as_str()).unwrap_or("mandelbrot");
    let units: i64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let t0 = Instant::now();
    let cs: f64 = match w {
        "mandelbrot" => mandelbrot(black_box(units)),
        "vec_sum" => vec_sum(black_box(units as usize)),
        "alloc_churn" => alloc_churn(black_box(units as usize)) as f64,
        "str_build" => str_build(black_box(units as usize)) as f64,
        "startup" => 1.0,
        other => {
            eprintln!("unknown workload: {}", other);
            std::process::exit(2);
        }
    };
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!("{}\t{:.3}\t{:.1}", w, ms, cs);
}
