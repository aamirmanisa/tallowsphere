#!/usr/bin/env python3
"""Tallow benchmark — workload reference implementation (Python 3.14).

Workloads: mandelbrot | vec_sum | alloc_churn | str_build | startup
Usage: python3 bench.py <workload> <units>
Prints: <workload>\t<elapsed_ms>\t<checksum>

Same unit definitions as bench.c / bench.rs / bench.go / bench.rb. The driver
gives this language a smaller unit count and normalises to s per M units.
"""
import sys
import time

W, H, MAXIT = 1200, 900, 200


def mandelbrot(pixels):
    acc = 0
    for p in range(pixels):
        x = p % W
        y = (p // W) % H
        cr = x * 4.0 / W - 2.0
        ci = y * 4.0 / H - 2.0
        zr = zi = 0.0
        i = 0
        while i < MAXIT:
            zr2 = zr * zr
            zi2 = zi * zi
            if zr2 + zi2 > 4.0:
                break
            zi = 2.0 * zr * zi + ci
            zr = zr2 - zi2 + cr
            i += 1
        acc += i
    return float(acc)


def vec_sum(n):
    a = [(i % 1000) * 0.5 for i in range(n)]
    s = 0.0
    for v in a:
        s += v * v
    return s


class Obj:
    __slots__ = ("a", "b", "c")


def alloc_churn(n):
    acc = 0
    for i in range(n):
        o = Obj()
        o.a = i
        o.b = i * 2
        o.c = i * 3
        acc += o.a + o.b + o.c
    return acc


def str_build(n):
    parts = []
    ap = parts.append
    for i in range(n):
        ap(str(i))
    buf = ",".join(parts) + ","
    return len(buf) + len(parts)


def main():
    w = sys.argv[1] if len(sys.argv) > 1 else "mandelbrot"
    units = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    t0 = time.perf_counter()
    if w == "mandelbrot":
        cs = mandelbrot(units)
    elif w == "vec_sum":
        cs = vec_sum(units)
    elif w == "alloc_churn":
        cs = float(alloc_churn(units))
    elif w == "str_build":
        cs = float(str_build(units))
    elif w == "startup":
        cs = 1.0
    else:
        print(f"unknown workload: {w}", file=sys.stderr)
        sys.exit(2)
    ms = (time.perf_counter() - t0) * 1000.0
    print(f"{w}\t{ms:.3f}\t{cs:.1f}")


if __name__ == "__main__":
    main()
