// Tallow benchmark — workload reference implementation (Go).
// Workloads: mandelbrot | vec_sum | alloc_churn | str_build | startup
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const (
	W     = 1200
	H     = 900
	MAXIT = 200
)

func mandelbrot(pixels int64) float64 {
	var acc int64
	for p := int64(0); p < pixels; p++ {
		x := float64(p % W)
		y := float64((p / W) % H)
		cr := x*4.0/float64(W) - 2.0
		ci := y*4.0/float64(H) - 2.0
		zr, zi := 0.0, 0.0
		i := 0
		for ; i < MAXIT; i++ {
			zr2 := zr * zr
			zi2 := zi * zi
			if zr2+zi2 > 4.0 {
				break
			}
			zi = 2.0*zr*zi + ci
			zr = zr2 - zi2 + cr
		}
		acc += int64(i)
	}
	return float64(acc)
}

func vecSum(n int) float64 {
	a := make([]float64, n)
	for i := 0; i < n; i++ {
		a[i] = float64(i%1000) * 0.5
	}
	s := 0.0
	for _, v := range a {
		s += v * v
	}
	return s
}

type Obj struct{ a, b, c int64 }

var sink uintptr
var sinkSlice [1]*Obj

//go:noinline
func escape(p *Obj) { sinkSlice[0] = p }

// allocChurn forces a real heap escape. Without the noinline store, Go's
// escape analysis keeps Obj on the stack and the row measures stack bumping
// (it returned 2.9 ns/unit in the first corrected run — impossible for a real
// allocator). With it, the row measures Go's actual cost for N small objects:
// heap allocation *plus* the garbage collection that follows.
func allocChurn(n int) int64 {
	var acc int64
	for i := 0; i < n; i++ {
		o := &Obj{a: int64(i), b: int64(i) * 2, c: int64(i) * 3}
		acc += o.a + o.b + o.c
		escape(o)
		sink ^= uintptr(unsafe.Pointer(o)) & 0xFF
	}
	runtime.KeepAlive(sink)
	return acc
}

func strBuild(n int) int64 {
	var sb strings.Builder
	sb.Grow(n*12 + 1)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "%d,", i)
	}
	return int64(sb.Len())
}

func main() {
	w := "mandelbrot"
	if len(os.Args) > 1 {
		w = os.Args[1]
	}
	units := int64(1)
	if len(os.Args) > 2 {
		units, _ = strconv.ParseInt(os.Args[2], 10, 64)
	}
	t0 := time.Now()
	var cs float64
	switch w {
	case "mandelbrot":
		cs = mandelbrot(units)
	case "vec_sum":
		cs = vecSum(int(units))
	case "alloc_churn":
		cs = float64(allocChurn(int(units)))
	case "str_build":
		cs = float64(strBuild(int(units)))
	case "startup":
		cs = 1.0
	default:
		fmt.Fprintf(os.Stderr, "unknown workload: %s\n", w)
		os.Exit(2)
	}
	ms := float64(time.Since(t0).Nanoseconds()) / 1e6
	fmt.Printf("%s\t%.3f\t%.1f\n", w, ms, cs)
}
