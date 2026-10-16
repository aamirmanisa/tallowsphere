/* Tallow benchmark — workload reference implementation (C baseline).
 * Workloads: mandelbrot | vec_sum | alloc_churn | str_build | startup
 * Usage: ./bench_c <workload> <units>
 * Prints: <workload>\t<elapsed_ms>\t<checksum>
 * Units are identical across every language in this suite; scripting
 * languages are given a smaller unit count and the driver normalises
 * to seconds per million units.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* one unit = one 1200x900x200 px mandelbrot image evicted lazily; here we
 * iterate a flat pixel stream so the unit is exactly one pixel. */
static double mandelbrot(long pixels) {
    const int W = 1200, H = 900, MAXIT = 200;
    long acc = 0;
    for (long p = 0; p < pixels; p++) {
        int x = (int)(p % W), y = (int)((p / W) % H);
        double cr = (x * 4.0 / W - 2.0), ci = (y * 4.0 / H - 2.0);
        double zr = 0.0, zi = 0.0;
        int i = 0;
        for (; i < MAXIT; i++) {
            double zr2 = zr * zr, zi2 = zi * zi;
            if (zr2 + zi2 > 4.0) break;
            zi = 2.0 * zr * zi + ci;
            zr = zr2 - zi2 + cr;
        }
        acc += i;
    }
    return (double)acc;
}

static double vec_sum(long n) {
    double *a = (double *)malloc(sizeof(double) * (size_t)n);
    for (long i = 0; i < n; i++) a[i] = (double)(i % 1000) * 0.5;
    double s = 0.0;
    for (long i = 0; i < n; i++) s += a[i] * a[i];
    free(a);
    return s;
}

typedef struct { long a, b, c; } Obj;

/* A volatile sink defeats allocation elision: without an observable escape,
 * gcc -O3 (and LLVM) prove malloc/free cancel out and delete the loop, which
 * silently invalidated this row in the first run. */
static volatile unsigned long SINK;

static long alloc_churn(long n) {
    long acc = 0;
    for (long i = 0; i < n; i++) {
        Obj *o = (Obj *)malloc(sizeof(Obj));
        o->a = i; o->b = i * 2; o->c = i * 3;
        acc += o->a + o->b + o->c;
        SINK += (unsigned long)o & 0xFF;
        free(o);
    }
    return acc;
}

static long str_build(long n) {
    size_t cap = (size_t)n * 12 + 1;
    char *buf = (char *)malloc(cap);
    size_t len = 0;
    for (long i = 0; i < n; i++) len += (size_t)sprintf(buf + len, "%ld,", i);
    long r = (long)len + (long)strlen(buf);
    free(buf);
    return r;
}

int main(int argc, char **argv) {
    const char *w = argc > 1 ? argv[1] : "mandelbrot";
    long units = argc > 2 ? atol(argv[2]) : 1;
    double t0 = now_ms(), cs = 0.0;
    if (!strcmp(w, "mandelbrot"))      cs = mandelbrot(units);
    else if (!strcmp(w, "vec_sum"))    cs = vec_sum(units);
    else if (!strcmp(w, "alloc_churn")) cs = (double)alloc_churn(units);
    else if (!strcmp(w, "str_build"))  cs = (double)str_build(units);
    else if (!strcmp(w, "startup"))    cs = 1.0;
    else { fprintf(stderr, "unknown workload: %s\n", w); return 2; }
    double t1 = now_ms();
    printf("%s\t%.3f\t%.1f\n", w, t1 - t0, cs);
    return 0;
}
