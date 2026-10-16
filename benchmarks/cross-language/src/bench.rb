#!/usr/bin/env ruby
# Tallow benchmark — workload reference implementation (Ruby).
# Workloads: mandelbrot | vec_sum | alloc_churn | str_build | startup
# Usage: ruby bench.rb <workload> <units>
W = 1200
H = 900
MAXIT = 200

def mandelbrot(pixels)
  acc = 0
  p = 0
  while p < pixels
    x = (p % W).to_f
    y = ((p / W) % H).to_f
    cr = x * 4.0 / W - 2.0
    ci = y * 4.0 / H - 2.0
    zr = 0.0
    zi = 0.0
    i = 0
    while i < MAXIT
      zr2 = zr * zr
      zi2 = zi * zi
      break if zr2 + zi2 > 4.0
      zi = 2.0 * zr * zi + ci
      zr = zr2 - zi2 + cr
      i += 1
    end
    acc += i
    p += 1
  end
  acc.to_f
end

def vec_sum(n)
  a = Array.new(n) { |i| (i % 1000) * 0.5 }
  s = 0.0
  a.each { |v| s += v * v }
  s
end

Obj = Struct.new(:a, :b, :c)

def alloc_churn(n)
  acc = 0
  i = 0
  while i < n
    o = Obj.new(i, i * 2, i * 3)
    acc += o.a + o.b + o.c
    i += 1
  end
  acc
end

def str_build(n)
  buf = +""
  i = 0
  while i < n
    buf << i.to_s << ","
    i += 1
  end
  buf.length
end

w = ARGV[0] || "mandelbrot"
units = (ARGV[1] || "1").to_i
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
cs = case w
     when "mandelbrot"  then mandelbrot(units)
     when "vec_sum"     then vec_sum(units)
     when "alloc_churn" then alloc_churn(units).to_f
     when "str_build"   then str_build(units).to_f
     when "startup"     then 1.0
     else
       warn "unknown workload: #{w}"
       exit 2
     end
ms = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000.0
printf("%s\t%.3f\t%.1f\n", w, ms, cs)
