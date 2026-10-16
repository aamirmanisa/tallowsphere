; ModuleID = 'tallow'
source_filename = "tallow"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

; Built-in types
%struct.TallowResult = type { i64, i64 }

%struct.Price = type { i64, ptr }

@.str.0 = private unnamed_addr constant [6 x i8] c"apple\00"
@.str.1 = private unnamed_addr constant [7 x i8] c"banana\00"

; External declarations
declare i32 @printf(ptr, ...)
declare i32 @snprintf(ptr, i64, ptr, ...)
declare ptr @malloc(i64)
declare void @free(ptr)
declare i64 @strlen(ptr)
declare ptr @strcpy(ptr, ptr)
declare ptr @strcat(ptr, ptr)
declare i32 @strcmp(ptr, ptr)
declare i32 @strncmp(ptr, ptr, i64)
declare ptr @strstr(ptr, ptr)
declare ptr @memcpy(ptr, ptr, i64)
declare ptr @memset(ptr, i32, i64)
declare void @exit(i32)
declare i64 @strtol(ptr, ptr, i32)
declare double @strtod(ptr, ptr)
declare ptr @strchr(ptr, i32)
declare double @llvm.fabs.f64(double)
declare double @llvm.floor.f64(double)
declare double @llvm.ceil.f64(double)
declare double @llvm.round.f64(double)
declare double @llvm.sqrt.f64(double)

; Format strings
@.fmt.int = private unnamed_addr constant [5 x i8] c"%lld\00"
@.fmt.float = private unnamed_addr constant [3 x i8] c"%g\00"
@.fmt.str = private unnamed_addr constant [3 x i8] c"%s\00"
@.fmt.newline = private unnamed_addr constant [2 x i8] c"\0A\00"
@.str.true = private unnamed_addr constant [5 x i8] c"true\00"
@.str.false = private unnamed_addr constant [6 x i8] c"false\00"
@.str.nil = private unnamed_addr constant [4 x i8] c"nil\00"

define void @tallow.main() {
entry:
  %0 = getelementptr %struct.Price, ptr null, i32 1
  %1 = ptrtoint ptr %0 to i64
  %2 = call ptr @malloc(i64 %1)
  %3 = getelementptr inbounds %struct.Price, ptr %2, i32 0, i32 0
  store i64 100, ptr %3
  %4 = getelementptr inbounds %struct.Price, ptr %2, i32 0, i32 1
  store ptr @.str.0, ptr %4
  %5 = alloca ptr
  store ptr %2, ptr %5
  %6 = getelementptr %struct.Price, ptr null, i32 1
  %7 = ptrtoint ptr %6 to i64
  %8 = call ptr @malloc(i64 %7)
  %9 = getelementptr inbounds %struct.Price, ptr %8, i32 0, i32 0
  store i64 200, ptr %9
  %10 = getelementptr inbounds %struct.Price, ptr %8, i32 0, i32 1
  store ptr @.str.1, ptr %10
  %11 = alloca ptr
  store ptr %8, ptr %11
  %12 = load ptr, ptr %5
  %13 = getelementptr inbounds %struct.Price, ptr %12, i32 0, i32 0
  %14 = load i64, ptr %13
  %15 = call i32 (ptr, ...) @printf(ptr @.fmt.int, i64 %14)
  %16 = call i32 (ptr, ...) @printf(ptr @.fmt.newline)
  %17 = load ptr, ptr %5
  %18 = getelementptr inbounds %struct.Price, ptr %17, i32 0, i32 1
  %19 = load ptr, ptr %18
  %20 = call i32 (ptr, ...) @printf(ptr @.fmt.str, ptr %19)
  %21 = call i32 (ptr, ...) @printf(ptr @.fmt.newline)
  %22 = call ptr @malloc(i64 24)
  %23 = getelementptr i64, ptr %22, i32 0
  store i64 2, ptr %23
  %24 = load ptr, ptr %5
  %25 = ptrtoint ptr %24 to i64
  %26 = getelementptr i64, ptr %22, i32 1
  store i64 %25, ptr %26
  %27 = load ptr, ptr %11
  %28 = ptrtoint ptr %27 to i64
  %29 = getelementptr i64, ptr %22, i32 2
  store i64 %28, ptr %29
  %30 = alloca ptr
  store ptr %22, ptr %30
  %31 = load ptr, ptr %30
  %32 = load i64, ptr %31
  %33 = call i32 (ptr, ...) @printf(ptr @.fmt.int, i64 %32)
  %34 = call i32 (ptr, ...) @printf(ptr @.fmt.newline)
  %35 = load ptr, ptr %30
  %36 = getelementptr i64, ptr %35, i64 0
  %37 = load i64, ptr %36
  %38 = alloca i64
  store i64 0, ptr %38
  br label %forarr.cond.0
forarr.cond.0:
  %39 = load i64, ptr %38
  %40 = icmp slt i64 %39, %37
  br i1 %40, label %forarr.body.1, label %forarr.end.3
forarr.body.1:
  %41 = load i64, ptr %38
  %42 = add i64 %41, 1
  %43 = getelementptr i64, ptr %35, i64 %42
  %44 = load i64, ptr %43
  %45 = inttoptr i64 %44 to ptr
  %46 = alloca ptr
  store ptr %45, ptr %46
  %47 = load ptr, ptr %46
  %48 = getelementptr inbounds %struct.Price, ptr %47, i32 0, i32 0
  %49 = load i64, ptr %48
  %50 = call i32 (ptr, ...) @printf(ptr @.fmt.int, i64 %49)
  %51 = call i32 (ptr, ...) @printf(ptr @.fmt.newline)
  br label %forarr.inc.2
forarr.inc.2:
  %52 = load i64, ptr %38
  %53 = add i64 %52, 1
  store i64 %53, ptr %38
  br label %forarr.cond.0
forarr.end.3:
  ret void
}

; Entry point
define i32 @__tallow_entry() {
entry:
  call void @tallow.main()
  ret i32 0
}

define i32 @main(i32 %argc, ptr %argv) {
entry:
  %ret = call i32 @__tallow_entry()
  ret i32 %ret
}
