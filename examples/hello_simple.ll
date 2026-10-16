; ModuleID = 'tallow'
source_filename = "tallow"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

; Built-in types
%struct.TallowResult = type { i64, i64, i64 }

@.str.0 = private unnamed_addr constant [4 x i8] c"big\00"
@.str.1 = private unnamed_addr constant [6 x i8] c"small\00"

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
declare ptr @memmove(ptr, ptr, i64)
declare ptr @memset(ptr, i32, i64)
declare ptr @realloc(ptr, i64)
declare void @exit(i32)
declare i64 @strtol(ptr, ptr, i32)
declare double @strtod(ptr, ptr)
declare ptr @strchr(ptr, i32)
declare double @llvm.fabs.f64(double)
declare double @llvm.floor.f64(double)
declare double @llvm.ceil.f64(double)
declare double @llvm.round.f64(double)
declare double @llvm.sqrt.f64(double)

; POSIX regex
declare i32 @regcomp(ptr, ptr, i32)
declare i32 @regexec(ptr, ptr, i64, ptr, i32)
declare void @regfree(ptr)

; zlib compression
declare i32 @compress2(ptr, ptr, ptr, i64, i32)
declare i32 @uncompress(ptr, ptr, ptr, i64)

; C math library
declare double @sin(double)
declare double @cos(double)
declare double @tan(double)
declare double @pow(double, double)
declare double @log(double)
declare double @log2(double)
declare double @log10(double)

; C stdlib for env/time
declare ptr @getenv(ptr)
declare ptr @_getcwd(ptr, i32)
declare i64 @time(ptr)

; C stdlib for rand/process
declare i32 @rand()
declare void @srand(i32)
declare i32 @system(ptr)
declare i32 @_getpid()

; C stdio for fs module
declare ptr @fopen(ptr, ptr)
declare i64 @fread(ptr, i64, i64, ptr)
declare i64 @fwrite(ptr, i64, i64, ptr)
declare i32 @fclose(ptr)
declare i32 @fseek(ptr, i64, i32)
declare i64 @ftell(ptr)
declare i32 @_access(ptr, i32)
declare i32 @remove(ptr)

; Tallow runtime FFI
declare ptr @tallow_fetch(ptr)
declare i32 @tallow_response_status(ptr)
declare ptr @tallow_response_body(ptr)
declare ptr @tallow_response_url(ptr)
declare void @tallow_response_free(ptr)
declare ptr @tallow_browser_launch(i32)
declare void @tallow_browser_close(ptr)
declare ptr @tallow_browser_new_page(ptr)
declare i32 @tallow_page_goto(ptr, ptr)
declare ptr @tallow_page_title(ptr)
declare ptr @tallow_page_url(ptr)
declare i32 @tallow_page_reload(ptr)
declare ptr @tallow_page_query_selector(ptr, ptr)
declare ptr @tallow_page_query_selector_all(ptr, ptr)
declare ptr @tallow_element_text(ptr)
declare ptr @tallow_element_inner_html(ptr)
declare ptr @tallow_element_attribute(ptr, ptr)
declare i32 @tallow_element_click(ptr)
declare i32 @tallow_element_type_text(ptr, ptr, i32)
declare void @tallow_element_free(ptr)
declare i32 @tallow_array_len(ptr)
declare ptr @tallow_array_get(ptr, i32)
declare void @tallow_array_free(ptr)
declare ptr @tallow_last_error()
declare void @tallow_free_string(ptr)

; Crypto FFI
declare ptr @tallow_blake3_hash(ptr)
declare ptr @tallow_blake3_hash_bytes(ptr, i64)
declare ptr @tallow_aes256_gcm_encrypt(ptr, ptr, ptr, i64, ptr)
declare ptr @tallow_aes256_gcm_decrypt(ptr, ptr, ptr, i64, ptr)
declare i32 @tallow_argon2id_hash(ptr, ptr, i64, ptr)
declare ptr @tallow_sha256(ptr)
declare ptr @tallow_sha384(ptr)
declare ptr @tallow_sha512(ptr)
declare ptr @tallow_sha3_256(ptr)
declare ptr @tallow_hmac_sha256(ptr, ptr)
declare i32 @tallow_hkdf_sha256(ptr, i64, ptr, i64, ptr, i64, ptr, i64)
declare i32 @tallow_ed25519_sign(ptr, ptr, i64, ptr)
declare i32 @tallow_ed25519_verify(ptr, ptr, i64, ptr)
declare i32 @tallow_x25519(ptr, ptr, ptr)
declare void @tallow_random_bytes(ptr, i64)
declare ptr @tallow_zstd_compress(ptr, i64, i32, ptr)
declare ptr @tallow_zstd_decompress(ptr, i64, ptr)
declare ptr @tallow_lz4_compress(ptr, i64, ptr)
declare ptr @tallow_lz4_decompress(ptr, i64, ptr)
declare ptr @tallow_chacha20_poly1305_encrypt(ptr, ptr, ptr, i64, ptr)
declare ptr @tallow_chacha20_poly1305_decrypt(ptr, ptr, ptr, i64, ptr)
declare ptr @tallow_reed_solomon_encode(ptr, i64, i64, i64, ptr)
declare void @tallow_free_bytes(ptr, i64)

; Transfer FFI
declare ptr @tallow_file_hash(ptr)
declare i32 @tallow_encrypt_file(ptr, ptr, ptr)
declare i32 @tallow_decrypt_file(ptr, ptr, ptr)
declare i64 @tallow_copy_file(ptr, ptr)
declare ptr @tallow_delta_scan(ptr)

; Browser extended FFI
declare ptr @tallow_page_content(ptr)
declare i32 @tallow_page_set_content(ptr, ptr)
declare ptr @tallow_page_screenshot(ptr)
declare ptr @tallow_page_pdf(ptr)
declare ptr @tallow_page_get_cookies(ptr)
declare i32 @tallow_page_clear_cookies(ptr)
declare i32 @tallow_page_set_viewport(ptr, i32, i32, double)
declare i32 @tallow_page_set_user_agent(ptr, ptr)
declare i32 @tallow_page_set_geolocation(ptr, double, double, double)
declare ptr @tallow_element_outer_html(ptr)
declare ptr @tallow_element_tag_name(ptr)
declare i32 @tallow_element_bounding_box(ptr, ptr, ptr, ptr, ptr)
declare i32 @tallow_element_focus(ptr)
declare i32 @tallow_element_clear(ptr)
declare i32 @tallow_element_scroll_into_view(ptr)
declare i32 @tallow_element_is_enabled(ptr)
declare ptr @tallow_page_extract_all_text(ptr, ptr)
declare ptr @tallow_page_evaluate(ptr, ptr)
declare ptr @tallow_page_accessibility_tree(ptr)
declare ptr @tallow_page_detect_captcha(ptr)
declare i32 @tallow_page_apply_stealth(ptr)
declare ptr @tallow_page_enter_iframe(ptr, ptr)
declare i32 @tallow_page_block_resources(ptr)
declare i32 @tallow_page_handle_cookie_consent(ptr, i32)
declare i32 @tallow_page_wait_stable(ptr, i64, i64)
declare ptr @tallow_page_detect_pagination(ptr)
declare void @tallow_page_free(ptr)

; Enterprise FFI
declare ptr @tallow_pii_scan(ptr)
declare ptr @tallow_pii_redact(ptr)
declare i64 @tallow_content_fingerprint(ptr)
declare double @tallow_content_similarity(i64, i64)
declare ptr @tallow_html_extract_text(ptr, ptr)
declare ptr @tallow_html_extract_links(ptr)
declare i32 @tallow_audit_log(ptr, ptr)
declare ptr @tallow_audit_export()

; Format strings
@.fmt.int = private unnamed_addr constant [5 x i8] c"%lld\00"
@.fmt.float = private unnamed_addr constant [3 x i8] c"%g\00"
@.fmt.str = private unnamed_addr constant [3 x i8] c"%s\00"
@.fmt.newline = private unnamed_addr constant [2 x i8] c"\0A\00"
@.str.true = private unnamed_addr constant [5 x i8] c"true\00"
@.str.false = private unnamed_addr constant [6 x i8] c"false\00"
@.str.nil = private unnamed_addr constant [4 x i8] c"nil\00"

define i32 @tallow.add(i32 %param.a, i32 %param.b) #0 {
entry:
  %0 = alloca i32
  store i32 %param.a, ptr %0
  %1 = alloca i32
  store i32 %param.b, ptr %1
  %2 = load i32, ptr %0
  %3 = load i32, ptr %1
  %4 = sext i32 %2 to i64
  %5 = sext i32 %3 to i64
  %6 = add i64 %4, %5
  %7 = trunc i64 %6 to i32
  ret i32 %7
}

define void @tallow.main() #0 {
entry:
  %0 = alloca i64
  store i64 10, ptr %0
  %1 = alloca i64
  store i64 20, ptr %1
  %2 = load i64, ptr %0
  %3 = trunc i64 %2 to i32
  %4 = load i64, ptr %1
  %5 = trunc i64 %4 to i32
  %6 = call i32 @tallow.add(i32 %3, i32 %5)
  %7 = alloca i32
  store i32 %6, ptr %7
  %8 = load i32, ptr %7
  %9 = call i32 (ptr, ...) @printf(ptr @.fmt.int, i64 %8)
  %10 = call i32 (ptr, ...) @printf(ptr @.fmt.newline)
  %11 = load i32, ptr %7
  %12 = sext i32 %11 to i64
  %13 = icmp sgt i64 %12, 25
  br i1 %13, label %if.then.0, label %if.else.1
if.then.0:
  %14 = call i32 (ptr, ...) @printf(ptr @.fmt.str, ptr @.str.0)
  %15 = call i32 (ptr, ...) @printf(ptr @.fmt.newline)
  br label %if.merge.2
if.else.1:
  %16 = call i32 (ptr, ...) @printf(ptr @.fmt.str, ptr @.str.1)
  %17 = call i32 (ptr, ...) @printf(ptr @.fmt.newline)
  br label %if.merge.2
if.merge.2:
  %18 = phi i64 [ 0, %if.then.0 ], [ 0, %if.else.1 ]
  ret void
}

; Entry point
define i32 @__tallow_entry() #0 {
entry:
  call void @tallow.main()
  ret i32 0
}

define i32 @main(i32 %argc, ptr %argv) #0 {
entry:
  %ret = call i32 @__tallow_entry()
  ret i32 %ret
}

; Hardening attributes
attributes #0 = { sspstrong uwtable "target-cpu"="x86-64" }

!llvm.module.flags = !{!0, !1, !2}
!0 = !{i32 8, !"cf-protection-return", i32 1}
!1 = !{i32 8, !"cf-protection-branch", i32 1}
!2 = !{i32 7, !"uwtable", i32 2}
