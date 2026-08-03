#include <sys/types.h>
#include <sys/stat.h>
#include "zygisk.hpp"

#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <signal.h>
#include <setjmp.h>

#define LOG_TAG "MyZygiskModule"
using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ===== 설정 =====
static const char* kTargetPkg = "com.gear2.growslayer";   // 실제 패키지명
static const uintptr_t kOffsetLoadMetadata = 0x4463454;  // 네 오프셋
static const uint32_t kMetadataMagic = 0xAF1BB1FA;

static const char* kTracePath = "/data/local/tmp/myzygisk_trace.log";
static const char* kDumpPath  = "/data/local/tmp/global-metadata.dump";
static const char* kSeenPath  = "/data/local/tmp/myzygisk_target_seen.flag";
static const char* kOkPath    = "/data/local/tmp/myzygisk_dump_ok.flag";
static const char* kFailPath  = "/data/local/tmp/myzygisk_dump_fail.flag";

// ===== 전역 =====
static JNIEnv* g_env = nullptr;
static volatile bool g_worker_started = false;

// ===== 로거 =====
static void tlog(const char* lv, const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    __android_log_print(!strcmp(lv, "E") ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG, "%s", buf);

    FILE* fp = fopen(kTracePath, "a");
    if (fp) {
        fprintf(fp, "[%s][pid:%d] %s\n", lv, getpid(), buf);
        fclose(fp);
    }
}
#define I(...) tlog("I", __VA_ARGS__)
#define E(...) tlog("E", __VA_ARGS__)

// ===== maps =====
static uintptr_t get_module_base_rx(const char* module_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    uintptr_t s = 0, e = 0;
    char perm[8] = {0};
    char path[512] = {0};

    while (fgets(line, sizeof(line), fp)) {
        int n = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %*s %*s %*s %511s",
                       &s, &e, perm, path);
        if (n >= 4 && strstr(path, module_name) && strstr(perm, "r-x")) {
            fclose(fp);
            return s;
        }
    }
    fclose(fp);
    return 0;
}

static bool addr_in_maps(uintptr_t addr) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;

    char line[1024];
    uintptr_t s = 0, e = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &s, &e) == 2) {
            if (addr >= s && addr < e) {
                I("addr 0x%" PRIxPTR " in map: %s", addr, line);
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

// ===== safe call =====
static sigjmp_buf g_jmpbuf;
static struct sigaction g_old_segv;
static volatile sig_atomic_t g_guard = 0;

static void segv_handler(int) {
    if (g_guard) siglongjmp(g_jmpbuf, 1);
}

template <typename Fn>
static void* safe_call(Fn fn, const char* arg, bool* crashed) {
    if (crashed) *crashed = false;

    struct sigaction sa{};
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &g_old_segv);

    g_guard = 1;
    void* ret = nullptr;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        ret = fn(arg);
    } else {
        if (crashed) *crashed = true;
    }
    g_guard = 0;

    sigaction(SIGSEGV, &g_old_segv, nullptr);
    return ret;
}

typedef void* (*LoadMetaDataLike_t)(const char*);

// ===== worker =====
static void* worker_thread(void*) {
    I("worker started");

    // libil2cpp 로드 대기 (최대 30초)
    uintptr_t base = 0;
    for (int i = 0; i < 300; ++i) {
        base = get_module_base_rx("libil2cpp.so");
        if (base) break;
        usleep(100000);
    }

    if (!base) {
        E("timeout: libil2cpp.so not found");
        FILE* f = fopen(kFailPath, "w");
        if (f) { fprintf(f, "FAIL no libil2cpp\n"); fclose(f); }
        return nullptr;
    }

    uintptr_t fn_addr = base + kOffsetLoadMetadata;
    I("libil2cpp base=0x%" PRIxPTR, base);
    I("target fn=0x%" PRIxPTR, fn_addr);

    if (!addr_in_maps(fn_addr)) {
        E("target fn not in maps");
        FILE* f = fopen(kFailPath, "w");
        if (f) { fprintf(f, "FAIL fn not in maps\n"); fclose(f); }
        return nullptr;
    }

    auto fn = reinterpret_cast<LoadMetaDataLike_t>(fn_addr);

    bool crashed = false;
    I("calling fn(\"global-metadata.dat\")");
    void* meta = safe_call(fn, "global-metadata.dat", &crashed);

    if (crashed) {
        E("fn call crashed (offset/prototype mismatch)");
        FILE* f = fopen(kFailPath, "w");
        if (f) { fprintf(f, "FAIL call crashed\n"); fclose(f); }
        return nullptr;
    }

    I("fn returned meta=%p", meta);
    if (!meta) {
        E("meta is null");
        FILE* f = fopen(kFailPath, "w");
        if (f) { fprintf(f, "FAIL meta null\n"); fclose(f); }
        return nullptr;
    }

    uint32_t magic = *(uint32_t*)meta;
    I("meta magic=0x%08x", magic);

    if (magic != kMetadataMagic) {
        E("magic mismatch (encrypted/transformed 가능)");
        FILE* f = fopen(kFailPath, "w");
        if (f) { fprintf(f, "FAIL magic mismatch: 0x%08x\n", magic); fclose(f); }
        return nullptr;
    }

    // 우선 4MB 덤프
    size_t dumpSize = 0x400000;
    FILE* out = fopen(kDumpPath, "wb");
    if (!out) {
        E("open dump failed");
        FILE* f = fopen(kFailPath, "w");
        if (f) { fprintf(f, "FAIL open dump\n"); fclose(f); }
        return nullptr;
    }
    size_t wr = fwrite(meta, 1, dumpSize, out);
    fclose(out);

    if (wr != dumpSize) {
        E("dump write failed %zu/%zu", wr, dumpSize);
        FILE* f = fopen(kFailPath, "w");
        if (f) { fprintf(f, "FAIL dump write %zu/%zu\n", wr, dumpSize); fclose(f); }
        return nullptr;
    }

    FILE* ok = fopen(kOkPath, "w");
    if (ok) {
        fprintf(ok, "OK pid=%d base=0x%" PRIxPTR " fn=0x%" PRIxPTR " meta=%p size=%zu\n",
                getpid(), base, fn_addr, meta, dumpSize);
        fclose(ok);
    }

    I("dump success: %s (%zu bytes)", kDumpPath, dumpSize);
    return nullptr;
}

static void maybe_start_for_proc(const char* proc) {
    if (!proc || g_worker_started) return;

    I("proc=%s", proc);

    size_t n = strlen(kTargetPkg);
    bool match = (strcmp(proc, kTargetPkg) == 0) ||
                 (strncmp(proc, kTargetPkg, n) == 0 && proc[n] == ':');

    if (!match) return;

    g_worker_started = true;
    I("target matched in pid=%d proc=%s", getpid(), proc);

    FILE* seen = fopen(kSeenPath, "w");
    if (seen) {
        fprintf(seen, "seen pid=%d proc=%s\n", getpid(), proc);
        fclose(seen);
    }

    pthread_t th;
    if (pthread_create(&th, nullptr, worker_thread, nullptr) == 0) {
        pthread_detach(th);
        I("worker spawned");
    } else {
        E("pthread_create failed");
    }
}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        (void)api;
        g_env = env;
        I("onLoad");
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        I("preAppSpecialize entered");
        if (!args || !args->nice_name || !g_env) {
            E("pre invalid args/env");
            return;
        }
        const char* proc = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!proc) {
            E("pre GetStringUTFChars failed");
            return;
        }
        maybe_start_for_proc(proc);
        g_env->ReleaseStringUTFChars(args->nice_name, proc);
    }

    void postAppSpecialize(const AppSpecializeArgs* args) override {
        I("postAppSpecialize entered");
        if (!args || !args->nice_name || !g_env) {
            E("post invalid args/env");
            return;
        }
        const char* proc = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!proc) {
            E("post GetStringUTFChars failed");
            return;
        }
        maybe_start_for_proc(proc);
        g_env->ReleaseStringUTFChars(args->nice_name, proc);
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
