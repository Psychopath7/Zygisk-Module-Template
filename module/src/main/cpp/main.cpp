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
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ===== 사용자 설정 =====
static const char* kTargetPkg = "com.gear2.growslayer";   // 실제 패키지명으로 변경
static const uintptr_t kOffsetLoadMetadata = 0x4463454;  // 네가 가진 오프셋
static const uint32_t kMetadataMagic = 0xAF1BB1FA;
static const char* kTracePath = "/data/local/tmp/myzygisk_trace.log";
static const char* kDumpPath  = "/data/local/tmp/global-metadata.dump";
static const char* kOkPath    = "/data/local/tmp/myzygisk_dump_ok.flag";

// ===== 전역 상태 =====
static volatile bool g_worker_started = false;
static JNIEnv* g_env = nullptr;

// ===== 로깅 =====
static void tracef(const char* lv, const char* fmt, ...) {
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    int prio = (!strcmp(lv, "E")) ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO;
    __android_log_print(prio, LOG_TAG, "%s", msg);

    FILE* fp = fopen(kTracePath, "a");
    if (fp) {
        fprintf(fp, "[%s][pid:%d] %s\n", lv, getpid(), msg);
        fclose(fp);
    }
}
#define TLOGI(...) tracef("I", __VA_ARGS__)
#define TLOGE(...) tracef("E", __VA_ARGS__)

// ===== maps 유틸 =====
static uintptr_t get_module_base_rx(const char* module_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    uintptr_t start = 0, end = 0;
    char perm[8] = {0};
    char path[512] = {0};

    while (fgets(line, sizeof(line), fp)) {
        int n = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %*s %*s %*s %511s",
                       &start, &end, perm, path);
        if (n >= 4 && strstr(path, module_name) && strstr(perm, "r-x")) {
            fclose(fp);
            return start;
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
                TLOGI("addr 0x%" PRIxPTR " in map: %s", addr, line);
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

// ===== SIGSEGV 가드 (직접 호출 보호용) =====
static sigjmp_buf g_jmpbuf;
static struct sigaction g_old_segv;
static volatile sig_atomic_t g_segv_guard = 0;

static void segv_handler(int sig) {
    (void)sig;
    if (g_segv_guard) {
        siglongjmp(g_jmpbuf, 1);
    }
}

template <typename Fn>
static void* safe_call_metadata(Fn fn, const char* arg, bool* crashed) {
    if (crashed) *crashed = false;

    struct sigaction sa {};
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGSEGV, &sa, &g_old_segv);
    g_segv_guard = 1;

    void* ret = nullptr;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        ret = fn(arg);
    } else {
        if (crashed) *crashed = true;
    }

    g_segv_guard = 0;
    sigaction(SIGSEGV, &g_old_segv, nullptr);
    return ret;
}

// ===== 덤프 =====
static bool dump_fixed_size(const void* p, size_t size) {
    if (!p || size == 0) return false;
    FILE* out = fopen(kDumpPath, "wb");
    if (!out) {
        TLOGE("open dump failed: %s", kDumpPath);
        return false;
    }
    size_t wr = fwrite(p, 1, size, out);
    fclose(out);
    if (wr != size) {
        TLOGE("write dump failed: %zu/%zu", wr, size);
        return false;
    }
    return true;
}

// 네가 가정한 시그니처
typedef void* (*LoadMetaDataLike_t)(const char*);

static void* worker_thread(void*) {
    TLOGI("worker started");

    // 1) libil2cpp 로드 대기
    uintptr_t base = 0;
    for (int i = 0; i < 300; ++i) { // 최대 30초
        base = get_module_base_rx("libil2cpp.so");
        if (base) break;
        usleep(100000);
    }

    if (!base) {
        TLOGE("timeout: libil2cpp.so not found");
        return nullptr;
    }

    uintptr_t fn_addr = base + kOffsetLoadMetadata;
    TLOGI("libil2cpp base=0x%" PRIxPTR, base);
    TLOGI("target fn=0x%" PRIxPTR " (base+0x%" PRIxPTR ")", fn_addr, kOffsetLoadMetadata);

    if (!addr_in_maps(fn_addr)) {
        TLOGE("target fn not in maps");
        return nullptr;
    }

    // 2) 함수 직접 호출 (보호 가드 적용)
    auto fn = reinterpret_cast<LoadMetaDataLike_t>(fn_addr);
    bool crashed = false;
    TLOGI("calling fn(\"global-metadata.dat\")");
    void* meta = safe_call_metadata(fn, "global-metadata.dat", &crashed);

    if (crashed) {
        TLOGE("fn call crashed (likely wrong prototype/offset)");
        return nullptr;
    }

    TLOGI("fn returned meta=%p", meta);
    if (!meta) {
        TLOGE("meta ptr is null");
        return nullptr;
    }

    // 3) magic 확인
    uint32_t magic = *(uint32_t*)meta;
    TLOGI("meta magic=0x%08x", magic);

    if (magic != kMetadataMagic) {
        TLOGE("magic mismatch (maybe encrypted/transformed)");
        return nullptr;
    }

    // 4) 4MB 우선 덤프
    size_t dump_sz = 0x400000;
    if (!dump_fixed_size(meta, dump_sz)) {
        TLOGE("dump failed");
        return nullptr;
    }

    FILE* ok = fopen(kOkPath, "w");
    if (ok) {
        fprintf(ok, "OK pid=%d base=0x%" PRIxPTR " fn=0x%" PRIxPTR " meta=%p dump=%s size=%zu\n",
                getpid(), base, fn_addr, meta, kDumpPath, dump_sz);
        fclose(ok);
    }

    TLOGI("dump success: %s (%zu bytes)", kDumpPath, dump_sz);
    return nullptr;
}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        (void)api;
        g_env = env;
        TLOGI("onLoad");
    }

    void postAppSpecialize(const AppSpecializeArgs* args) override {
        if (!args || !args->nice_name || !g_env) return;

        const char* proc = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!proc) return;

        // exact + sub-process 모두 대응 (com.pkg / com.pkg:xxx)
        bool match = (strncmp(proc, kTargetPkg, strlen(kTargetPkg)) == 0);

        if (match && !g_worker_started) {
            g_worker_started = true;
            TLOGI("target matched: %s", proc);
            TLOGI("spawning worker");

            pthread_t th;
            if (pthread_create(&th, nullptr, worker_thread, nullptr) == 0) {
                pthread_detach(th);
            } else {
                TLOGE("pthread_create failed");
            }
        }

        g_env->ReleaseStringUTFChars(args->nice_name, proc);
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
