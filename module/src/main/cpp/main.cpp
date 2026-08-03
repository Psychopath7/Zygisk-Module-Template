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

#define LOG_TAG "MyZygiskModule"
using zygisk::Api;
using zygisk::AppSpecializeArgs;

static const char* kTargetPkg = "com.gear2.growslayer";   // 실제 패키지명 정확히
static const uintptr_t kOffset = 0x4463454;

static const char* kTrace = "/data/local/tmp/myzygisk_trace.log";
static const char* kSeen  = "/data/local/tmp/myzygisk_target_seen.flag";
static const char* kAddr  = "/data/local/tmp/myzygisk_addr_ok.flag";

static JNIEnv* g_env = nullptr;
static volatile bool g_started = false;
static pid_t g_target_pid = -1;

static void logf2(const char* lv, const char* fmt, ...) {
    char b[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);

    __android_log_print(!strcmp(lv, "E") ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG, "%s", b);
    FILE* f = fopen(kTrace, "a");
    if (f) { fprintf(f, "[%s][pid:%d] %s\n", lv, getpid(), b); fclose(f); }
}
#define I(...) logf2("I", __VA_ARGS__)
#define E(...) logf2("E", __VA_ARGS__)

static uintptr_t get_base(const char* so) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024], perm[8], path[512];
    uintptr_t s=0,e=0;
    while (fgets(line, sizeof(line), fp)) {
        perm[0]=0; path[0]=0;
        int n = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %*s %*s %*s %511s", &s, &e, perm, path);
        if (n >= 4 && strstr(path, so) && strstr(perm, "r-x")) {
            fclose(fp);
            return s;
        }
    }
    fclose(fp);
    return 0;
}

static void* worker(void*) {
    I("worker start pid=%d", getpid());

    for (int i=0; i<300; i++) {
        if (getpid() != g_target_pid) {
            E("pid changed, stop worker");
            return nullptr;
        }

        uintptr_t base = get_base("libil2cpp.so");
        if (base) {
            uintptr_t target = base + kOffset;
            I("libil2cpp base=0x%" PRIxPTR, base);
            I("target addr=0x%" PRIxPTR, target);

            FILE* f = fopen(kAddr, "w");
            if (f) {
                fprintf(f, "pid=%d base=0x%" PRIxPTR " target=0x%" PRIxPTR "\n", getpid(), base, target);
                fclose(f);
            }
            return nullptr;
        }
        usleep(100000);
    }

    E("timeout waiting libil2cpp");
    return nullptr;
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
        if (!args || !args->nice_name || !g_env) return;

        const char* proc = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!proc) return;

        I("proc=%s", proc);

        // 정확 일치만 허용 (디버그 단계)
        if (!g_started && strcmp(proc, kTargetPkg) == 0) {
            g_started = true;
            g_target_pid = getpid();

            I("target matched pid=%d proc=%s", g_target_pid, proc);

            FILE* f = fopen(kSeen, "w");
            if (f) { fprintf(f, "seen pid=%d proc=%s\n", g_target_pid, proc); fclose(f); }

            pthread_t th;
            if (pthread_create(&th, nullptr, worker, nullptr) == 0) {
                pthread_detach(th);
                I("worker spawned");
            } else {
                E("pthread_create failed");
            }
        }

        g_env->ReleaseStringUTFChars(args->nice_name, proc);
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
