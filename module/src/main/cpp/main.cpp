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
#include <dlfcn.h>
#include "dobby.h"

#define LOG_TAG "MyZygiskModule"
using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ===== 설정 =====
static const char* kTargetPkg = "com.gear2.growslayer";   // 실제 패키지명
static const uintptr_t kOffsetLoadMetadata = 0x4463454;  // 대상 오프셋
static const uint32_t kMetadataMagic = 0xAF1BB1FA;

static const char* kTracePath = "/data/local/tmp/myzygisk_trace.log";
static const char* kSeenPath  = "/data/local/tmp/myzygisk_target_seen.flag";
static const char* kOkPath    = "/data/local/tmp/myzygisk_dump_ok.flag";
static const char* kDumpPath  = "/data/local/tmp/global-metadata.dump";

// ===== 전역 =====
static JNIEnv* g_env = nullptr;
static volatile bool g_target_proc = false;
static volatile bool g_dlopen_hooked = false;
static volatile bool g_meta_hooked = false;

// ===== 로깅 =====
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

// ===== 유틸 =====
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

// ===== metadata hook =====
typedef void* (*LoadMetaDataLike_t)(const char* path);
static LoadMetaDataLike_t orig_LoadMeta = nullptr;

static void* my_LoadMeta(const char* path) {
    I("my_LoadMeta enter path=%s", path ? path : "(null)");

    void* ret = nullptr;
    if (orig_LoadMeta) ret = orig_LoadMeta(path);

    I("my_LoadMeta ret=%p", ret);

    if (ret) {
        uint32_t magic = *(uint32_t*)ret;
        I("meta magic=0x%08x", magic);

        if (magic == kMetadataMagic) {
            // 우선 4MB 덤프
            FILE* out = fopen(kDumpPath, "wb");
            if (out) {
                size_t dumpSize = 0x400000;
                size_t wr = fwrite(ret, 1, dumpSize, out);
                fclose(out);
                I("dump write: %zu/%zu", wr, dumpSize);

                FILE* ok = fopen(kOkPath, "w");
                if (ok) {
                    fprintf(ok, "OK pid=%d ret=%p size=%zu path=%s\n", getpid(), ret, wr, kDumpPath);
                    fclose(ok);
                }
            } else {
                E("failed to open dump path");
            }
        }
    }

    return ret;
}

// ===== dlopen hook =====
typedef void* (*android_dlopen_ext_t)(const char*, int, const void*);
static android_dlopen_ext_t orig_dlopen_ext = nullptr;

static void* my_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    void* h = orig_dlopen_ext ? orig_dlopen_ext(filename, flags, extinfo) : nullptr;

    if (!g_target_proc) return h;
    if (g_meta_hooked) return h;
    if (!filename) return h;

    if (strstr(filename, "libil2cpp.so")) {
        I("libil2cpp loaded: %s", filename);

        uintptr_t base = get_module_base_rx("libil2cpp.so");
        if (!base) {
            E("libil2cpp base not found yet");
            return h;
        }

        uintptr_t fn = base + kOffsetLoadMetadata;
        I("libil2cpp base=0x%" PRIxPTR ", fn=0x%" PRIxPTR, base, fn);

        int hr = DobbyHook((void*)fn, (void*)my_LoadMeta, (void**)&orig_LoadMeta);
        if (hr == 0) {
            g_meta_hooked = true;
            I("LoadMeta hook success");
        } else {
            E("LoadMeta hook failed code=%d", hr);
        }
    }

    return h;
}

// ===== module =====
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

        size_t n = strlen(kTargetPkg);
        bool match = (strcmp(proc, kTargetPkg) == 0) ||
                     (strncmp(proc, kTargetPkg, n) == 0 && proc[n] == ':');

        if (match) {
            g_target_proc = true;
            I("target matched in pid=%d proc=%s", getpid(), proc);

            FILE* f = fopen(kSeenPath, "w");
            if (f) {
                fprintf(f, "seen pid=%d proc=%s\n", getpid(), proc);
                fclose(f);
            }

            if (!g_dlopen_hooked) {
                void* sym = DobbySymbolResolver(nullptr, "android_dlopen_ext");
                if (!sym) {
                    E("android_dlopen_ext symbol not found");
                } else {
                    int hr = DobbyHook(sym, (void*)my_dlopen_ext, (void**)&orig_dlopen_ext);
                    if (hr == 0) {
                        g_dlopen_hooked = true;
                        I("hook android_dlopen_ext success");
                    } else {
                        E("hook android_dlopen_ext failed code=%d", hr);
                    }
                }
            }
        }

        g_env->ReleaseStringUTFChars(args->nice_name, proc);
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
