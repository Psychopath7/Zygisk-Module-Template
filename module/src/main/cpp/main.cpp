#include <sys/types.h>
#include "zygisk.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "dobby.h"

#define LOG_TAG "MyZygiskModule"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

static bool g_il2cpp_hooked = false;
static bool g_target_seen = false;
static FILE* g_fp = nullptr;

// ---------- robust logger ----------
static void open_log_file_once() {
    if (g_fp) return;
    // root/magisk 환경에서 보통 접근 가능
    g_fp = fopen("/data/local/tmp/myzygisk_trace.log", "a");
}

static void close_log_file() {
    if (g_fp) {
        fflush(g_fp);
        fclose(g_fp);
        g_fp = nullptr;
    }
}

static void vlog_all(const char* level, const char* fmt, va_list ap) {
    char buf[2048];
    vsnprintf(buf, sizeof(buf), fmt, ap);

    // 1) logcat
    int prio = ANDROID_LOG_INFO;
    if (!strcmp(level, "E")) prio = ANDROID_LOG_ERROR;
    __android_log_print(prio, LOG_TAG, "%s", buf);

    // 2) stderr
    fprintf(stderr, "[%s][%s] %s\n", LOG_TAG, level, buf);
    fflush(stderr);

    // 3) file
    open_log_file_once();
    if (g_fp) {
        time_t t = time(nullptr);
        fprintf(g_fp, "[%ld][pid:%d][%s] %s\n", (long)t, getpid(), level, buf);
        fflush(g_fp);
    }
}

static void LOGI2(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_all("I", fmt, ap);
    va_end(ap);
}
static void LOGE2(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_all("E", fmt, ap);
    va_end(ap);
}

// ---------- helpers ----------
uintptr_t get_module_base(const char* module_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE2("failed to open /proc/self/maps");
        return 0;
    }

    char line[1024];
    uintptr_t start = 0, end = 0;
    char perm[8] = {0};
    char path[512] = {0};

    while (fgets(line, sizeof(line), fp)) {
        int n = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %*s %*s %*s %511s",
                       &start, &end, perm, path);
        if (n >= 4) {
            if (strstr(path, module_name) && strstr(perm, "r-x")) {
                fclose(fp);
                return start;
            }
        }
    }

    fclose(fp);
    return 0;
}

// target 주소가 maps 어느 구간인지 덤프
static void dump_mapping_for_addr(uintptr_t addr) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE2("dump_mapping_for_addr: maps open fail");
        return;
    }

    char line[1024];
    uintptr_t start = 0, end = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            if (addr >= start && addr < end) {
                LOGI2("addr 0x%" PRIxPTR " in mapping: %s", addr, line);
                fclose(fp);
                return;
            }
        }
    }
    fclose(fp);
    LOGE2("addr 0x%" PRIxPTR " not found in maps", addr);
}

typedef void* (*LoadMetaDataFile_t)(const char* path);
static LoadMetaDataFile_t orig_LoadMetaDataFile = nullptr;

void* my_LoadMetaDataFile(const char* path) {
    LOGI2("my_LoadMetaDataFile called: %s", path ? path : "(null)");
    void* ret = orig_LoadMetaDataFile ? orig_LoadMetaDataFile(path) : nullptr;
    LOGI2("LoadMetaDataFile ret=%p", ret);

    // 성공 마커 파일 (확실한 증거)
    FILE* ok = fopen("/data/local/tmp/myzygisk_hit.flag", "w");
    if (ok) {
        fprintf(ok, "HIT pid=%d path=%s ret=%p\n", getpid(), path ? path : "(null)", ret);
        fclose(ok);
    }
    return ret;
}

typedef void* (*android_dlopen_ext_t)(const char*, int, const void*);
static android_dlopen_ext_t orig_android_dlopen_ext = nullptr;

void* my_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    void* handle = orig_android_dlopen_ext(filename, flags, extinfo);

    if (!g_il2cpp_hooked && filename && strstr(filename, "libil2cpp.so")) {
        LOGI2("libil2cpp load detected: %s", filename);

        uintptr_t base = get_module_base("libil2cpp.so");
        if (!base) {
            LOGE2("libil2cpp base not found");
            return handle;
        }

        uintptr_t target = base + 0x4463454;
        LOGI2("base=0x%" PRIxPTR ", target=0x%" PRIxPTR, base, target);
        dump_mapping_for_addr(target);

        // readable probe
        volatile uint32_t probe = *(volatile uint32_t*)target;
        LOGI2("target first dword=0x%08x", probe);

        int hr = DobbyHook((void*)target, (void*)my_LoadMetaDataFile, (void**)&orig_LoadMetaDataFile);
        if (hr == 0) {  // success
            g_il2cpp_hooked = true;
            LOGI2("DobbyHook success @0x%" PRIxPTR, target);

            FILE* ok = fopen("/data/local/tmp/myzygisk_hooked.flag", "w");
            if (ok) {
                fprintf(ok, "HOOKED pid=%d base=0x%" PRIxPTR " target=0x%" PRIxPTR "\n", getpid(), base, target);
                fclose(ok);
            }
        } else {
            LOGE2("DobbyHook failed code=%d @0x%" PRIxPTR, hr, target);
        }
    }

    return handle;
}

class MyModule : public zygisk::ModuleBase {
public:
    ~MyModule() {
        close_log_file();
    }

    void onLoad(Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
        LOGI2("onLoad called");
    }

    void postAppSpecialize(const AppSpecializeArgs* args) override {
        if (!args || !args->nice_name) {
            LOGE2("postAppSpecialize: args or nice_name null");
            return;
        }

        const char* process_name = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) {
            LOGE2("GetStringUTFChars failed");
            return;
        }

        // 여기 패키지명 반드시 수정
        if (strstr(process_name, "com.gear2.growslayer")) {
            g_target_seen = true;
            LOGI2("target process detected: %s", process_name);

            FILE* ok = fopen("/data/local/tmp/myzygisk_target_seen.flag", "w");
            if (ok) {
                fprintf(ok, "TARGET pid=%d process=%s\n", getpid(), process_name);
                fclose(ok);
            }

            void* sym = DobbySymbolResolver(nullptr, "android_dlopen_ext");
            if (!sym) {
                LOGE2("android_dlopen_ext symbol not found");
            } else {
                int hr = DobbyHook(sym, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
                if (hr == 0) {  // success
                    LOGI2("hook android_dlopen_ext success");
                } else {
                    LOGE2("hook android_dlopen_ext failed code=%d", hr);
                }
            }
        }

        env_->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
};

REGISTER_ZYGISK_MODULE(MyModule)
