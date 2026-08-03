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

static const char* kTargetPkg = "com.your.target.app"; // 실제 패키지명
static const char* kTracePath = "/data/local/tmp/myzygisk_trace.log";

static JNIEnv* g_env = nullptr;
static volatile bool g_started = false;

static void tlog(const char* lv, const char* fmt, ...) {
    char buf[1024];
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

static void maybe_start(const char* proc) {
    if (!proc || g_started) return;

    I("proc=%s", proc);

    size_t n = strlen(kTargetPkg);
    bool match = (strcmp(proc, kTargetPkg) == 0) ||
                 (strncmp(proc, kTargetPkg, n) == 0 && proc[n] == ':');

    if (match) {
        g_started = true;
        I("target matched in pid=%d proc=%s", getpid(), proc);

        FILE* ok = fopen("/data/local/tmp/myzygisk_target_seen.flag", "w");
        if (ok) {
            fprintf(ok, "seen pid=%d proc=%s\n", getpid(), proc);
            fclose(ok);
        }
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
            E("preAppSpecialize invalid args/env");
            return;
        }
        const char* proc = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!proc) {
            E("pre GetStringUTFChars failed");
            return;
        }
        maybe_start(proc);
        g_env->ReleaseStringUTFChars(args->nice_name, proc);
    }

    void postAppSpecialize(const AppSpecializeArgs* args) override {
        I("postAppSpecialize entered");
        if (!args || !args->nice_name || !g_env) {
            E("postAppSpecialize invalid args/env");
            return;
        }
        const char* proc = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!proc) {
            E("post GetStringUTFChars failed");
            return;
        }
        maybe_start(proc);
        g_env->ReleaseStringUTFChars(args->nice_name, proc);
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
