#include <jni.h>
#include <zygisk.hpp>
#include <android/log.h>
#include <string>
#include <atomic>

#define LOG_TAG "ZygiskToolLoader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

static constexpr const char *kTargetPackage = "com.gear2.growslayer"; 
// 예: "com.example.game"

static constexpr const char *kTargetActivityClass =
    "com/google/firebase/MessagingUnityPlayerActivity";

static std::atomic<bool> g_should_hook{false};
static std::atomic<bool> g_loaded_once{false};

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) return;
        const char *process = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (!process) return;

        // 보통 메인 프로세스명 == 패키지명
        if (strcmp(process, kTargetPackage) == 0) {
            g_should_hook.store(true);
            LOGI("Target process matched: %s", process);
        }
        env_->ReleaseStringUTFChars(args->nice_name, process);
    }

    void postAppSpecialize(const AppSpecializeArgs *) override {
        if (!g_should_hook.load()) return;
        installJavaHookFallback();
    }

private:
    Api *api_{nullptr};
    JNIEnv *env_{nullptr};

    // "onCreate 첫줄 아래"에 smali 삽입 대신,
    // Activity 생성 시점에서 loadLibrary를 시도하는 fallback.
    void installJavaHookFallback() {
        JNIEnv *env = env_;
        if (!env) return;

        // 1) 대상 Activity 클래스 확인
        jclass targetCls = env->FindClass(kTargetActivityClass);
        if (!targetCls) {
            env->ExceptionClear();
            LOGE("Target class not found: %s", kTargetActivityClass);
            return;
        }
        env->DeleteLocalRef(targetCls);

        // 2) System.loadLibrary("Tool") 호출
        callSystemLoadLibrary("Tool");
    }

    void callSystemLoadLibrary(const char *libName) {
        if (g_loaded_once.exchange(true)) {
            LOGI("Library already loaded once, skip");
            return;
        }

        JNIEnv *env = env_;
        jclass systemCls = env->FindClass("java/lang/System");
        if (!systemCls) {
            env->ExceptionClear();
            LOGE("java/lang/System not found");
            return;
        }

        jmethodID midLoadLibrary = env->GetStaticMethodID(
            systemCls, "loadLibrary", "(Ljava/lang/String;)V");
        if (!midLoadLibrary) {
            env->ExceptionClear();
            LOGE("System.loadLibrary method not found");
            env->DeleteLocalRef(systemCls);
            return;
        }

        jstring jLib = env->NewStringUTF(libName);
        env->CallStaticVoidMethod(systemCls, midLoadLibrary, jLib);

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            LOGE("System.loadLibrary(\"%s\") threw exception", libName);
        } else {
            LOGI("System.loadLibrary(\"%s\") success", libName);
        }

        env->DeleteLocalRef(jLib);
        env->DeleteLocalRef(systemCls);
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
