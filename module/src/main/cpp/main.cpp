#include "zygisk.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "dobby.h"

#define LOG_TAG "MyZygiskModule"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// --- 1. 유틸리티 (기존과 동일) ---
uintptr_t get_module_base(const char* module_name) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0; 
    char line[512];
    uintptr_t base_addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            base_addr = (uintptr_t)strtoull(line, NULL, 16);
            break; 
        }
    }
    fclose(fp);
    return base_addr;
}

// --- 2. 타겟 함수 후킹 로직 (기존과 동일) ---
typedef void* (*LoadMetaDataFile_t)(const char* path);
LoadMetaDataFile_t orig_LoadMetaDataFile = nullptr;

void* my_LoadMetaDataFile(const char* path) {
    LOGI("[!] my_LoadMetaDataFile Executed! Path: %s", path);
    void* result = orig_LoadMetaDataFile(path); 
    LOGI("[!] LoadMetaDataFile retval: %p", result);
    return result;
}

// --- 3. 🌟 모든 라이브러리 로드 감지 (수정됨) ---
typedef void* (*android_dlopen_ext_t)(const char*, int, const void*);
android_dlopen_ext_t orig_android_dlopen_ext = nullptr;

void* my_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    // 앱이 로드하려고 시도하는 모든 모듈의 이름을 로그로 출력
    if (filename != nullptr) {
        LOGI("[*] Loading library: %s", filename);
    }
    
    void* handle = orig_android_dlopen_ext(filename, flags, extinfo);
    
    if (filename != nullptr && strstr(filename, "libil2cpp.so")) {
        LOGI("[!] === libil2cpp.so Load Detected! ===");
        uintptr_t base_addr = get_module_base("libil2cpp.so");
        
        if (base_addr != 0) {
            uintptr_t target_addr = base_addr + 0x4463454;
            LOGI("[!] libil2cpp.so Base: 0x%" PRIxPTR, base_addr);
            DobbyHook((void*)target_addr, (void*)my_LoadMetaDataFile, (void**)&orig_LoadMetaDataFile);
            LOGI("[!] Hook applied at: 0x%" PRIxPTR, target_addr);
        } else {
            LOGE("[-] Failed to find libil2cpp.so base.");
        }
    }
    
    return handle;
}

// --- 4. Zygisk 메인 로직 (주입 확인 로그 추가) ---
class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        // ⚠️ 주의: 반드시 실제 분석할 앱의 패키지명으로 변경하세요!
        if (process_name != nullptr && strstr(process_name, "com.gear2.growslayer")) {
            // 🌟 Zygisk가 앱에 정상 주입되었는지 확인하는 로그
            LOGI("[!] ========================================");
            LOGI("[!] Target App Specialized: %s", process_name);
            LOGI("[!] ========================================");
            
            void* dlopen_addr = DobbySymbolResolver(nullptr, "android_dlopen_ext");
            if (dlopen_addr) {
                DobbyHook(dlopen_addr, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
                LOGI("[*] dlopen_ext hooked successfully!");
            }
        }
        
        env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)
