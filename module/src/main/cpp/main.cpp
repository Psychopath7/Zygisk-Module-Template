#include <zygisk.hpp>
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include "dobby.h"

#define LOG_TAG "MyZygiskModule"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// --- 1. 유틸리티: 프로세스 메모리에서 모듈의 베이스 주소 구하기 ---
uintptr_t get_module_base(const char* module_name) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("[!] /proc/self/maps 파일을 열 수 없습니다.");
        return 0; 
    }

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

// --- 2. 후킹할 타겟 함수(LoadMetaDataFile) 원본 포인터 및 가짜 함수 ---
typedef void* (*LoadMetaDataFile_t)(const char* path);
LoadMetaDataFile_t orig_LoadMetaDataFile = nullptr;

void* my_LoadMetaDataFile(const char* path) {
    LOGI("[!] my_LoadMetaDataFile 실행됨! 경로: %s", path);
    
    // 원본 로직 실행
    void* result = orig_LoadMetaDataFile(path); 
    
    LOGI("[!] LoadMetaDataFile 반환값(retval): %p", result);
    return result;
}

// --- 3. android_dlopen_ext 후킹 (libil2cpp.so 메모리 로드 감지용) ---
typedef void* (*android_dlopen_ext_t)(const char*, int, const void*);
android_dlopen_ext_t orig_android_dlopen_ext = nullptr;

void* my_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    // 라이브러리가 정상적으로 메모리에 올라가도록 원본 함수 먼저 실행
    void* handle = orig_android_dlopen_ext(filename, flags, extinfo);
    
    if (filename != nullptr && strstr(filename, "libil2cpp.so")) {
        LOGI("[!] libil2cpp.so 메모리 로드 감지됨!");
        
        // 베이스 주소 구하기
        uintptr_t base_addr = get_module_base("libil2cpp.so");
        
        if (base_addr != 0) {
            // 요청하신 오프셋 0x4463454 적용
            uintptr_t target_addr = base_addr + 0x4463454;
            
            LOGI("[!] libil2cpp.so Base: 0x%" PRIxPTR, base_addr);
            LOGI("[!] Target Offset Address: 0x%" PRIxPTR, target_addr);
            
            // Dobby를 사용하여 타겟 메모리 주소 인라인 후킹
            DobbyHook((void*)target_addr, (void*)my_LoadMetaDataFile, (void**)&orig_LoadMetaDataFile);
            LOGI("[!] 성공적으로 후킹되었습니다!");
        } else {
            LOGE("[!] libil2cpp.so 베이스 주소를 찾을 수 없습니다.");
        }
    }
    
    return handle;
}

// --- 4. Zygisk 모듈 메인 클래스 ---
class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        // ⚠️ 주의: 본인이 실습하는 앱의 패키지명으로 "com.your.target.app"을 수정해야 합니다.
        if (process_name != nullptr && strstr(process_name, "com.gear2.growslayer")) {
            LOGI("[!] 타겟 앱(%s) 감지됨. dlopen 후킹 대기...", process_name);
            
            // 시스템 dlopen 함수 주소를 찾아 후킹 준비
            void* dlopen_addr = DobbySymbolResolver(nullptr, "android_dlopen_ext");
            if (dlopen_addr) {
                DobbyHook(dlopen_addr, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
            } else {
                LOGE("[!] android_dlopen_ext 주소를 찾을 수 없습니다.");
            }
        }
        
        env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    Api *api;
    JNIEnv *env;
};

// Zygisk 모듈 등록 매크로
REGISTER_ZYGISK_MODULE(MyModule)
