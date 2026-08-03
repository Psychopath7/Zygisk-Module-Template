#include <sys/types.h>
#include "zygisk.hpp"
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <thread>
#include <inttypes.h>

#define LOG_TAG "MyZygiskModule"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// --- 1. /proc/self/maps 읽기 유틸리티 ---
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

// --- 2. 비침습적 메모리 감시 스레드 ---
void monitor_thread() {
    LOGI("[*] Passive memory monitor thread started...");
    
    uintptr_t base_addr = 0;
    
    // libil2cpp.so가 메모리에 올랐는지 100ms 간격으로 확인 (최대 30초간 대기)
    for (int i = 0; i < 300; i++) {
        base_addr = get_module_base("libil2cpp.so");
        if (base_addr != 0) {
            LOGI("[!] ========================================");
            LOGI("[!] libil2cpp.so Loaded in Memory!");
            LOGI("[!] Base Address : 0x%" PRIxPTR, base_addr);
            LOGI("[!] Target Addr  : 0x%" PRIxPTR, base_addr + 0x4463454);
            LOGI("[!] ========================================");
            break;
        }
        usleep(100000); // 0.1초 대기
    }

    if (base_addr == 0) {
        LOGE("[-] Timeout: libil2cpp.so was not loaded in 30 seconds.");
    }
}

// --- 3. Zygisk 메인 로직 ---
class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        // ⚠️ 주의: 반드시 분석할 앱의 실제 패키지명으로 입력하세요!
        if (process_name != nullptr && strstr(process_name, "com.gear2.growslayer")) {
            LOGI("[!] Target App Specialized: %s", process_name);
            
            // 시스템 메모리를 변조하지 않고, 수동 감시 스레드만 독립 실행
            std::thread(monitor_thread).detach();
        }
        
        env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)
