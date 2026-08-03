#include <sys/types.h>
#include <sys/stat.h>
#include "zygisk.hpp"
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#define LOG_TAG "MyZygiskModule"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ===== 사용자 설정 =====
static const char* kTargetPkg = "com.gear2.growslayer"; // 반드시 실제 패키지명으로 변경
static const uintptr_t kOffsetLoadMetadata = 0x4463454; // 네가 확인한 오프셋
static const uint32_t kMetadataMagic = 0xAF1BB1FA;      // global-metadata.dat magic
static const char* kDumpPath = "/data/local/tmp/global-metadata.dump";
static const char* kTracePath = "/data/local/tmp/myzygisk_trace.log";

// ===== 상태 =====
static volatile bool g_worker_started = false;
static JNIEnv* g_env = nullptr;

// ===== 유틸 =====
static void tracef(const char* level, const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int prio = (!strcmp(level, "E")) ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO;
    __android_log_print(prio, LOG_TAG, "%s", buf);

    FILE* fp = fopen(kTracePath, "a");
    if (fp) {
        fprintf(fp, "[%s][pid:%d] %s\n", level, getpid(), buf);
        fclose(fp);
    }
}
#define TLOGI(...) tracef("I", __VA_ARGS__)
#define TLOGE(...) tracef("E", __VA_ARGS__)

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
    uintptr_t start = 0, end = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            if (addr >= start && addr < end) {
                TLOGI("addr 0x%" PRIxPTR " in map: %s", addr, line);
                fclose(fp);
                return true;
            }
        }
    }

    fclose(fp);
    return false;
}

// 간단한 안전 읽기(완전한 SIGSEGV 방지는 아님)
// 크래시 위험 줄이려고 maps 확인 후 최소 read만 수행
static bool read_u32_checked(uintptr_t addr, uint32_t* out) {
    if (!out) return false;
    if (!addr_in_maps(addr)) return false;
    *out = *(volatile uint32_t*)addr;
    return true;
}

// metadata 구조를 모르는 상황이므로, magic부터 찾고
// 최대 max_scan 범위 내에서 "그럴듯한 끝"을 추정하여 덤프
static bool dump_metadata_blob(uint8_t* base_ptr, size_t max_scan) {
    if (!base_ptr || max_scan < 0x1000) return false;

    // 1) magic 확인
    uint32_t magic = *(uint32_t*)base_ptr;
    if (magic != kMetadataMagic) {
        TLOGE("magic mismatch: got=0x%08x expect=0x%08x", magic, kMetadataMagic);
        return false;
    }

    TLOGI("metadata magic matched: 0x%08x", magic);

    // 2) version 읽기 (일반적으로 offset 4)
    uint32_t version = *(uint32_t*)(base_ptr + 4);
    TLOGI("metadata version guess: %u", version);

    // 3) 보수적으로 덤프 크기 추정
    // 완전한 파서는 아니므로 "무리하지 않는 크기"로 잘라 덤프
    // 필요 시 나중에 확장 가능
    size_t dump_size = 0x400000; // 4MB 기본
    if (dump_size > max_scan) dump_size = max_scan;
    if (dump_size < 0x1000) return false;

    FILE* out = fopen(kDumpPath, "wb");
    if (!out) {
        TLOGE("failed to open dump path: %s", kDumpPath);
        return false;
    }

    size_t wr = fwrite(base_ptr, 1, dump_size, out);
    fclose(out);

    if (wr != dump_size) {
        TLOGE("dump write failed: %zu/%zu", wr, dump_size);
        return false;
    }

    TLOGI("dump success: %s (%zu bytes)", kDumpPath, dump_size);
    return true;
}

// 핵심: 오프셋 함수 호출 시도
// 주의: 시그니처 불일치 시 크래시 가능.
// 네 정보 기반으로 (const char*) -> void* 가정.
typedef void* (*LoadMetaDataLike_t)(const char* path);

static void* worker_thread(void*) {
    TLOGI("worker started");

    // libil2cpp 로드 대기 (최대 20초)
    uintptr_t base = 0;
    for (int i = 0; i < 200; ++i) {
        base = get_module_base_rx("libil2cpp.so");
        if (base) break;
        usleep(100000); // 100ms
    }

    if (!base) {
        TLOGE("libil2cpp base not found (timeout)");
        return nullptr;
    }

    uintptr_t fn_addr = base + kOffsetLoadMetadata;
    TLOGI("libil2cpp base=0x%" PRIxPTR, base);
    TLOGI("target fn addr=0x%" PRIxPTR " (base+0x%" PRIxPTR ")", fn_addr, kOffsetLoadMetadata);

    if (!addr_in_maps(fn_addr)) {
        TLOGE("target addr not in maps");
        return nullptr;
    }

    // 함수 시작 바이트 4개 확인(디버깅용)
    uint32_t head = 0;
    if (read_u32_checked(fn_addr, &head)) {
        TLOGI("target first dword=0x%08x", head);
    } else {
        TLOGE("failed to read target first dword");
    }

    // 함수 직접 호출 시도 (위험 구간)
    // 앱 크래시 시 이 부분을 비활성화하고 다른 오프셋/시그니처 재검증 필요
    LoadMetaDataLike_t fn = reinterpret_cast<LoadMetaDataLike_t>(fn_addr);

    TLOGI("calling target fn(\"global-metadata.dat\") ...");
    void* meta_ptr = fn("global-metadata.dat");
    TLOGI("target fn returned meta_ptr=%p", meta_ptr);

    if (!meta_ptr) {
        TLOGE("meta_ptr is null");
        return nullptr;
    }

    // magic 검사
    uint32_t mg = *(uint32_t*)meta_ptr;
    TLOGI("meta_ptr magic=0x%08x", mg);

    if (mg != kMetadataMagic) {
        TLOGE("not plain metadata (maybe encrypted/transformed)");
        return nullptr;
    }

    // 덤프 (최대 16MB 스캔 한도)
    if (!dump_metadata_blob((uint8_t*)meta_ptr, 0x1000000)) {
        TLOGE("dump failed");
        return nullptr;
    }

    // 성공 마커
    FILE* ok = fopen("/data/local/tmp/myzygisk_dump_ok.flag", "w");
    if (ok) {
        fprintf(ok, "OK pid=%d base=0x%" PRIxPTR " fn=0x%" PRIxPTR " meta=%p dump=%s\n",
                getpid(), base, fn_addr, meta_ptr, kDumpPath);
        fclose(ok);
    }

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

        // 정확 일치 권장
        if (strcmp(proc, kTargetPkg) == 0 && !g_worker_started) {
            g_worker_started = true;
            TLOGI("target matched: %s", proc);

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
