
#include <android/log.h>
#include <jni.h>
#include <cstring>

extern "C" bool test_hook(const char *content) {
    __android_log_print(4, "hook_so", "junk code");
    __android_log_print(4, "hook_so", "junk code");
    __android_log_print(4, "hook_so", "junk code");
    return strstr(content, "test_hook") != nullptr;
}

__attribute__((constructor(1), visibility("hidden"))) void my_init_array1(void) {
    if (test_hook("my_init_array1")) {
        __android_log_print(4, "hook_so", "my_init_array1 success");
    } else {
        __android_log_print(4, "hook_so", "my_init_array1 failed");
    }
}

extern "C" void _init(void) {
    if (test_hook("_init")) {
        __android_log_print(4, "hook_so", "_init success");
    } else {
        __android_log_print(4, "hook_so", "_init failed");
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_nativehooktarget_MainActivity_hookMe(JNIEnv
                                                      *env,
                                                      jobject thiz
) {
    if (test_hook("hookMe")) {
        __android_log_print(4, "hook_so", "hookMe success");
    } else {
        __android_log_print(4, "hook_so", "hookMe failed");
    }

}