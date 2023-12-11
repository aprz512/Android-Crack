//
// Created by root on 12/9/23.
//

#include "jni.h"
#include <cstring>
#include <android/log.h>
#include "sandhook_native.h"



void *orig = nullptr;

typedef char *(*type_t)(char *, char *);

char* proxy(char *str1, char *str2) {
    // invoke origin method
    char * result = ((type_t) orig)(str1, str2);
    if (strcmp(str2, "test_hook") == 0) {
        return str1;
    }
    __android_log_print(4, "hook_so", "proxy origin result %s", result);
    return result;
}

void do_hook_test_hook() {
    const char *libc_path = "/system/lib64/libc.so";
    orig = SandInlineHookSym(libc_path, "strstr", reinterpret_cast<void *>(&proxy));

    __android_log_print(4, "hook_so", "hook result %p", orig);
}

extern "C" jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    do_hook_test_hook();
    return JNI_VERSION_1_6;
}