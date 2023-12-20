

export ANDROID_NDK=/root/Android/Sdk/ndk/21.4.7075529
export ABI=arm64-v8a

rm -r build
mkdir build && cd build 

# CMake的内置支持
# cmake -DCMAKE_SYSTEM_NAME=Android \
# 	-DCMAKE_SYSTEM_VERSION=29 \
# 	-DCMAKE_ANDROID_ARCH_ABI=x86_64 \
# 	-DANDROID_NDK=$ANDROID_NDK \
# 	-DCMAKE_ANDROID_STL_TYPE=c++_shared \
# 	..

# 工具链文件支持
cmake \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=$ABI \
    -DANDROID_PLATFORM=android-27 \
    -DANDROID_NDK=$ANDROID_NDK \
	..

cmake --build .

adb push elf /data/local/tmp/elf