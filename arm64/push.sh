adb connect 192.168.3.12:5555
adb push obj/local/arm64-v8a/arm64 /data/local/tmp/arm64
adb shell "chmod 777 /data/local/tmp/arm64"
#adb push obj/local/armeabi-v7a/arm64 /data/local/tmp/arm32
#adb shell "chmod 777 /data/local/tmp/arm32"
