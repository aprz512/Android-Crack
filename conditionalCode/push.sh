adb connect 192.168.3.12:5555

adb push obj/local/arm64-v8a/conditional /data/local/tmp/conditional64
adb shell "chmod 777 /data/local/tmp/conditional64"

adb push obj/local/armeabi-v7a/conditional /data/local/tmp/conditional32
adb shell "chmod 777 /data/local/tmp/conditional32"
