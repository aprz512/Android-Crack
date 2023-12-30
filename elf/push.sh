adb connect 192.168.3.12:5555
adb push ls2 /data/local/tmp/ls
adb shell "chmod 777 /data/local/tmp/ls"
adb shell "/data/local/tmp/ls"