function LogPrint(log) {
    var theDate = new Date();
    var hour = theDate.getHours();
    var minute = theDate.getMinutes();
    var second = theDate.getSeconds();
    var mSecond = theDate.getMilliseconds();

    hour < 10 ? hour = "0" + hour : hour;
    minute < 10 ? minute = "0" + minute : minute;
    second < 10 ? second = "0" + second : second;
    mSecond < 10 ? mSecond = "00" + mSecond : mSecond < 100 ? mSecond = "0" + mSecond : mSecond;
    var time = hour + ":" + minute + ":" + second + ":" + mSecond;
    var threadid = Process.getCurrentThreadId();
    console.log("[" + time + "]" + "->threadid:" + threadid + "--" + log);

}

function printNativeStack(context, name) {
    //Debug.
    var array = Thread.backtrace(context, Backtracer.ACCURATE);
    var first = DebugSymbol.fromAddress(array[0]);
    if (first.toString().indexOf('libopenjdk.so!NET_Send') < 0) {
        var trace = Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
        LogPrint("-----------start:" + name + "--------------");
        LogPrint(trace);
        LogPrint("-----------end:" + name + "--------------");
    }

}

function printJavaStack(name) {
    Java.perform(function () {
        var Exception = Java.use("java.lang.Exception");
        var ins = Exception.$new("Exception");
        var straces = ins.getStackTrace();
        if (straces != undefined && straces != null) {
            var strace = straces.toString();
            var replaceStr = strace.replace(/,/g, " \n ");
            LogPrint("=============================" + name + " Stack strat=======================");
            LogPrint(replaceStr);
            LogPrint("=============================" + name + " Stack end======================= \n ");
            Exception.$dispose();
        }
    });
}

function isprintable(value) {
    if (value >= 32 && value <= 126) {
        return true;
    }
    return false;
}

function getsocketdetail(fd) {
    var result = "";
    var type = Socket.type(fd);
    if (type != null) {
        result = result + "type:" + type;
        var peer = Socket.peerAddress(fd);
        var local = Socket.localAddress(fd);
        result = result + ",address:" + JSON.stringify(peer) + ",local:" + JSON.stringify(local);
    } else {
        result = "unknown";
    }
    return result;

}

function hookSocket() {
    var libcmodule = Process.getModuleByName("libc.so");
    var recvfrom_addr = libcmodule.getExportByName("recvfrom");
    var sendto_addr = libcmodule.getExportByName("sendto");
    console.log(recvfrom_addr + "---" + sendto_addr);
    //ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len)
    Interceptor.attach(recvfrom_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];

            LogPrint("go into libc.so->recvfom");

            printNativeStack(this.context, "recvfom");
        }, onLeave(retval) {
            var size = retval.toInt32();
            if (size > 0) {
                var result = getsocketdetail(this.arg0.toInt32());
                console.log(result + "---libc.so->recvfrom:" + hexdump(this.arg1, {
                    length: size
                }));
            }

            LogPrint("leave libc.so->recvfom");
        }
    });
    //ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len)
    Interceptor.attach(sendto_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            LogPrint("go into libc.so->sendto");
            printNativeStack(this.context, "sendto");
        }, onLeave(retval) {
            var size = ptr(this.arg2).toInt32();
            if (size > 0) {
                var result = getsocketdetail(this.arg0.toInt32());
                console.log(result + "---libc.so->sendto:" + hexdump(this.arg1, {
                    length: size
                }));
            }

            LogPrint("leave libc.so->sendto");
        }
    });
}

function main() {
    hookSocket();
}

setImmediate(main);