

Java.perform(function () {

    Java.use("android.widget.TextView").setText.overload('java.lang.CharSequence').implementation = function (text) {
        var text_str = text.toString();

        // 将字符串发送到主机进程
        send(text_str);


        var recv_str;

        recv(function (received_json) {
            // 收到的 json 格式与 python 对应即可
            recv_str = received_json.data
            console.log("received_json:" + recv_str)
        }).wait();

        var replaced_str = Java.use('java.lang.String').$new(recv_str);

        var result = this.setText(replaced_str);

        return result;
    }

})


function show_time13212() {
    Java.perform(function () {
        Java.choose('com.example.demo3.MainActivity', {
            onMatch(instance) {
                instance.showTime();
            },
            onComplete() { }
        })
    })
}



rpc.exports = {
    showTime: show_time13212
}
