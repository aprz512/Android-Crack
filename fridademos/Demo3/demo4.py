import time
import frida
import base64


def my_message_handler(message, payload):
    print("message:", message)
    print("payload:", payload)
    if message["type"] == "send":
        data = message["payload"].split(":")[1].strip()
        print('data:', message)
        encode_data = str(base64.b64decode(data))
        print('encode_data:', encode_data)
        name, password = encode_data.split(":")
        print("name:" + name)
        print("password:" + password)
        replaced_data = str(base64.b64encode(("admin"+":"+password).encode()))
        print("replaced_data:", replaced_data)
        script.post({"data": replaced_data})
        print("send replaced data!!!")


# 这里的端口号是 frida-server 开启时的端口号
# device = frida.get_device_manager().add_remote_device("192.168.3.12:7788")
device = frida.get_usb_device()

# 以 spawn 模式启动
pid = device.spawn(["com.example.demo3"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)


# session = device.attach("com.example.demo3")


# 加载脚本
with open("demo4.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)
script.load()

# 执行方法调用
command = ""
while True:
    command = input("Enter Command:")
    if command == "1":
        # 这里会将 show_time 转成 showTime，真TM神奇，所以最好直接用小写
        script.exports.show_time()
    else:
        print("unknown command")
