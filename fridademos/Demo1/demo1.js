function main() {
    Java.perform(function () {
        // 相当于是找到类 Class 对象
        var fridaDemo1Class = Java.use("com.example.demo1.FridaDemo1")

        // hook com.example.demo1.FridaDemo1#func(int, int)
        fridaDemo1Class.func.overload('int', 'int').implementation = function (arg1, arg2) {
            // 获取原函数的结果
            var result = this.func(arg1, arg2);
            // 打印参数与结果
            console.log("arg1, arg2, result", arg1, arg2, result)
            // 改变函数的结果
            return 9527;
        }

        // hook com.example.demo1.FridaDemo1#func(java.lang.String)
        fridaDemo1Class.func.overload('java.lang.String').implementation = function (arg1) {
            // 构造一个 String 对象
            var helloStr = Java.use('java.lang.String').$new('Hello')
            // 改变传递的参数，执行原函数
            var result = this.func(helloStr);

            console.log("arg1, result", arg1, result)

            // 返回 world
            return Java.use('java.lang.String').$new("World");
        }

        // hook com.example.demo1.FridaDemo1#nice
        fridaDemo1Class.nice.implementation = function () {
            // 获取原函数的结果
            var result = this.nice();
            // 打印参数与结果
            console.log("nice result", result)
            return result;
        }

        // hook com.example.demo1.FridaDemo1#secret
        fridaDemo1Class.secret.implementation = function () {
            var result = this.secret();
            console.log("secret result", result)
            return result;
        }

        // 找到类的实例对象
        Java.choose("com.example.demo1.MainActivity", {
            onMatch: function (instance) {
                console.log("found instance :", instance)
                console.log("found instance :", instance.abc())
            }, onComplete: function () { }
        })

        var result = Java.use("com.example.demo1.MainActivity").sabc();
        console.log(result);
    })
}

// 立即执行 main 函数
setImmediate(main)

function trigger() {
    Java.perform(function () {
        // 找到类的实例对象
        Java.choose("com.example.demo1.MainActivity", {
            onMatch: function (instance) {
                console.log("trigger test method ... ", instance.test())
            }, onComplete: function () { }
        })
    })
}

// 2s后执行trigger函数
setTimeout(trigger, 2000)