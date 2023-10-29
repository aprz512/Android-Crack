function main() {
    Java.perform(function () {

        Java.use("java.util.Arrays").toString.overload('[Ljava.lang.Object;').implementation = function (x) {
            var result = this.toString(x);
            if (x.length > 0 && x[0].getClass().getName() == "com.example.demo2.MainActivity$Bean") {
                Java.openClassFile("/data/local/tmp/r0gson.dex").load();
                const gsonClass = Java.use('com.r0ysue.gson.Gson');
                for (var i = 0; i < x.length; i++) {
                    console.log("entry=", gsonClass.$new().toJson(x[i]));
                }
            }
            return result;
        }


        // Java.choose('com.example.demo2.Father', {
        //     onMatch: function (instance) {
        //         console.log('found instance', instance);
        //         var son = Java.cast(instance, Java.use('com.example.demo2.Son'))
        //         console.log('cast instance', son.test());
        //     }, onComplete: function () { }

        // })


        Java.choose('com.example.demo2.Son', {
            onMatch: function (instance) {
                console.log('found instance', instance);
                var father = Java.cast(instance, Java.use('com.example.demo2.Father'))
                console.log('cast instance', father.test());
            }, onComplete: function () { }

        })

        Java.registerClass({
            name: 'com.example.demo2.SimpleBook2',
            implements: [Java.use('com.example.demo2.IBook')],
            fields: {
                proxy: 'com.example.demo2.IBook',
            },
            methods: {
                '<init>': [{
                    returnType: 'void',
                    argumentTypes: ['com.example.demo2.IBook'],
                    implementation: function (proxy) {
                        this.$super.$init();
                        this.proxy.value = proxy;
                    }
                }],
                id() {
                    return this.proxy.value.id();
                },
                size() {
                    return this.proxy.value.size();
                },
                test(input) {
                    this.proxy.value.test(input);
                    return true;
                },
            }
        })

        Java.choose('com.example.demo2.MainActivity', {
            onMatch: function (instance) {
                console.log('found MainActivity instance', instance);
                var oldBook = instance.book.value;
                instance.book.value = Java.use('com.example.demo2.SimpleBook2').$new(oldBook);
                console.log('book test id = ', instance.book.value.id());
                console.log('book test size = ', instance.book.value.size());
                console.log('book test result = ', instance.book.value.test(1));
            }, onComplete: function () { }

        })

        var methods = Java.use('com.example.demo2.MainActivity').class.getDeclaredMethods();
        for (var i in methods) {
            console.log('origin method name -> ' + methods[i].toString());
            console.log('encode method name ->' + encodeURIComponent(methods[i].toString().replace(/^.*?\.([^\s\.\(\)]+)\(.*?$/, "$1")));
        }


        Java.use('com.example.demo2.MainActivity')[decodeURIComponent("%D6%8F")].implementation = function() {
            console.log('method invoke');
            return 200;
        }
    })
}



setImmediate(main)
