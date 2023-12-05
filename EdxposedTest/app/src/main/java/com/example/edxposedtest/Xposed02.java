package com.example.edxposedtest;

import android.util.Log;

import java.lang.reflect.Field;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Xposed02 implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.example.hooktarge")) {

            Class<?> aClass = loadPackageParam.classLoader.loadClass("com.example.hooktarge.HookTarget2");
            Field id = aClass.getDeclaredField("id");
            id.setAccessible(true);
            XposedBridge.log("HookTarget2 id = " + id.get(null));
            id.set(null, 42);
            XposedBridge.log("HookTarget2 id = " + id.get(null) + ", change by field set");

            int id1 = XposedHelpers.getStaticIntField(aClass, "id");
            XposedBridge.log("HookTarget2 id = " + id1 + " get by api");
            XposedHelpers.setStaticIntField(aClass, "id", 100);
            XposedBridge.log("HookTarget2 id = " + XposedHelpers.getStaticIntField(aClass, "id") + " set by api");

            XposedHelpers.findAndHookConstructor("com.example.hooktarge.HookTarget2", loadPackageParam.classLoader, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                    Object thisObject = param.thisObject;
                    Field str = aClass.getDeclaredField("str");
                    str.setAccessible(true);
                    str.set(thisObject, "ass");
                    XposedBridge.log(param.thisObject.toString());

                    Object str1 = XposedHelpers.getObjectField(thisObject, "str");
                    XposedBridge.log(str1 + " get by api");
                    XposedHelpers.setObjectField(thisObject, "str", "hhhhh");
                    XposedBridge.log(param.thisObject.toString() + "change by api");
                }
            });

        }
    }

}
