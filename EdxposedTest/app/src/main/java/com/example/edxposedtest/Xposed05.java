package com.example.edxposedtest;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;


public class Xposed05 implements IXposedHookLoadPackage {


    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (!loadPackageParam.packageName.equals("com.example.nativehooktarget")) {
            return;
        }

        XposedHelpers.findAndHookMethod(
                "java.lang.Runtime",
                loadPackageParam.classLoader,
                "loadLibrary0",
                ClassLoader.class,
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        super.beforeHookedMethod(param);
                        XposedBridge.invokeOriginalMethod(param.method, param.thisObject, new Object[] {
                                param.args[0], "sohook"
                        });
                        Log.e("hook_so", "beforeHookedMethod");
                    }
                });
    }

}
