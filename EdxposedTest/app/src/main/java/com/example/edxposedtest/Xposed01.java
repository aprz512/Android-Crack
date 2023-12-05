package com.example.edxposedtest;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Xposed01 implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.example.hooktarge")) {
//
//            XposedHelpers.findAndHookConstructor(loadPackageParam.classLoader.loadClass("com.example.hooktarge.HookTarget1"), new XC_MethodHook() {
//                @Override
//                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
//                    super.beforeHookedMethod(param);
//                    Log.e("Xposed01", "no params beforeHookedMethod");
//                }
//
//                @Override
//                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
//                    super.afterHookedMethod(param);
//                    Log.e("Xposed01", "no params afterHookedMethod");
//                }
//            });
            XposedHelpers.findAndHookConstructor("com.example.hooktarge.HookTarget1", loadPackageParam.classLoader, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    Log.e("Xposed01", "no params beforeHookedMethod");
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                    Log.e("Xposed01", "no params afterHookedMethod");
                }
            });
            XposedHelpers.findAndHookConstructor("com.example.hooktarge.HookTarget1", loadPackageParam.classLoader, String.class, long.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    Log.e("Xposed01", "params beforeHookedMethod");
                    param.args[0] = "abd";
                    param.args[1] = 42;
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                    Log.e("Xposed01", "params afterHookedMethod");
                    Log.e("Xposed01", "thisObject = " + param.thisObject);
                    Log.e("Xposed01", "getResult = " + param.getResult());
                }
            });
        }
    }

}
