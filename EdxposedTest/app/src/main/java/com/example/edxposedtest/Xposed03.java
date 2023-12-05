package com.example.edxposedtest;

import java.lang.reflect.Field;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Xposed03 implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.example.hooktarge")) {
            XposedHelpers.findAndHookMethod(
                    "com.example.hooktarge.HookTarget3",
                    loadPackageParam.classLoader,
                    "test1",
                    new XC_MethodHook() {

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                    param.setResult("test11111111");
                }
            });

            XposedHelpers.findAndHookMethod(
                    "com.example.hooktarge.HookTarget3",
                    loadPackageParam.classLoader,
                    "test2",
                    new XC_MethodHook() {

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            super.afterHookedMethod(param);
                            param.setResult("test222222222");
                        }
                    });

            XposedHelpers.findAndHookMethod(
                    "com.example.hooktarge.HookTarget3$AbsClass",
                    loadPackageParam.classLoader,
                    "test1",
                    new XC_MethodHook() {

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            super.afterHookedMethod(param);
                            param.setResult("test11111111");
                        }
                    });

            XposedHelpers.findAndHookMethod(
                    "com.example.hooktarge.HookTarget3$1",
                    loadPackageParam.classLoader,
                    "run",
                    new XC_MethodHook() {

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            super.afterHookedMethod(param);
                            param.setResult(100);
                        }
                    });

        }
    }

}
