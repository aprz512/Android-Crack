package com.example.edxposedtest;

import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.widget.Toast;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;



public class Xposed04 implements IXposedHookLoadPackage {

//    private static Class<?> loadClass(String className, ClassLoader classLoader) {
//
//    }


    public static ClassLoader getLoadedApkClassloader(XC_MethodHook.MethodHookParam param) {
        ClassLoader currentClassLoader = param.thisObject.getClass().getClassLoader();

        Object currentActivityThread = XposedHelpers.callStaticMethod(
                XposedHelpers.findClass("android.app.ActivityThread", currentClassLoader),
                "currentActivityThread",
                new Class[]{},
                new Object[]{});

        Object mBoundApplication = XposedHelpers.getObjectField(
                currentActivityThread,
                "mBoundApplication");

        Application mInitialApplication = (Application) XposedHelpers.getObjectField(
                currentActivityThread,
                "mInitialApplication");

        Object loadedApkInfo = XposedHelpers.getObjectField(
                mBoundApplication, "info");


        Application mApplication = (Application) XposedHelpers.getObjectField(loadedApkInfo, "mApplication");

        return mApplication.getClassLoader();
    }

    public void getClassLoaderClassList(ClassLoader classLoader) {
        //private final DexPathList pathList;
        XposedBridge.log("start deal with classloader:" + classLoader);
        Object pathListObj = XposedHelpers.getObjectField(classLoader, "pathList");
        //private final Element[] dexElements;
        Object[] dexElementsObj = (Object[]) XposedHelpers.getObjectField(pathListObj, "dexElements");
        for (Object i : dexElementsObj) {
            //private final DexFile dexFile;
            Object dexFileObj = XposedHelpers.getObjectField(i, "dexFile");
            //private Object mCookie;
            Object mCookieObj = XposedHelpers.getObjectField(dexFileObj, "mCookie");
            //private static native String[] getClassNameList(Object cookie);
            Class DexFileClass = XposedHelpers.findClass("dalvik.system.DexFile", classLoader);

            String[] classList = (String[]) XposedHelpers.callStaticMethod(DexFileClass, "getClassNameList", mCookieObj);
            for (String classname : classList) {
                XposedBridge.log(dexFileObj + "---" + classname);
            }
        }
        XposedBridge.log("end deal with classloader:" + classLoader);

    }


    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.f0208.lebo")) {

            getClassLoaderClassList(loadPackageParam.classLoader);

            XposedHelpers.findAndHookMethod(
                    "com.wrapper.proxyapplication.WrapperProxyApplication",
                    loadPackageParam.classLoader,
                    "onCreate",
                    new XC_MethodHook() {

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            super.afterHookedMethod(param);
                            ClassLoader loadedApkClassloader = getLoadedApkClassloader(param);
                            XposedBridge.log(loadedApkClassloader.toString());
                            XposedHelpers.findAndHookMethod(
                                    "com.zw.lebo.SplashView",
                                    loadedApkClassloader,
                                    "onCreate",
                                    Bundle.class,
                                    new XC_MethodHook() {

                                        @Override
                                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                            super.afterHookedMethod(param);
                                            XposedBridge.log("com.zw.lebo.MainActivity#onCreate");
                                            Toast.makeText((Context) param.thisObject, "a5right", Toast.LENGTH_SHORT).show();
                                        }
                                    });
                        }
                    });


        }
    }

}
