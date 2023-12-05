package com.example.hooktarge;

import android.util.Log;

public class HookTarget3 {

    public void test() {
        String s = test1();
        Log.e("HookTarget3", s);
        String s1 = test2();
        Log.e("HookTarget3", s1);
        test3();
        test4();
    }

    class AbsClass {
        private String test1() {
            return "test1";
        }

        public int run() {
            return 1;
        }
    }

    private String test1() {
        return "test1";
    }

    private static String test2() {
        return "test2";
    }

    private void test3() {
        AbsClass absClass = new AbsClass();
        Log.e("HookTarget3", absClass.test1());
    }

    private void test4() {
        AbsClass absClass = new AbsClass() {
            @Override
            public int run() {
                return 2;
            }
        };

        int run = absClass.run();
        Log.e("HookTarget3", run + "");
    }

}


