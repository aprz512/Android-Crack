package com.example.demo1;

import android.util.Log;

public class FridaDemo1 {

    private static final String secret = "secret";
    private StringBuilder builder = new StringBuilder();

    public static String secret2() {
        return secret;
    }

    String func(String x) {
        String s = x.toLowerCase();
        builder.append(s);
        return s;
    }

    int func(int x, int y) {
        builder.append(x + y);
        return x + y;
    }

    String secret() {
        return builder.toString();
    }

    static int nice() {
        return 333;
    }

}
