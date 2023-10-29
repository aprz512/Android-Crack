package com.example.demo2;

import android.util.Log;

import java.util.UUID;

public class SimpleBook implements IBook {

    @Override
    public String id() {
        return UUID.randomUUID().toString();
    }

    @Override
    public int size() {
        return 100;
    }

    @Override
    public boolean test(int input) {
        Log.e("SimpleBook", "input = " + input);
        return false;
    }

}
