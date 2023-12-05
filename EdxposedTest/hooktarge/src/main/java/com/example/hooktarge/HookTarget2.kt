package com.example.hooktarge

class HookTarget2 {

    private var str: String = "hello"

    companion object {
        @JvmStatic
        private val id: Int = 10
    }

    override fun toString(): String {
        return "HookTarget2(str='$str')"
    }


}