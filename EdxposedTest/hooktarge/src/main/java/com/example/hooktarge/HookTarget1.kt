package com.example.hooktarge

class HookTarget1 constructor(private val str: String, val id: Long ) {

    constructor() :this("", 0)

    override fun toString(): String {
        return "HookTarget1(str='$str', id=$id)"
    }


}