package com.serviceaudit.snk.utils

import com.serviceaudit.snk.CONFIG

object DebugTool {
    private val DEBUG = CONFIG.DEBUG

    fun getLineInfo(outLev: Int = 0): String { // get first level of call stack
        val stacks = Throwable().stackTrace
        val ste = stacks[2 + outLev]
        return "[Source - Package:" + ste.className + ".java:" + ste.lineNumber + " Method:" + ste.methodName + "]"
    }

    fun assert(res: Boolean) {
        if (!res) {
            println("============================Assert Exit=========================")
            println("Go to debug and fix the bug here: ${getLineInfo(0)}")
            println("=============================End Assert ========================")
            exitOrThrow(RuntimeException("Assert Failed!"))
        }
    }

    fun panic(msg: String = "Panic for bug!") {
        println("============================Panic Exit=========================")
        println("Go to debug and fix the bug here: ${getLineInfo()}")
        println("=============================End Panic ========================")
        exitOrThrow(RuntimeException(msg))
    }

    fun panic(ex: Exception) {
        println("============================Panic Exit=========================")
        println("Go to debug and fix the bug here: ${getLineInfo(1)}")
        println("=============================End Panic ========================")
        exitOrThrow(ex)
    }

    fun fatalError(msg: String = "", ex: java.lang.Exception? = null) {
        ex?.printStackTrace()
        println("EXIT with fatal error!! $msg")
        System.exit(-1)
    }

    private fun exitOrThrow(ex: Exception) {
        if (DEBUG) {
            println("DEBUG EXIT! ${ex.message}")
            System.exit(-1)
        } else {
            throw RuntimeException(ex)
        }
    }

    fun exitHere(info: String = "") {
        if (info.isNotEmpty()) {
            println("Exit Message: $info")
        }
        println("*****************Debug Exit Here*****************")
        println(getLineInfo(1))
        System.exit(-1)
    }
}