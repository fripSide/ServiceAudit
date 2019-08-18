package com.serviceaudit.snk.utils

import com.serviceaudit.snk.CONFIG

enum class LogLev(override val value: Int): HasValue<Int> {
    Verbose(0),
    Debug(1),
    Info(2),
    Warn(3),
    Error(4),
    Mute(5);

    companion object : EnumConverter<Int, LogLev>(buildValueMap())
}

class LogNow {
    companion object {
        var logLev = LogLev.Info

        fun setLogLevel() {
            val levels = listOf("verbose", "debug", "info", "warn", "error", "mute")
            val lv = levels.indexOf(CONFIG.LOG_LEV)
            logLev = LogLev.fromValue(lv, LogLev.Info)
            LogNow.debug("Current LogLev: $logLev")
        }

        fun debug(msg: String) {
            if (logLev <= LogLev.Debug) {
                val li = DebugTool.getLineInfo(1)
                println("[Debug] $msg $li")
            }
        }

        fun info(msg: String) {
            if (logLev <= LogLev.Info) {
                val li = DebugTool.getLineInfo(1)
                println("[Info] $msg $li")
            }

        }

        fun warn(msg: String) {
            if (logLev <= LogLev.Warn) {
                val li = DebugTool.getLineInfo(1)
                println("[Warning] $msg $li")
            }
        }

        fun error(msg: String) {
            if (logLev <= LogLev.Error) {
                val li = DebugTool.getLineInfo(1)
                System.err.println("[Error] $msg $li")
            }
        }

        // just print
        fun show(msg: String) {
            println(msg)
        }
    }
}