package com.serviceaudit.snk

const val version = "1.2"

data class Conf(var ANDROID_JAR: String = "", val CLASS_PATH: String = "", var ANDROID_VERSION: Int = 26,
                var JAR: String = "framework-lite.jar",
                val PSCOUT_PATH: String = "data/pscout.txt", val EDGE_MINER: String = "data/callbacks.txt",
                val DEBUG: Boolean = true, val LOG_LEV: String = "info")