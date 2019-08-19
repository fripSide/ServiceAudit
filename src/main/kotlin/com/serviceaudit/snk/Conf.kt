package com.serviceaudit.snk

const val version = "1.0"

data class Conf(val ANDROID_JAR: String = "", val CLASS_PATH: String = "",
                val PSCOUT_PATH: String = "data/pscout.txt", val EDGE_MINER: String = "data/callbacks.txt",
                val DEBUG: Boolean = true, val LOG_LEV: String = "info")