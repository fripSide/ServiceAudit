package com.serviceaudit.snk.utils

import java.io.File
import java.lang.Exception

object Results {
    private val SAVE_DIR = "results"

    // all stub classes
    val ALL_STUB = "all_stub.json"
    // service helper and service impl
    val ALL_SERVICE = "all_service.json"

    val SERVICE_IMPL = "service_impl.json"

    val SERVICE_HELPER = "service_helper.json"

    val ASSOCIATE_METHODS = "associate_methods_mining.json"

    val VUL_API = "vulnerable_api.json"

    val REPORT = "report.txt"

    init {
        if (!File(SAVE_DIR).exists()) {
            File(SAVE_DIR).mkdir()
        }
    }

    fun saveResult(json: String, path: String) {
        try {
            File("$SAVE_DIR/$path").writeText(json)
        } catch (ex: Exception) {
            DebugTool.panic(ex)
        }
    }
}