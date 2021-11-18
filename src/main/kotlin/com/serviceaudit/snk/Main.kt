package com.serviceaudit.snk

import com.beust.klaxon.Klaxon
import com.serviceaudit.snk.analysis.runNlpApproach
import com.serviceaudit.snk.analysis.runVulnerabilitiesAnalysis
import com.serviceaudit.snk.services.ServiceApi
import com.serviceaudit.snk.services.runIpcExtractor
import com.serviceaudit.snk.utils.ArgsParser
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import java.io.File
import java.lang.Exception


fun showDocument() {
    LogNow.show("\$ServiceAudit version$version\$")
}

fun runAnalysis() {
    when {
        ArgsParser.checkOption(ArgsParser.RUN_GEN) -> {
            runIpcExtractor(false)
        }
        ArgsParser.checkOption(ArgsParser.RUN_NLP) -> {
            // only run nlpApproach
            val serviceApi = runIpcExtractor()
            runNlpApproach(serviceApi)
        }
        else -> { // run all
            val serviceApi = runIpcExtractor()
//            runNlpApproach(serviceApi)
            runVulnerabilitiesAnalysis(serviceApi)
        }
    }
}

fun setAPILev(api: Int) {
    CONFIG.ANDROID_JAR = CONFIG.ANDROID_JAR + api + "\\" + CONFIG.JAR
    CONFIG.ANDROID_VERSION = api
    println("Run API version: " + CONFIG.ANDROID_JAR)
}

lateinit var CONFIG: Conf

open class Main {
    companion object {
        @JvmStatic fun main(args: Array<String>) {
            if (args.isEmpty()) {
                println("Usage: ServiceAudit.jar conf.json")
                return
            }
            val confPath = args[0]
            val txt = File(confPath)
            try {
                CONFIG = Klaxon().parse<Conf>(txt)!!
            } catch (ex: Exception) {
                CONFIG = Conf()
                DebugTool.fatalError("Failed to parse Conf file: $confPath!", ex)
            }
            var apiLev = CONFIG.ANDROID_VERSION
            if (args.size >= 2) {
                apiLev = args[1].toInt()
            }

            setAPILev(apiLev)
            LogNow.setLogLevel()
            showDocument()
            ArgsParser.parseArgs(args)
            runAnalysis()
        }
    }
}