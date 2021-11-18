package com.serviceaudit.snk.utils

object ArgsParser {

    const val RUN_ALL = "run_all" // default
    const val RUN_GEN = "run_gen"
    const val RUN_NLP = "run_nlp"

    data class BoolOption(var desc: String, var open: Boolean)

    val options = HashMap<String, BoolOption>()

    init {
        val runNlp = BoolOption("run nlp approach only", false)
        val runGen = BoolOption("run helper generation approach only", false)
        val allMode = BoolOption("run all the approaches (default)", true)
        options["-nlp"] = runNlp
        options["-gen"] = runGen
        options["-all"] = allMode
    }

    fun parseArgs(args: Array<String>) {
        if (args.size < 2 || args.size > 3) {
//            printHelp()
            LogNow.show("Start to run all of the approaches...")
            return
        }
        val opt = args[1]
        for (key in options.keys) {
            if (opt == key) {
                val action = options[key]!!
                action.open = true
                break
            }
        }
    }

    fun printHelp() {
        LogNow.show("Usage: ServiceAudit.jar conf api -mode")
        options.forEach{ opt ->
            LogNow.show("\t${opt.key} ${opt.value.desc}")
        }
    }

    fun checkOption(name: String): Boolean {
        if (options.containsKey(name)) {
            return options[name]!!.open
        }
        return false
    }
}