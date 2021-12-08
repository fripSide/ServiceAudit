package com.serviceaudit.snk.analysis

import com.beust.klaxon.Klaxon
import com.serviceaudit.snk.CONFIG
import com.serviceaudit.snk.services.*
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.Results
import com.serviceaudit.snk.utils.Statistics
import com.serviceaudit.snk.validations.*
import soot.SootMethod

/*

 */
class VulnerabilitiesDetecting(private var serviceApi: ServiceApi) {
    val vulService = HashMap<String, VulService>()

    val resultsSet = HashSet<VulServiceApi>()

    val vulMethods = HashSet<SootMethod>()

    var validators = mutableListOf<IValidator>()

    init {
//        validators.add(PermissionApiValidator())
        validators.add(InconsistentParamsCheckingValidator())
        validators.add(IpcFloodValidator())
        validators.add(MethodStatusValidator())
        validators.add(IllegalParameterValidator())

        // keep validator by order
        validators.sortBy { it -> it.order }
    }

    // a service helper list for debug
    val mustContains = hashSetOf<String>("AppOpsManager", "BackupManager", "LegacyCameraDevice", "Toast", "NotificationManager", "FingerprintManager", "MediaBrowser",
            "BluetoothHealth", "NfcAdapter", "ConnectivityManager", "ClipboardManager", "AccessibilityManager", "LauncherApps", "DevicePolicyManager",
            "TvInputManager", "EthernetManager", "WifiManager", "LocationManager", "WallpaperManager")

    private fun checkContain(cls: List<String>) {
        val contains = HashMap<String, Boolean>()
        for (name in mustContains) {
            contains[name] = false
        }
        cls.forEach { helper ->
            for (name in mustContains) {
                if (helper.endsWith(name)) {
                    contains[name] = true
                }
//                if (helper.endsWith("EthernetManager")) {
//                    println("$helper")
//                }
            }
        }
        contains.forEach { t, u ->
            if (!u) {
                println("UnContains $t")
            }
        }
    }

    fun runValidators() {
        val infSet = HashSet<String>()
        val helperClsSet = HashSet<String>()
        val helperClass = serviceApi.serviceHelperSet

        helperClass.forEach { helper ->
            helperClsSet.add(helper.serviceHelper.name)
        }
//        checkContain(helperClsSet.toList())

        serviceApi.entryPointMethodSet.forEach l1@{ api ->
            var focus = "ConnectivityManager"
//            println(api.iInterface)
            infSet.add(api.helperClass!!.name)
            val helperName = api.helperClass!!.name
//            if (!helperName.endsWith(focus)) return@l1
            if (api.implMethod != null && !api.implClass!!.isInterface) {
                validateOneApi(api)
            }
//            println("Analysis focus class $helperName ${api.interfaceMtd}")
//            DebugTool.exitHere()
        }
    }

    private fun validateParamsChecking() {
        val infSet = HashSet<String>()
        val helperClsSet = HashSet<String>()
        val helperClass = serviceApi.serviceHelperSet

        helperClass.forEach { helper ->
            helperClsSet.add(helper.serviceHelper.name)
        }
//        checkContain(helperClsSet.toList())

        serviceApi.entryPointMethodSet.forEach l1@{ api ->
            var focus = "AudioManager"
//            println(api.iInterface)
            infSet.add(api.helperClass!!.name)
            val helperName = api.helperClass!!.name
//            if (!helperName.endsWith(focus)) return@l1
            validateOneApi(api)
//            println("Analysis focus class $helperName ${api.interfaceMtd}")
        }
        LogNow.debug("UnContain List:")
        checkContain(infSet.toList())
    }

    private fun validateIPCFlood() {
        validators = mutableListOf<IValidator>()
        validators.add(IpcFloodValidator())
        val helperClsSet = HashSet<String>()
        val helperClass = serviceApi.serviceHelperSet

        helperClass.forEach { helper ->
            helperClsSet.add(helper.serviceHelper.name)
        }
        checkContain(helperClsSet.toList())

        serviceApi.entryPointMethodSet.forEach l1@{ api ->
            var focus = "EthernetManager"
//            println(api.iInterface)
            val helperName = api.helperClass!!.name
            if (!helperName.endsWith(focus)) return@l1
            validateOneApi(api)
            println("Analysis focus class $helperName ${api.interfaceMtd}")
            DebugTool.exitHere()
        }
    }

    private fun validateOneApi(api: ServiceMethod) {
        val focus = "pendingRequestForNetwork"
//        if (api.interfaceMtd.name != focus) return
        var score = 0
        val failedValidator = mutableListOf<String>()
        for (validator in validators) {
            val s = validator.validateApi(api)
            if (s > 0)
                failedValidator.add(validator.tag)
            score += s
        }

        if (score > 0) {
            LogNow.info("Find vulnerable api: ${api.interfaceMtd} ${api.calledMethod}")
            val vul = api.asVulnerableApi()
            vul.failedValidatorList = failedValidator
            resultsSet.add(vul)
            addVulService(api, vul)
            LogNow.info("${api.callChain}")
        } else {
//            LogNow.info("No vul ${api.calledMethod} ${api.interfaceMtd}")
        }
    }

    var noImpl = 0
    private fun addVulService(api: ServiceMethod, vul: VulServiceApi) {
        val cls = api.iInterface!!.name
        val helperName = api.helperClass!!.name
        if (!vulService.containsKey(helperName)) {
            if (api.interfaceMtd == api.implMethod) noImpl++
            vulService[helperName] = VulService(cls, hashSetOf())
        }
        vulService[helperName]!!.vulApiList.add(vul)
    }

    fun saveResults() {
        val str = Klaxon().toJsonString(vulService)
        Results.saveResult(str, Results.VUL_API)
        shortReport()
    }

    // serious vulnerabilities for debug
    private fun shortReport() {
        if (!CONFIG.DEBUG) return
        val resContain = hashSetOf("Toast", "NotificationManager", "FingerprintManager", "MediaBrowser",
                "BluetoothHealth", "NfcAdapter", "ClipboardManager", "AccessibilityManager", "LauncherApps",
                "TvInputManager", "EthernetManager", "WifiManager", "LocationManager", "WallpaperManager")
        val nameSet = HashSet<String>()
        for (name in vulService.keys) {
            val shortList = name.split(".")
            val shortName = shortList.last()
            nameSet.add(shortName)
        }
        var cnt = 0
        for (result in resContain) {
            if (!nameSet.contains(result)) {
                LogNow.error("Missing Service: $result")
                cnt++
            }
        }
        LogNow.show("VulNUM: ${resultsSet.size} Cls: ${vulService.keys.size}")
        println("Total Missing: $cnt")
        LogNow.show("No Impl Methods(native code): $noImpl")
    }

}

fun runVulnerabilitiesAnalysis(api: ServiceApi) {
    if (api.entryPointMethodSet.isEmpty()) {
        api.associateServiceMethods()
    }


    val vulDetect = VulnerabilitiesDetecting(api)
    vulDetect.runValidators()
    vulDetect.saveResults()
    Statistics.vulResults = vulDetect.resultsSet
    Statistics.statClasses(api)
}
