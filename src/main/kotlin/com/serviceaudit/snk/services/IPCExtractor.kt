package com.serviceaudit.snk.services

import com.serviceaudit.snk.CONFIG
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.*

/*
Extract Service helper classes and Service implement classes.
An Service helper class must have a member filed of Service implement Stub class which is inherit from

Is Not Service Helper Class:
1. android.view.LayoutInflater does not use a binder service
2.
 */
class IPCExtractor {
    // all service helper class are register in SystemServiceRegistry.java
    private val kServiceHelperRegisterCls: String = "android.app.SystemServiceRegistry"
    private val kServiceHelperRegisterFunc: String = "registerService"
    private val kServiceHelperCreateFunc = "createService"
    private val kGetServiceMtd = "<android.os.ServiceManager: android.os.IBinder getService(java.lang.String)>"

    // messenger should be exclude
    private val kExcludeServiceImpl: String = "android.os.IMessenger\$Stub"

//    private val kBinderCls = "android.os.Binder"
//
//    // service Impl identify api
    private val kServiceImplInterface = "android.os.IInterface"
//    private val kServiceImplRegister1 = "publishBinderService"
//    private val kServiceImplCls = "ServiceManager"
//    private val kServiceImplMtd = "addService"

    // check the integrity of the framework.jar file
    private val serviceKeywords: Array<String> = arrayOf("SystemServiceRegistry", "IInterface")
    private val focusCls = listOf("NotificationManagerService", "NotificationManager", "FingerprintManager", "Toast", "MediaBrowser", "BluetoothHealth", "NfcAdapter",
            "ClipboardManager", "AccessibilityManager", "LauncherApps", "TvInputManager", "EthernetManager", "WifiManager",
            "LocationManager", "WallpaperManager")
    private val warnTag = "The framework.jar is not the full version which need to isIn services.jar or do not support current Android SDK version. "

    val serviceApi = ServiceApi()

    fun runAnalysis() {
        var cls = CONFIG.ANDROID_JAR
//        cls = "E:\\PaperWork\\Android\\Jar\\cls"
        SootTool.initSootSimply(CONFIG.CLASS_PATH, cls)
        LogNow.show("Input Classes: $cls")
//        SootTool.initSootCallGraph(CONFIG.CLASS_PATH, cls, true)
//        SootTool.dumpClass("android.os.IBinder")
//        DebugTool.exitHere("dump class")

        checkIntegrityOfFrameworkJar()
        extractServiceImpl()
        extractServiceHelper()

//        SootTool.printSootClasses()
//        PackManager.v().writeOutput()
    }

    //
    private fun extractServiceImpl() {
        val implList = ServiceImplExtractor.getServiceImplClass()
        val allStubInFramework = ServiceImplExtractor.getAllStubClassInFramework()
        val allStubInSdk = ServiceImplExtractor.getAllStubClassInSdk()
        implList.forEach { impl ->
            ServiceImplExtractor.setStubInterfaceFromImpl(impl)
        }
        serviceApi.addServiceStubsAndImplClass(implList, allStubInFramework, allStubInSdk)
    }

    private fun extractServiceHelper() {
        val allList = ServiceHelperExtractor.getAllServiceHelperInSdk()
        val importantList = ServiceHelperExtractor.getImportantServiceHelper()
//        println(importantList.size) // 68
        serviceApi.serviceHelperSet.addAll(allList)
        importantList.forEach { helper ->
            helper.isImportant = true
            if (serviceApi.serviceHelperSet.contains(helper)) {
                val raw = serviceApi.serviceHelperSet.find { it == helper }
                if (raw != null) {
                    raw.isImportant = true
                    raw.serviceName = helper.serviceName
                }
            }
        }

        serviceApi.serviceHelperSet.addAll(importantList)
    }

    private fun analysisServiceImplUsage() {
        val implList = serviceApi.getImplClsList()
        implList.forEach { impl ->
            ServiceImplExtractor.setStubInterfaceFromImpl(impl)
            val clsList = extractImplUsageInSdk(impl)
            for (cls in clsList) {
//                impl.serviceHelperSet.add(cls)
            }
        }
    }

    private fun checkIntegrityOfFrameworkJar() {

    }

    private fun extractImplUsageInSdk(impl: ServiceImplClass): HashSet<SootClass> {
        val helperSet = HashSet<SootClass>()

        return helperSet
    }

    fun saveResults() {
        serviceApi.saveAllService()
        serviceApi.saveServiceApi()
//        serviceApi.saveNotUsedHelperCls()
        serviceApi.saveAllStubs()
    }
}

fun runIpcExtractor(loadCache: Boolean = true): ServiceApi {
    if (loadCache && CONFIG.DEBUG) {
        val serviceApi = ServiceApi.loadFromFile()
        if (serviceApi != null) return serviceApi
    }
    val ipc = IPCExtractor()
    ipc.runAnalysis()
    ipc.saveResults()
    return ipc.serviceApi
}