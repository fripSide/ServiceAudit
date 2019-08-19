package com.serviceaudit.snk.services

import com.beust.klaxon.Klaxon
import com.serviceaudit.snk.analysis.ServiceMethodAnalysis
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.Results
import com.serviceaudit.snk.utils.SootTool
import org.jf.util.ExceptionWithContext.withContext
import soot.Scene
import soot.SootClass
import soot.SootMethod

// use to serialize result
// Stub -> Service Implement
data class ServiceImplResults(var serviceImplCls: String, var serviceName: String?, var iInterface: String?)

// Helper -> StubList(StubProxy)
data class ServiceHelperResults(var serviceHelper: String, var serviceName: String?, var isImportant: Boolean, var stubInterfaceList: List<String>)

data class ServiceStubClass(var frameworkStubs: List<String>, var sdkStubs: List<String>)

data class RawService(var implCls: List<String>, var helperCls: List<String>)

class ServiceHelperClass(val serviceHelper: SootClass) {
    var serviceName: String? = null // ServiceManager.getService
    val serviceImplSet = HashSet<SootClass>() // service impl class or Interface
    var isImportant = false // if can get by ServiceManager

    override fun hashCode(): Int {
        return serviceHelper.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other is ServiceHelperClass) {
            return serviceHelper == other.serviceHelper
        }
        return super.equals(other)
    }

    override fun toString(): String {
        return if (serviceName != null) "[$serviceName]$serviceHelper $serviceImplSet" else "[]$serviceHelper $serviceImplSet"
    }

    fun getImplList(): List<String> {
        val results = mutableListOf<String>()
        serviceImplSet.forEach{ impl ->
            results.add(impl.name)
        }
        return results
    }

}

class ServiceImplClass(val serviceImpl: SootClass) {
    var serviceName: String? = null
//    var serviceHelperSet = HashSet<SootClass>()
    var interfaceImplClass: SootClass? = null

    override fun hashCode(): Int {
        return serviceImpl.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other is ServiceHelperClass) {
            return serviceImpl == other.serviceHelper
        }
        return super.equals(other)
    }

    override fun toString(): String {
        return if (serviceName != null) "[$serviceName]$serviceImpl" else "[]$serviceImpl"
    }
}

/*
 ServiceHelper -> IInterface.Stub.Proxy
 IInterface.Stub -> ServiceImpl
 */
class ServiceApi {
//    key = packageName#className
    val serviceHelperSet = HashSet<ServiceHelperClass>()

    // need to check Stub
    val serviceImplSet = HashSet<ServiceImplClass>()

    // all stub class in framework
    val allStubInFramework = HashMap<String, SootClass>()
    val allStubInSdk = HashMap<String, SootClass>()

    //
    val entryPointMethodSet = HashSet<ServiceMethod>()

    companion object {
        fun loadFromFile(): ServiceApi? {
            val serviceApi = ServiceApi()

            return null
        }
    }

    fun getClassName(pkg: String): String {
        val params = pkg.split("#")
        if (params.isEmpty()) return ""
        return params.last()
    }

    fun addServiceStubsAndImplClass(implList: List<ServiceImplClass>, allStubFramework: List<SootClass>, allStubSdk: List<SootClass>) {
        serviceImplSet.addAll(implList)
        for (stub in allStubFramework) {
            allStubInFramework[stub.name] = stub
        }
        for (stub in allStubSdk) {
            allStubInSdk[stub.name] = stub
        }
    }

    fun getImplClsList(): List<ServiceImplClass> {
        return serviceImplSet.toList()
    }

    fun isStubUsedInSdk(sc: SootClass): Boolean {
        val name = sc.name
        return allStubInSdk.contains(name)
    }

    fun isStubUsedInFramework(sc: SootClass): Boolean {
        val name = sc.name
        return allStubInFramework.contains(name)
    }

    fun findStubByForServiceHelepr(helper: ServiceHelperClass) {

    }

    // save service implement class
    fun saveAllService() {
        val implSet = HashSet<String>()
        val helperSet = HashSet<String>()
        for (impl in serviceImplSet) {
            implSet.add(impl.serviceImpl.name)
//            for (helper in impl.serviceHelperSet) {
//                helperSet.add(helper.name)
//            }
        }

        for (helper in serviceHelperSet) {
            helperSet.add(helper.serviceHelper.name)
        }
        val rawService = RawService(implSet.toList(), helperSet.toList())
        val data = Klaxon().toJsonString(rawService)
        Results.saveResult(data, Results.ALL_SERVICE)
    }

    fun saveAllStubs() {
        val sdkStubList = ArrayList<String>()
        sdkStubList.addAll(allStubInSdk.keys)
        val frameworkStubs = ArrayList<String>()
        frameworkStubs.addAll(allStubInFramework.keys)
        val allStub = ServiceStubClass(frameworkStubs, sdkStubList)
        val data = Klaxon().toJsonString(allStub)
        Results.saveResult(data, Results.ALL_STUB)
    }

    fun saveServiceApi() {
        val helperResults = mutableListOf<ServiceHelperResults>()
        val implResults = mutableListOf<ServiceImplResults>()
        serviceHelperSet.forEach{ helper ->
            helperResults.add(ServiceHelperResults(helper.serviceHelper.name, helper.serviceName, helper.isImportant, helper.getImplList()))
        }
        serviceImplSet.forEach{ impl ->
            implResults.add(ServiceImplResults(impl.serviceImpl.name, impl.serviceName, impl.interfaceImplClass?.name))
        }
        val helperData = Klaxon().toJsonString(helperResults)
        val implData = Klaxon().toJsonString(implResults)
        Results.saveResult(helperData, Results.SERVICE_HELPER)
        Results.saveResult(implData, Results.SERVICE_IMPL)
    }

    // for each service interface, get the corresponding service impl method
    private fun getServiceImplForInterface(sm: ServiceMethod): SootClass? {
        var inf = sm.iInterface
        if (sm.implClass!!.isInterface) {
            inf = sm.implClass!!
        } else {
            return sm.implClass
        }
        var exist = false
        for (impl in serviceImplSet) {
            if (impl.interfaceImplClass == inf) {
                sm.implClass = impl.serviceImpl
                exist = true
            }
        }
        // resolve service impl via cha analysis
        if (!exist) {
//            LogNow.error("Need to perform cha analysis to get real impl: ${sm.implClass}")
//            DebugTool.exitHere()
        }
        return sm.implClass
    }

    // associate each service helper class with the service impl classes it have used
    // entryPointMethodSet keeps the aidl methods that can be exploit by third part app and need to be analyzed
    fun associateServiceMethods() {
        entryPointMethodSet.clear()
        serviceHelperSet.forEach l1@{ helper ->
//            val focus = "android.media.tv.TvInputManager"
//            if (helper.serviceHelper.name != focus) return@l1
            val methods = ServiceMethodAnalysis.resolveCallSetInHelper(helper)
            if (methods.isEmpty()) {
                LogNow.debug("No methods find in $helper.")
//                DebugTool.exitHere("$helper")
            }
//            LogNow.info("methods $methods")
            for (serviceMethod in methods) {
//                println("${serviceMethod.implClass} ${serviceMethod.implMethod}")
//                DebugTool.exitHere()
                val implCls = getServiceImplForInterface(serviceMethod)
                if (implCls != null) {
                    serviceMethod.implMethod = ServiceMethodAnalysis.resolveImplMethodForApi(implCls, serviceMethod.interfaceMtd)
//                    println("$implCls ${serviceMethod.implMethod}")
//                    DebugTool.exitHere()
                } else {
                    LogNow.info("Not In ${serviceMethod.interfaceMtd} ${serviceMethod.iInterface} (may implement in native code)")
                    DebugTool.exitHere()
                }
            }
            entryPointMethodSet.addAll(methods)
        }
        LogNow.info("Total num of focus methods: ${entryPointMethodSet.size}")
//        DebugTool.exitHere()
    }

}