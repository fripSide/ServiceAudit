package com.serviceaudit.snk.services

import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.jimple.ClassConstant
import soot.jimple.InvokeExpr
import java.lang.Exception

/*
Get Stub class which is inherit from IInterface and Binder.
This IInterface class is the real api which can be used by third party classes.
1. check apis between helper API and Stub.Proxy API (SDK layer) (find out all IProxy in android package)
2. check apis between Stub and Service Implement class.
 */
object ServiceHelperExtractor {

    private val kServiceHelperRegisterCls: String = "android.app.SystemServiceRegistry"
    private val kServiceHelperRegisterFunc: String = "registerService"
    private val kServiceHelperCreateFunc = "createService"
    private val kGetServiceMtd = "<android.os.ServiceManager: android.os.IBinder getService(java.lang.String)>"

    // messenger should be exclude
    private val kExcludeServiceImpl: String = "android.os.IMessenger\$Stub"
    private val kExcludeServiceImplSet = hashSetOf("android.os.IMessenger", "android.content.IContentProvider")

    // check the integrity of the framework.jar file
    private val serviceKeywords: Array<String> = arrayOf("SystemServiceRegistry", "IInterface")
    private val warnTag = "The framework.jar is not the full version which need to isIn services.jar or do not support current Android SDK version. "

    /*
        Search every public concrete class and try to get IInterface
     */
    fun getAllServiceHelperInSdk(): List<ServiceHelperClass> {
        val apiSet = HashSet<ServiceHelperClass>()
        Scene.v().applicationClasses.forEach l1@{ cls ->
            if (cls.isPublic and cls.isConcrete && cls.name.startsWith("android")) {
                val scList = ServiceImplResolver.searchImplInterface(cls)
                if (scList.isNotEmpty()) {
                    val api = ServiceHelperClass(cls)
                    val pkg = api.serviceHelper
//                    val focusCls = "android.net.EthernetManager"
//                    if (pkg.name != focusCls) return@l1
                    scList.forEach { sc ->
                        api.serviceImplSet.add(sc)
                    }
//                    DebugTool.exitHere("extract one cls $api $scList")
                    apiSet.add(api)
//                    println("Find $cls $scList")
                }
            }
        }
//        println("Total Helper Size: ${apiSet.size}")
        return apiSet.toList()
    }

    fun getImportantServiceHelper(): List<ServiceHelperClass> {
        val cls = Scene.v().getSootClass(kServiceHelperRegisterCls)
        var registerMtd: SootMethod? = null
        run l1@{
            cls.methods.forEach { mtd ->
                if (SootTool.isInitMethod(mtd)) {
                    registerMtd = mtd
                    return@l1 //break
                }
            }
        }
        val body = registerMtd?.retrieveActiveBody()
        if (body == null) {
            DebugTool.panic(Exception("ServiceRegisterClass Should Have cinit! $warnTag"))
        }

        val helperApiList = HashSet<ServiceHelperClass>()
        var helperCnt = 0
        var implCnt = 0
        for (useBox in body!!.useBoxes) {
            if (useBox.value is InvokeExpr) {
                val api = resolveServiceHelperRegister(useBox.value as InvokeExpr)
                if (api != null) {
                    val pkg = api.serviceHelper
//                    println(pkg)
//                    val focusCls = "android.app.NotificationManager"
//                    if (pkg.name != focusCls) continue
                    helperCnt++
                    if (findServiceImplStubUsage(api)) implCnt++
                    else LogNow.debug("$pkg Service impl for helper does not find!")
//                    DebugTool.exitHere("extract one cls $api")
                    helperApiList.add(api)
                }
            }
        }
//        LogNow.info("Service Helper Class Total Num: $helperCnt Impl: $implCnt")
        return helperApiList.toList()
    }

    // find the name of service Helper and save to ServiceApi
    // Find IInterface.Stub.asInterface() -> Service Impl
    /*We should exclude these IBinder stub which are not registered in SystemManager
        as all the vulnerable api is launched as IAppOpsService.Stub.asInterface(ServiceManager.getService("appops")).
      The Binder object should get by service name.
      A service helper class may use various service impl class.
    */
    private fun findServiceImplStubUsage(api: ServiceHelperClass): Boolean {
        val helperCls = api.serviceHelper
        val implList = ServiceImplResolver.searchServiceImplClass(helperCls)
        if (implList.isEmpty() && api.serviceName == null) return false
//        println("Helper: $helperCls $implList")
        implList.forEach{ implCls ->
            if (implCls.name != kExcludeServiceImpl) {
//                println(" Impl: $implCls")
                api.serviceImplSet.add(implCls)
            }
        }

        return true
    }

    private fun extractServiceApiFromRegisterBlock(cls: SootClass): ServiceHelperClass? {
        // find
        var createMtd: SootMethod? = null
        for (mtd in cls.methods) {
            if (mtd.name == kServiceHelperCreateFunc && mtd.returnType.toString() != SootTool.OBJECT.name) {
                createMtd = mtd
                break
            }
        }
        createMtd = createMtd!!
        val ret = SootTool.getReturnFromMethod(createMtd, true)
        val helper = SootTool.getClsFromValue(ret!!)
        val api = ServiceHelperClass(helper!!)
        api.serviceName = extractBinderTag(createMtd)
        return api
    }

    private fun resolveServiceHelperRegister(invoke: InvokeExpr): ServiceHelperClass? {
        val funcName = invoke.method.name
        // is service helper register block
        if (funcName == kServiceHelperRegisterFunc && invoke.argCount > 2 && invoke.args[1] is ClassConstant) {
            val blockCls = SootTool.getClsFromValue(invoke.args[2])
            val api = extractServiceApiFromRegisterBlock(blockCls!!)
            DebugTool.assert(api != null)
            if (api == null) {
                val helper = getServiceHelperRegisterName(invoke)
                if (helper != null)
                    return ServiceHelperClass(helper)
            }
            return api
        }
        return null
    }

    private fun extractBinderTag(mtd: SootMethod): String? {
        val b = mtd.retrieveActiveBody()
        for (box in b.useBoxes) {
            if (box.value is InvokeExpr) {
                val inv = box.value as InvokeExpr
                if (inv.method.toString() == kGetServiceMtd) {
//                    println(inv.args[0].toString())
                    return inv.args[0].toString()
                }
            }
        }
        return null
    }

    // get return type of registerService
    private fun getServiceHelperRegisterName(invoke: InvokeExpr) : SootClass? {
        val funcName = invoke.method.name
        if (funcName == kServiceHelperRegisterFunc && invoke.argCount > 1 && invoke.args[1] is ClassConstant) {
            val call = invoke.args[2]
            val cls = SootTool.getClsFromValue(call)
            var sc  = SootTool.getClsFromValue(invoke.args[1])
            cls?.methods?.forEach { mtd->
                if (mtd.name == kServiceHelperCreateFunc && mtd.returnType.toString() != SootTool.OBJECT.name) {
                    val ret = SootTool.getReturnFromMethod(mtd, true)
                    //                    println("Value : ${SootTool.getClsFromValue(ret!!)}")
                    sc = SootTool.getClsFromValue(ret!!)
                    if (sc != null) {
                        return sc
                    } else {
                        DebugTool.panic("null sc $ret $mtd")
//                        println(interfaceMtd.retrieveActiveBody().units)
//                        interfaceMtd.retrieveActiveBody().units.forEach { expr ->
//                            if (expr is ReturnStmt) {
//                                println("$expr Find ${expr.op.type}")
//                                println(expr.op.type == NullType.v())
//                                if (expr.op.type is RefType) {
//                                    println("refType")
//                                }
//                            }
//                        }
                    }
                }
            }
            return sc
        }
        return null
    }
}