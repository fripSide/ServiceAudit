package com.serviceaudit.snk.services

import com.serviceaudit.snk.analysis.JimpleValueSolver
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.Value
import soot.jimple.AssignStmt
import soot.jimple.IdentityStmt
import soot.jimple.InvokeExpr
import java.lang.Exception
import java.util.*
import kotlin.collections.HashSet

/*
Extract the ServiceImpl from the register function.
Only the registered services impl can be used by third party apps via
IInterface.Stub.asInterface(SystemManager.getService()).
 */
object ServiceImplExtractor {
    private val kServiceImplPublishFunc = "publishBinderService"
    private val kServiceImplCls = "ServiceManager"
    private val kServiceImplAddMtdName = "addService"
    private val kServiceImplAddClsName = "android.os.ServiceManager"
    private val kSystemServiceBaseClass = "com.android.server.SystemService"

    private val kServiceImplInterface = "android.os.IInterface"
    private val kBinderCls = "android.os.Binder"
    private val kIBinderCls = "android.os.IBinder"

    private val kPkgFramework = "com.android"
    private val kPkgSdk = "android"

    private val implList = mutableListOf<ServiceImplClass>()
    // all stub classes, some of them are not registered as binder service

    fun getServiceImplClass(): List<ServiceImplClass> {
        implList.clear()
        searchServiceImplRegister()
        searchServiceImplPublish()
        val remainList = HashSet<ServiceImplClass>()
        implList.forEach { impl ->
            if (impl.serviceImpl != SootTool.OBJECT) {
//               println(impl.serviceImpl)
                remainList.add(impl)
            }
//            println("${impl.serviceName} ${impl.serviceImpl}")
        }
        LogNow.info("Total Registered Service: ${implList.size} Total Stub: ${remainList.size}")

        return remainList.toList()
    }


    fun getAllStubClassInFramework(): List<SootClass> {
        val stubList = searchServiceViaClsHierarchy(kPkgFramework)
        return stubList.toList()
    }

    fun getAllStubClassInSdk(): List<SootClass> {
        val stubList = searchServiceViaClsHierarchy(kPkgSdk)
        return stubList.toList()
    }

    private fun searchServiceViaClsHierarchy(pkgPrefix: String): HashSet<SootClass> {
        val stubSet = HashSet<SootClass>()
        val hir = Scene.v().activeHierarchy
        val inf = Scene.v().getSootClass(kServiceImplInterface)
        val clsList = hir.getImplementersOf(inf)
        val binder = Scene.v().getSootClass(kBinderCls)
        val binderSet = HashSet<SootClass>(hir.getSubclassesOf(binder))
        clsList.forEach { cls ->
            if (cls.name.startsWith(pkgPrefix)) {
                if (binderSet.contains(cls)) {
                    stubSet.add(cls)
                } else {
//                    println("Is not Binder service: $cls")
//                    println(hir.getSuperclassesOf(cls))
                }
            }
        }
//        DebugTool.exitHere()
        // all Stub: 333 738
        // is Binder: 257 738
        LogNow.info("In package: $pkgPrefix stub classes count: ${stubSet.size} Binder class count: ${binderSet.size}")
        return stubSet
    }

    /*
    ignore:
    <com.android.server.connectivity.PacManager$2: void onServiceConnected(android.content.ComponentName,android.os.IBinder)>
    <com.android.server.telecom.TelecomLoaderService$TelecomServiceConnection: void onServiceConnected(android.content.ComponentName,android.os.IBinder)>
     */
    private fun searchServiceImplRegister() {
        val clsList = findAddServiceList()
        for (cls in clsList) {
//            val focus = "com.android.server.am.BatteryStatsService"
//            if (cls.name != focus) continue
//			var nc = cls.methods
            resolveServiceImplRegister(cls)
        }
    }

    private fun searchServiceImplPublish() {
        val baseCls = Scene.v().getSootClass(kSystemServiceBaseClass)
        val subCls = SootTool.getSubClassList(baseCls)
        for (cls in subCls) {
            val sc = extractServicePublic(cls)
            if (sc != null) implList.add(sc)
        }
    }

    private fun resolveServiceImplRegister(cls: SootClass) {
//        println("resolveServiceImplRegister $cls")
        val mtdSet = filterMethodContainCalls(cls, kServiceImplAddMtdName, kServiceImplAddClsName)
        var mtdCnt = 0
		cls.methods.forEach{ mtd ->
            val body = SootTool.tryGetMethodBody(mtd)
            body?.useBoxes?.forEach { box ->
                if (box.value is InvokeExpr) {
                    val expr = box.value as InvokeExpr
                    val call = expr.method
                    val callMtdCls = call.declaringClass
                    if (call.name == kServiceImplAddMtdName && callMtdCls.name == kServiceImplAddClsName) {
                        val name = expr.args[0].toString()
//                        val implClass = resolveImplClassFromValue(expr.args[1], interfaceMtd)
						println(expr)
                        var implClass = resolveServiceImplInMethod(expr.args[1], mtd)
                        if (implClass != null) {
                            implClass.serviceName = name
                            implList.add(implClass)
                            mtdCnt++
                        } else {
                            implClass = ServiceImplClass(SootTool.OBJECT)
                            implClass.serviceName = name
                            implList.add(implClass)
//                            println("Not find $name $interfaceMtd")
                        }
//                        println("$name $cls")

                    }
                }
            }
        }
//        println("Mtd count: $mtdCnt")
    }

    private fun resolveValueForServiceInstance() {

    }

    private fun findAddServiceList(): List<SootClass> {
        val clsList = mutableListOf<SootClass>()
		val mtdList = mutableListOf<SootMethod>()
//		Scene.v().applicationClasses.forEach { cls ->
//			cls.methods.forEach { mtd ->
//				mtdList.add(mtd)
////				val body = SootTool.tryGetMethodBody(mtd)
//			}
//		}
//		for (mtd in mtdList) {
//			val body = SootTool.tryGetMethodBody(mtd)
//		}
		val focusCls = SootTool.filterClass("com.android")
		focusCls.forEach { cls ->
			if (SootTool.checkClsContainsMethodCall(cls, kServiceImplAddMtdName, kServiceImplAddClsName)) {
				clsList.add(cls)
//					DebugTool.exitHere(cls.name)
			}
        }
        return clsList
    }

    private fun extractServicePublic(cls: SootClass): ServiceImplClass? {
        if (cls.isInterface) return null
        var inv: InvokeExpr? = null
        var invMtd: SootMethod? = null
        run l1@{
            for (mtd in cls.methods) {
                val body = SootTool.tryGetMethodBody(mtd)
                body?.useBoxes?.forEach { box ->
                    if (box.value is InvokeExpr) {
                        val expr = box.value as InvokeExpr
                        if (expr.method.name == kServiceImplPublishFunc) {
                            inv = expr
                            invMtd = mtd
                            return@l1
                        }
                    }
                }
            }
        }

        if (inv != null) {
//            println("Find $inv in $cls")
            val name = inv!!.args[0].toString()
//            val implClass = resolveImplClassFromValue(inv!!.args[1], invMtd!!)
            var implClass = resolveServiceImplInMethod(inv!!.args[1], invMtd!!)
            if (implClass != null) {
                implClass.serviceName = name
                return implClass
            } else {
//                println("Not find: $name $inv")
                implClass = ServiceImplClass(SootTool.OBJECT)
                implClass.serviceName = name
                return implClass
            }
        }
        return null
    }

    private fun resolveServiceImplInMethod(v: Value, mtd: SootMethod): ServiceImplClass? {
        val solver = JimpleValueSolver()
        var impl: ServiceImplClass? = null
        solver.checkAndGetCls = { mService ->
            var ret = false
            if (mService.name != kIBinderCls) {
                impl = ServiceImplClass(mService)
                ret = true
            }
            ret
        }
        solver.startToSearchValue(v, mtd)
        return impl
    }

    /*
    Perform point-to analysis to find out the mService Stub
    1. Just assign once
    @ouf of date
     */
    private fun resolveImplClassFromValue(v: Value, mtd: SootMethod): ServiceImplClass? {
        var sc: ServiceImplClass? = null
        val body = mtd.retrieveActiveBody()
        // unit
//        println(body)
        var deep = 3
        val workList = ArrayDeque<Value>()
        workList.push(v)
        run l1@{
            while (workList.isNotEmpty()) {
                if (deep <= 0) return@l1
                run l2@ {
                    val curVal = SootTool.getExprValue(workList.poll())
                    deep--
//                    println("resolveImplClassFromValue $curVal $interfaceMtd $cls")
                    body.units.forEach { u ->
//                        println(u)
                        if (u is AssignStmt && u.leftOpBox.value == curVal && u.rightOpBox.value.toString() != "null") {
                            val leftVal = SootTool.getExprValue(u.leftOpBox.value)
                            if (leftVal == curVal && u.rightOpBox.value.toString() != "null") {
//                                println("rightOpBox ${u.rightOpBox.value} ${u.rightOpBox}")
                                val assign = u.rightOpBox.value
                                val mService = SootTool.getClsFromValue(assign)
                                if (mService != null) {
                                    if (mService.name != kIBinderCls) {
//                                        println("AssignStmt: Find real service $mService")
                                        sc = ServiceImplClass(mService)
                                        return@l1
                                    } else {
//                                        println("Need to Search deeper: $assign")
                                        workList.add(assign)
                                        return@l2
                                    }
                                }
                            }
                        } else if (u is IdentityStmt) {
                            val leftVal = SootTool.getExprValue(u.leftOpBox.value)
                            if (leftVal == curVal) {
                                val rightVal = u.rightOpBox.value
                                val mService = SootTool.getClsFromValue(rightVal)
                                if (mService != null && mService.name != kIBinderCls) {
//                                    println("IdentityStmt: Find real service $mService")
                                    sc = ServiceImplClass(mService)
                                    return@l1
                                }

                            }
                        }
                    }
                }

            }
        }

        // useBox
//        DebugTool.exitHere()
        if (sc == null) {
//            sc = ServiceImplClass(SootTool.OBJECT)
//            println("Not find: $interfaceMtd")
        }
        return sc
    }

    // Filter out the methods which isIn stmt to call another method by its callMtdCls and callMtdName.
    private fun filterMethodContainCalls(cls: SootClass, callMtdName: String, callMtdCls: String? = null): HashSet<SootMethod> {
        val methods = HashSet<SootMethod>()
        for (mtd in cls.methods) {
            val body = SootTool.tryGetMethodBody(mtd)
            body?.useBoxes?.forEach { box ->
                if (box.value is InvokeExpr) {
                    val expr = box.value as InvokeExpr
                    try {
                        val curMtd = expr.method
                        if (curMtd.name == callMtdName) {
                            if (callMtdCls != null) {
                                val sc = curMtd.declaringClass
                                if (sc.name == callMtdCls)
                                    methods.add(mtd)
                            } else {
                                methods.add(mtd)
                            }
                        }
                    } catch (ex: Exception) {
                        LogNow.debug("Failed to get method of $expr")
                    }
                }
            }
        }
        return methods
    }

    private fun containsAddServiceMethodCall(cls: SootClass): Boolean {
        for (mtd in cls.methods) {
            val body = SootTool.tryGetMethodBody(mtd)
            body?.useBoxes?.forEach { box ->
                if (box.value is InvokeExpr) {
                    val expr = box.value as InvokeExpr
                    try {
                        val curMtd = expr.method
                        val sc = curMtd.declaringClass
                        if (sc.name == kServiceImplAddClsName && curMtd.name == kServiceImplAddMtdName) {
//                            println(curMtd.signature)
                            return true
                        }
                    } catch (ex: Exception) { // native method
                        LogNow.debug("Failed to get method of $expr")
                    }
                }
            }
        }
        return false
    }

    // find out IInterface for ServiceImpl class
    fun setStubInterfaceFromImpl(impl: ServiceImplClass) {
        val cls  = impl.serviceImpl
        impl.interfaceImplClass = SootTool.getInfForImpl(cls)
        if (cls.isInterface) {
            impl.interfaceImplClass = cls
            return
        }
        val hir = Scene.v().activeHierarchy
        val supList = hir.getSuperclassesOf(cls)
        supList.forEach { sup -> // stub
            val infList = sup.interfaces
//            println(infList)
            for (inf in infList) {
                for (supInf in inf.interfaces) {
                    if (supInf.name == kServiceImplInterface) {
                        impl.interfaceImplClass = inf
//                        println("Find sup: $sup")
                        return@forEach
                    }
                }
            }
        }

//        SootTool.dumpClass(cls)
//        DebugTool.exitHere()
    }

    /*
    To find out the
    com.android.pacprocessor.PacService
     */
    private fun manualExtract() {

    }
}