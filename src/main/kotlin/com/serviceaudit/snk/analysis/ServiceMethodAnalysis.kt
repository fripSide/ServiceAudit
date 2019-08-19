package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.services.ServiceApi
import com.serviceaudit.snk.services.ServiceHelperClass
import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.SootClass
import soot.SootMethod
import kotlin.collections.HashMap
import kotlin.collections.HashSet

/*
Associate method in interface with usage classes or implement classes.
 */
object ServiceMethodAnalysis {

    val mtdToImpl = HashMap<SootMethod, SootClass>()

    fun resolveMethods(api: ServiceApi) {

    }

    fun resolveCallSetInHelper(cls: ServiceHelperClass): HashSet<ServiceMethod> {
        mtdToImpl.clear()
        val methodInInf = getFocusMethodsForHelper(cls)
//        println("target methods: $methodInInf")
        val callSet = HashSet<ServiceMethod>()
//        println(methodInInf)
        val helper = cls.serviceHelper
        val publicApi = getHelperApi(helper)
        publicApi.forEach { mtd ->
           val callPath = CallGraphBuilder(mtd, methodInInf).build()
            callSet.addAll(callPath)
        }
        if (callSet.isEmpty()) {
            LogNow.debug("Need to improve precise: ${cls.serviceHelper.name} $callSet")
        }
        // get method desc
        callSet.forEach { call ->
            if (mtdToImpl[call.interfaceMtd] != null) {
                call.implClass = mtdToImpl[call.interfaceMtd]
            } else {
                LogNow.error("Do not use service helper")
            }
            call.implMethod = getImplMethod(call.interfaceMtd, call.implClass!!)
//            println(mtdToImpl[call.interfaceMtd])
//            println(call.interfaceMtd)
//            println(call.implClass)
//            DebugTool.exitHere()
            for (callMtd in call.callChain) {
                if (!call.mtdDesc.contains(callMtd)) {
                    call.mtdDesc[callMtd] = HashSet()
                }
                call.mtdDesc[callMtd]!!.addAll(InvokeExprParamsSolver.extractParamsInSootMethod(callMtd))
            }
        }
        return callSet
    }

    fun  resolveImplMethodForApi(cls: SootClass, targetMethod: SootMethod): SootMethod? {
        val focusApi = getFocusMethodsForImpl(cls)
        focusApi.forEach { mtd ->
            if (mtd.name == targetMethod.name) {
//                println("Focus $mtd")
               return mtd
            }
        }
        return null
    }

    fun getImplicitTargets(mtd: SootMethod): List<SootMethod> {
        // change IPC call to real stub method

        //
        return ImplicitControFlowResolver.checkAndResolveImplicitCall(mtd)
    }


    private fun getFocusMethodsForHelper(cls: ServiceHelperClass): HashSet<SootMethod> {
        val mtdSet = HashSet<SootMethod>()
        for (infImpl in cls.serviceImplSet) {
            var inf = infImpl
            if (!infImpl.isInterface) {
                inf = SootTool.getInfForImpl(infImpl)
            }
            inf.methods.forEach { mtd ->
                if (mtd.isAbstract && mtd.isPublic) {
                    mtdSet.add(mtd)
                    mtdToImpl[mtd] = infImpl
                }
            }
        }
        return mtdSet
    }

    private fun getFocusMethodsForImpl(cls: SootClass): HashSet<SootMethod> {
        val mtdSet = HashSet<SootMethod>()
        cls.methods?.forEach {
            if (it.isPublic) {
                mtdSet.add(it)
            }
        }
        return mtdSet
    }

    private fun getImplMethod(infMtd: SootMethod, impCls: SootClass): SootMethod {
        impCls.methods.forEach { mtd ->
            if (mtd.name == infMtd.name) return mtd
        }
        return infMtd
    }

    private fun getHelperApi(helper: SootClass): HashSet<SootMethod> {
        val mtdSet = HashSet<SootMethod>()
        for (mtd in helper.methods) {
            val body = SootTool.tryGetMethodBody(mtd)
            if (mtd.isConcrete && body != null) {
                mtdSet.add(mtd)
            }
        }
        return mtdSet
    }
}