package com.serviceaudit.snk.validations

import com.serviceaudit.snk.analysis.JimpleValueSolver
import com.serviceaudit.snk.analysis.ParamsAssociateAnalysis
import com.serviceaudit.snk.services.ServiceImplResolver
import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.jimple.InvokeExpr

class IpcFloodValidator(override val tag: String = "IpcFloodValidator", override val order: Int = 90): IValidator {

    // now use fixed score, these score can be train via ml methods
    val vulScore = 1

    private val kServiceImplInterface = "android.os.IInterface"

    /*
    Check if the ipc method has add stub classes to list as callback.
    If the parameter is extends from Binder, the IPC methods may suffer IPC flood attack.
     */
    override fun validateApi(call: ServiceMethod): Int {
        val mtd = call.callChain.last
//        println("${mtd.activeBody}")
        val invoke = getIpcMethodInvokeExpr(mtd, call.interfaceMtd)
        if (invoke != null) {
            var res = true
            res = res && checkParamIsBinder(invoke)
            res = res && checkPutInList(mtd, call.interfaceMtd)
            if (res) {
                call.vulTag = VulnerableTags.IpcFlood
                return vulScore
            }
        }
        return 0
    }

    private fun getIpcMethodInvokeExpr(sm: SootMethod, mtd: SootMethod): InvokeExpr? {
        val body = SootTool.tryGetMethodBody(sm)
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val expr = box.value as InvokeExpr
               if (expr.method == mtd) {
                   return expr
               }
            }
        }
        return null
    }

    private fun checkParamIsBinder(ink: InvokeExpr): Boolean {
        val mtd = ink.method
        mtd.parameterTypes.forEach { param ->
            val cls = param.toString()
            if (cls.startsWith("android")) {
                val sc = Scene.v().getSootClass(cls)
                if (isStubClass(sc)) {
                    return true
                }
            }
        }
//        ink.args.forEach { arg ->
//            val cls = JimpleValueSolver().startToSearchValue(arg, mtd)
//            DebugTool.exitHere("$arg $cls")
//        }
        return false
    }

    // if the Stub is saved in list.
    // remove from list will not cause to crash
    private fun checkPutInList(mtd: SootMethod, inf: SootMethod): Boolean {
        val callbackMethod = hashSetOf("callback", "listener")
        val excludeMethod = hashSetOf("remove", "unregister")
        val nameList = ParamsAssociateAnalysis.splitWord(inf.name)
//        println(nameList)
//        DebugTool.exitHere()
        var ret = false
        nameList.forEach { name ->
            if (callbackMethod.contains(name)) ret = true
            if (excludeMethod.contains(name)) return false
        }

        return ret
    }

    private fun isStubClass(sc: SootClass): Boolean {
        for (inf in sc.interfaces) {
            if (inf.name == kServiceImplInterface) {
                return true
            }
        }
        return false
    }
}