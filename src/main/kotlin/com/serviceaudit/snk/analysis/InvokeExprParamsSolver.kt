package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.services.MethodDesc
import com.serviceaudit.snk.services.MethodParams
import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod
import soot.Value
import soot.jimple.DefinitionStmt
import soot.jimple.InvokeExpr
import soot.jimple.internal.JimpleLocal

/*
perform point-to analysis to get the method name and params name
 */
class InvokeExprParamsSolver {

    companion object {
        fun extractMethodDescInServiceMethod(call: ServiceMethod) {

        }

        fun extractParamsInSootMethod(mtd: SootMethod): List<MethodDesc> {
            return InvokeExprParamsSolver().parse(mtd)
        }
    }

    private val excludingFuncs = listOf("<init>")

    fun parse(mtd: SootMethod): List<MethodDesc> {
        val body = SootTool.tryGetMethodBody(mtd)
//        println("$interfaceMtd")
//        println("$body")
        val mtdDescList = mutableListOf<MethodDesc>()
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val ink = box.value as InvokeExpr
                val mtdName = ink.method.name
                if (!excludingFuncs.contains(mtdName)) {
                    val methodDesc = resolveInvokeInMtd(mtd, ink)
                    mtdDescList.add(methodDesc)
                }
            }
//            println("$box ${box.javaClass} ${box.value}")
        }
        return mtdDescList
    }

    /*
    If the raw name of a local value cannot be retrieved, we should use the name of source method instead.
    The result of JimpleLocal should be a function name or a field name.
    eg. str = this.mContext.getOpPackageName();
    Use getOpPackageName as local value name.
     */
    private fun resolveInvokeInMtd(mtd: SootMethod, ink: InvokeExpr): MethodDesc {
        val mtdName = ink.method.name
        val mtdDesc = MethodDesc(mtdName, null)
        val paramsSet = HashSet<MethodParams>()
        ink.args.forEach { arg ->
            if (arg is JimpleLocal) {
                paramsSet.addAll(retrieveRawTypeForLocal(arg, mtd))
            }
        }

        mtdDesc.params = paramsSet.toList()
//        println("Invoke $mtdName $ink $mtdDesc")
        return mtdDesc
    }

    // local value is init in current function
    private fun retrieveRawTypeForLocal(v: Value, mtd: SootMethod): HashSet<MethodParams> {
        val paramsSet = HashSet<MethodParams>()
        val body = mtd.activeBody
        body.units.forEach { u ->
            if (u is DefinitionStmt) {
                val leftVal = u.leftOpBox.value
                val rightVal = u.rightOpBox.value
                if (v == leftVal) {
                    val param = SootTool.getRightValueParamName(rightVal)
                    if (param.paramName != "") {
                        paramsSet.add(param)
                    }
//                    println("${leftVal.javaClass} left:$leftVal right:$rt ${rightVal.javaClass} $u")
                }
            }
        }
        return paramsSet
    }
}