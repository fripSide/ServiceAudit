package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.SootTool
import soot.SootClass
import soot.SootMethod
import soot.Value
import soot.jimple.*
import java.util.*

/*
Perform inter-procedure Point-to analysis to get the real type of a jimple value.
 */
class JimpleValueSolver {
    var checkAndGetCls: ((SootClass) -> Boolean)? = null

    val kAsBinder = "asBinder"

    private val workList = ArrayDeque<Value>()
    private var curCls: SootClass? = null
    private var curMtd: SootMethod? = null

    enum class JumpStatus {
        CONTINUE, // continue
        RETURN,  // return
        IGNORE, // do nothing
    }

    fun startToSearchValue(v: Value, mtd: SootMethod, deep: Int = 3) {
        DebugTool.assert(checkAndGetCls != null)
        checkAndGetCls!!
        curCls = mtd.declaringClass
        curMtd = mtd
        val body = mtd.retrieveActiveBody()
        // unit
        var lev = deep
        workList.clear()
        workList.push(v)
        while (workList.isNotEmpty()) {
            run l@{
                if (lev <= 0) return
                val curVal = SootTool.getExprValue(workList.poll())
//                println("resolveImplClassFromValue $curVal $interfaceMtd")
                lev--
                body.units.forEach { u ->
                    if (u is DefinitionStmt) {
                        val status = resolveValueFromDefinitionStmt(curVal, u)
                        if (status == JumpStatus.RETURN) return
                        else if (status == JumpStatus.CONTINUE) return@l
                    }
                }
            }
        }
//        println("resolveImplClassFromValue Failed $v $interfaceMtd")
//        DebugTool.exitHere()
    }

    private fun resolveValueFromDefinitionStmt(curVal: Value, u: DefinitionStmt): JumpStatus {
        val leftVal = SootTool.getExprValue(u.leftOpBox.value)
        if (leftVal == curVal && u.rightOpBox.value.toString() != "null") {
            val assign = u.rightOpBox.value
            var cls: SootClass? = null
//            println(assign)
            if (u.rightOpBox.value is InvokeExpr) { // asBinder()
                val invoke = u.rightOpBox.value as InvokeExpr
                val mtd = invoke.method
                if (mtd.name == kAsBinder) {
                    cls = curCls
                }
            }

            if (cls == null) {
                cls = SootTool.getClsFromValue(assign)
            }
//            println(cls)
            if (cls != null) {
                val find = checkAndGetCls!!(cls)
                if (!find) {
//                    println(SootTool.getExprValue(assign))
                    workList.add(assign)
//                    println("Add to worklist ${assign.javaClass}")
                    return JumpStatus.CONTINUE
                }
                return JumpStatus.RETURN
            }
        }
        return JumpStatus.IGNORE
    }

    private fun resolveValueFromIdentityStmt(curVal: Value, u: IdentityStmt): JumpStatus {
        return JumpStatus.IGNORE
    }
}