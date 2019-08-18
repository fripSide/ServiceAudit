package com.serviceaudit.snk.validations

import com.serviceaudit.snk.analysis.*
import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.SootTool
import soot.Local
import soot.SootMethod
import soot.jimple.AssignStmt
import soot.jimple.InvokeExpr
import soot.jimple.Stmt
import soot.toolkits.graph.ExceptionalUnitGraph
import soot.toolkits.graph.MHGDominatorsFinder
import soot.tagkit.LineNumberTag
import kotlin.collections.HashSet


class IllegalParameterValidator(override val tag: String = "IllegalParameterValidator", override val order: Int = 110): IValidator {

    // now use fixed score, these score can be train via ml methods
    val vulScore = 1

    val exceptionSet = hashSetOf("BadParcelableException", "IllegalArgumentException", "NullPointerException",
            "SecurityException", "NetworkOnMainThreadException", "NetworkOnMainThreadException")


    val fakeStatusExceptions = hashSetOf("java.lang.IllegalStateException")

    /*
     */
    override fun validateApi(call: ServiceMethod): Int {

        if (checkIllegalParametersInHelper(call)) {
            if (!checkParamsProtectedInImpl(call)) {
                call.vulTag = VulnerableTags.IllegalParam
                return vulScore
            }
        }
        return 0
    }

    fun extractExceptionThrowsInMtd(sm: SootMethod): HashSet<String> {
        val ret = HashSet<String>()
        val body = SootTool.tryGetMethodBody(sm)
        body?.traps!!.forEach { trap ->
//            println(trap)
            val shortName = trap.exception.shortJavaStyleName
            if (exceptionSet.contains(shortName)) {
                ret.add(trap.exception.shortJavaStyleName)
            }
        }
//        println(body)
        body.locals.forEach { local ->
            val ts = local.type.toString()
            if (ts.endsWith("Exception")) {
                val shortNameList = ts.split(".")
                val short = shortNameList.last()
                if (exceptionSet.contains(short)) {
                    ret.add(short)
                }
            }
//            println(local.type)
//            println(local.name)
        }
//        println(body.locals)
//        body?.useAndDefBoxes!!.forEach { box ->
//            println("$box ${box.value} ${box.value.javaClass}")
//            println(SootTool.getClsFromValue(box.value))
//        }
        return ret
    }

    private fun extractExceptionBeforeInvokeMtd(sm: SootMethod, inv: Stmt) : HashSet<String> {
        val ret = HashSet<String>()
        val body = SootTool.tryGetMethodBody(sm)

        val exceptGraph = ExceptionalUnitGraph(body)

        // if exception node dominate invoke node
        val analysis = MHGDominatorsFinder(ExceptionalUnitGraph(body))
//        println(exceptGraph)
        val domis = analysis.getDominators(inv)

        exceptGraph.forEach { u ->
            println(u)
            if (u.branches()) {
                val t = exceptGraph.getSuccsOf(u)
                t.forEach { ui ->
                    println(ui)
                }
                if (t is Stmt) {
                    val s = t as Stmt
                    if (s.containsInvokeExpr()) {
                        val ink = s.invokeExpr

                        //if (ink.method.name == )
                    }
                }
            }
        }
        DebugTool.exitHere()

        body?.locals?.forEach { local ->
//            val tag = local.getTag("LineNumberTag") as LineNumberTag
            local.useBoxes.forEach { box ->
                val li = box.getTag("LineNumberTag") as LineNumberTag
                println("line $li")
            }
//            val ts = local.type.toString()
//            if (ts.endsWith("Exception")) {
//                val shortNameList = ts.split(".")
//                val short = shortNameList.last()
//                if (fakeStatusExceptions.contains(short)) {
//                    ret.add(short)
//                }
//            }
        }
        return ret
    }

    private fun extractExceptionBeforeInvoke(sm: SootMethod, invoke: SootMethod) : HashSet<String> {
        val ret = HashSet<String>()
        val body = SootTool.tryGetMethodBody(sm)
        val inv = SootTool.getInvokeUnitInMethod(sm, invoke)
        body?.units?.forEach { u ->
            val s = getExceptionNameFromUnit(u)
//            println("${u.javaClass} $u $s")
            if (s != null && fakeStatusExceptions.contains(s)) {
//                println("Find Exception $u")
                ret.add(s)
            }
            if (u == inv) {
//                println("Find Invoke")
                return ret
            }
        }

//        println(body)
        return ret
    }

    // only the checked last level method
    private fun checkLastLevelFakeStatus(call: ServiceMethod): Boolean {
        val mtd = call.callChain.last
        val exceptions = extractExceptionBeforeInvoke(mtd, call.interfaceMtd)

        var checkStatus = false
        exceptions.forEach { exp ->
            if (fakeStatusExceptions.contains(exp)) {
                checkStatus = true
            }
        }
        if (checkStatus && !filterApiByPermission(call.implMethod!!)) {
            return true
        }
        return false
    }

    // service interface method should have args
    private fun infHasArgs(sm: SootMethod): Boolean {
//        println(sm)
//        println(sm.parameterCount)
        return sm.parameterCount > 0
    }

    private fun checkIllegalParams(call: ServiceMethod): Boolean {
        val inf = call.interfaceMtd
        if (!infHasArgs(inf)) return false

        val allException = HashSet<String>()
        call.callChain.forEach { mtd ->
            //            println(mtd.activeBody)
            allException.addAll(extractExceptionThrowsInMtd(mtd))
        }
        if (allException.isNotEmpty()) {
            if (call.exceptionBypass == null) {
                call.exceptionBypass = mutableListOf()
            }
            call.exceptionBypass!!.addAll(allException)
            return true
        }
        return false
    }

    // check if impl API contains permission checking invokes
    private fun filterApiByPermission(sm: SootMethod): Boolean {
        val customPermissionChecking = PermissionMap.checkCustomPermissionApi(sm)
        if (customPermissionChecking != "") return true

        // api permission checking
        val methods = SootTool.getInvokeMethodListInMethod(sm)
        methods.forEach { mtd ->
            val permissions = PermissionMap.checkMethodPermission(mtd)
            if (permissions.isNotEmpty()) return true
        }
        return false
    }

    private fun getExceptionNameFromUnit(u: soot.Unit): String? {
        if (u is AssignStmt) {
            return u.rightOp.type.toString()
        }
        return null
    }

    // --------------------------------------------------------------------------
    // check illegal parameters,
    // 1. args checking in last level method
    // 2. dataflow analysis to check IPC method params
    private fun checkIllegalParametersInHelper(call: ServiceMethod): Boolean {

        // check last level exception
        if (lastCallLevelCheckingAnalysis(call)) {
                return true
        }

        if (dataFlowAnalysis(call)) {
                return true
        }

        return false
    }


    private fun dataFlowAnalysis(call: ServiceMethod): Boolean {
        val res = ExceptionDataFlowAnalysis(call).checkExceptions()
        if (res.isNotEmpty()) {
            addParamsException(call, res)
            return true
        }
        return false
    }

    private fun lastCallLevelCheckingAnalysis(call: ServiceMethod): Boolean {
        val last = call.callChain.last
        val res = backwardExceptionExistAnalysis(last, call.interfaceMtd)
        if (res != null) {
            addParamsException(call, listOf(res))
            return true
        }
        return false
    }

    /*
    If exist throw Illegal Param Exception Before Invoked (not check the params)
    Helper class
     */
    private fun backwardExceptionExistAnalysis(mtd: SootMethod, inv: SootMethod): String? {
//        val u = SootTool.getInvokeUnitInMethod(mtd, inv)
        val body = SootTool.tryGetMethodBody(mtd)
//        val exceptionGraph = ExceptionalUnitGraph(body)
//        val locals = exceptionGraph.getPredsOf(u)
        // backword analysis
//        println(body)
        var start = false
        body?.units?.reversed()?.forEach { r ->
            if (start) {
               val res = checkExceptionInUnit(r)
                if (res != null) return res
            }
            if (SootTool.unitInvokeMethod(r, inv)) {
                start = true
            }
        }
//        DebugTool.exitHere()
        return null
    }

    private fun addParamsException(call: ServiceMethod, exp: List<String>) {
        if (call.exceptionBypass == null) {
            call.exceptionBypass = mutableListOf()
        }
        call.exceptionBypass!!.addAll(exp)
    }

    /*
    If a unit is exception check Statement
     */
    private fun checkExceptionInUnit(r: soot.Unit): String? {
//        println("checkUnit ${r.javaClass} $r")
        var invoked: SootMethod? = null
        if (r is AssignStmt) {
            val right = r.rightOp
            if (right is InvokeExpr) {
                invoked = right.method
            }
        } else if (r is InvokeExpr) {
            invoked = r.method
        }
        if (invoked != null) {
            val res = ExceptionStmtChecking.checkExceptionInFun(invoked, 0)
//            DebugTool.exitHere()
            if (res != null) return res
        }
        return null
    }


    /*
     Service Implement class, check if params of methods are validated.
     */
    private fun checkParamsProtectedInImpl(call: ServiceMethod): Boolean {
        if (call.implMethod == call.interfaceMtd) return false

        val mtd = call.implMethod!!
        val declared = ExceptionStmtChecking.getDeclaredParamsInMethod(mtd)
        val body = SootTool.tryGetMethodBody(mtd)
        body?.units?.forEach { u ->
            if (u is Stmt && u.containsInvokeExpr()) {
                val expr = u.invokeExpr
                if (isMethodCheckParams(expr.method, declared)) {
                    return true
                }
            } else {
                val exp = SootTool.getAssignTypeFromUnit(u)
                val expName = ExceptionStmtChecking.filterExceptionByName(exp)
                if (expName != null) {
                    return true
                }
            }

        }
        return false
    }

    // checked one method
    private fun isMethodCheckParams(mtd: SootMethod, used: HashMap<Int, soot.Local?>): Boolean {
        val params = HashSet<soot.Local>()
        val declared = ExceptionStmtChecking.getDeclaredParamsInMethod(mtd)
        declared.forEach { t, u ->
            if (u is Local && used[t] != null) {
                params.add(u)
            }
        }
        val checking = ExceptionStmtChecking.getExceptionInParamsCheckings(mtd, params)
        if (checking.isNotEmpty()) {
            checking.forEach { exp ->
                if (exceptionSet.contains(exp)) {
                    return true
                }
            }
        }
        return false
    }
}