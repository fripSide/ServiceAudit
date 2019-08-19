package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.SootTool
import soot.Local
import soot.SootMethod
import soot.Unit
import soot.jimple.*
import soot.jimple.internal.ImmediateBox
import soot.toolkits.graph.ExceptionalUnitGraph
import soot.toolkits.scalar.ArraySparseSet
import soot.toolkits.scalar.BackwardFlowAnalysis
import soot.toolkits.scalar.FlowSet

class ParamsExceptionDesc(var idx: Int, val local: Local, val exp: String?, var methodName: String = "") {

    override fun hashCode(): Int {
        return local.toString().hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other is ParamsExceptionDesc) {
            return other.idx == idx
        }
        return super.equals(other)
    }

    override fun toString(): String {
        if (exp != null) {
            return "$methodName params[$idx] ${local.type}: $local -> $exp"
        }
        return "params[$idx] ${local.type}: $local"
    }
}

/*
Checked if the parameter of IPC methods is checked in service helper method
@params params, that are passed by paraent
 */
class ExceptionBackwardAnalysis(val g: ExceptionalUnitGraph, var inv: SootMethod, var paramUsed: HashMap<Int, Local?>): BackwardFlowAnalysis<Unit, FlowSet<Local>>(g) {

    private val paramSet = hashMapOf<Local, Int>()

    private val emptySet: FlowSet<Local> = ArraySparseSet<Local>()

    private val paramsExp = mutableMapOf<Local, ParamsExceptionDesc>()

    private val pointToMap = mutableMapOf<Local, Local>()

    private val declaredParams = HashMap<Int, Local?>()

    private var isFind = false

    init {
        doAnalysis()
    }

    override fun newInitialFlow(): FlowSet<Local> {
        return emptySet.clone()
    }

    override fun merge(inSet1: FlowSet<Local>?, inSet2: FlowSet<Local>?, outSet: FlowSet<Local>?) {
        inSet1?.union(inSet2, emptySet)
    }

    override fun copy(srcSet: FlowSet<Local>?, destSet: FlowSet<Local>?) {
        srcSet?.copy(destSet)
    }

    override fun flowThrough(inSet: FlowSet<Local>?, node: Unit?, outSet: FlowSet<Local>?) {
        if (node == null || isFind) return
//        println("flowThrough: ${node.javaClass} $node")
        val stmt = node as Stmt
        if (stmt.containsInvokeExpr()) {
            val expr = stmt.invokeExpr
            analysisInvokeExpr(expr)
        }
        when (node) {

            // check param
            is IfStmt -> {
                analysisIfBranch(node)
            }

            // invoke method, add IPC method params to set
//            is InvokeStmt -> {
//                val expr = node.invokeExpr
//                analysisInvokeExpr(expr)
//            }
//
//            is AssignStmt -> {
//                val rightOp = node.rightOp
//                if (rightOp is InvokeExpr) {
//                    analysisInvokeExpr(rightOp)
//                }
//            }

            // get method declared parameters
             is IdentityStmt -> {
                val right = node.rightOp
                if (right is ParameterRef) {
                    val left = node.leftOp
                    if (left is Local) {
                        declaredParams[right.index] = left
                    }
                }
            }
        }
        isFind = paramsExp.isNotEmpty()
    }

    fun isParamCheckedException(): List<ParamsExceptionDesc> {
        val paramsExceptions = HashSet<ParamsExceptionDesc>()
        // add exception items
        paramsExp.forEach { t, u ->
            var idx = 0
            if (paramSet[t] != null)
                idx = paramSet[t]!!
            u.idx = idx
            paramsExceptions.add(u)
        }
        val usedMap = HashMap<Local, Int>()
        paramUsed.forEach { t, u ->
            if (u != null) {
                usedMap[u] = t
            }
        }
        // passed by function
        declaredParams.forEach { t, u ->
            val idx = findPointToUsed(u, usedMap)
            if (idx >= 0) {
                var item = paramsExceptions.find { it.idx == idx }
                if (item == null) {
                    // should ordered by declare
                    item = ParamsExceptionDesc(t, paramUsed[idx]!!, null)
                }
                item.idx = t
                paramsExceptions.add(item)
            }
        }
        return paramsExceptions.toList()
    }

    private fun findPointToUsed(local: Local?, usedParams: HashMap<Local, Int>): Int {
        if (local != null) {
            if (usedParams.containsKey(local)) {
                return usedParams[local]!!
            }
        }
        return -1
    }

    private fun analysisInvokeExpr(expr: InvokeExpr) {
//        println("Invoke $expr")
        if (expr.method == inv) {
            for (i in 0..(expr.argCount - 1)) {
                val arg = expr.args[i]
                if (arg is Local) {
                    if (paramUsed[i] != null) {
                        paramSet[arg] = i
                    } else {
//                        println("$expr $paramUsed")
//                        DebugTool.exitHere()
                    }
//                    paramSet[arg] = i
                }
            }

        } else if (paramSet.isNotEmpty()) { // check if is illegal param validate
            analysisParamsCheckMethod(expr)
        }
    }

    /*

     */
    private fun analysisParamsCheckMethod(inv: InvokeExpr): Boolean {
        val args = ExceptionStmtChecking.getInvokeParams(inv)
        val usedPrams = HashMap<Int, Local?>()
        args.forEach { t, u ->
            if (paramSet.containsKey(u)) {
                usedPrams[t] = u
            }
        }
//        println("analysisParamsCheckMethod $args $paramSet $usedPrams ${inv.method}")
        if (usedPrams.isNotEmpty()) {
            val mtd = inv.method
//            val res = ExceptionStmtChecking.checkExceptionInFun(inv.method)
            val params = ExceptionStmtChecking.getCheckingParamsInMethod(inv.method, usedPrams)
            if (params.isNotEmpty()) {
                val ret = ExceptionStmtChecking.paramsAreCheckingInMethods(inv.method, params)
                if (ret.isNotEmpty()) {
                    ret.forEach { t, u ->
                        val p = ParamsExceptionDesc(0, t, u, mtd.name)
                        paramsExp[t] = p
                    }
                }
//                    DebugTool.exitHere()
                return true
            }
        }

        return false
    }

    private fun analysisIfBranch(expr: IfStmt) {
        val cmp = expr.condition as ConditionExpr
        val paramsChecked = isParamsCheckExpr(cmp)
        if (paramsChecked.isNotEmpty()) {
            val branch = g.getSuccsOf(expr)
            branch.forEach { u ->
                val exp = SootTool.getAssignTypeFromUnit(u)
                if (exp != null) {
                    val expName = ExceptionStmtChecking.filterExceptionByName(exp)
                    if (expName != null) {
                        paramsChecked.forEach { param ->
                            paramsExp[param] = ParamsExceptionDesc(0, param, expName, inv.name)
                        }
                    }
                }
            }
        }
    }


    private fun isParamsCheckExpr(expr: ConditionExpr): List<Local> {
        val paramsUsed = mutableListOf<Local>()
        run l1@ {
            expr.useBoxes.forEach { u ->
                if (u is ImmediateBox) {
                    val v = u.value
                    if (v is Local) {
                        if (paramSet.contains(v)) {
                           paramsUsed.add(v)
                        }
                    }

                }
            }
        }

        return paramsUsed
    }
}

/*
Inter-procedure DataFlow analysis
 */
class ExceptionDataFlowAnalysis(val call: ServiceMethod) {

    private var paramsUsed = HashMap<Int, Local?>()

    fun checkExceptions(): List<String> {
        var called = call.interfaceMtd

        if (called.parameterCount == 0) return emptyList()
        val workList = call.callChain
        paramsUsed = ExceptionStmtChecking.getMethodInvokedParams(workList.last, called)
        for (i in (workList.size - 1) downTo 0) {
            val callee = workList[i]
            val curParams = ExceptionStmtChecking.getMethodInvokedParams(callee, called)
            updateParamsSet(curParams)
            val ret = backwardParamsCheckingExceptionAnalysis(callee, called)
            val res = mutableListOf<String>()
            paramsUsed.clear()
            for (param in ret) {
                if (param.exp != null) {
                    res.add(param.toString())
                } else {
                    paramsUsed[param.idx] = param.local
                }
            }
            if (res.isNotEmpty()) {
                return res
            }
            if (paramsUsed.isEmpty()) return emptyList()
//            DebugTool.exitHere()
//            return emptyList()
            called = callee
        }
        return emptyList()
    }


    private fun backwardParamsCheckingExceptionAnalysis(mtd: SootMethod, inv: SootMethod): List<ParamsExceptionDesc> {
        val body = SootTool.tryGetMethodBody(mtd)
//        println(body)
        val exceptionGraph = ExceptionalUnitGraph(body)
        return ExceptionBackwardAnalysis(exceptionGraph, inv, paramsUsed).isParamCheckedException()
    }

    private fun updateParamsSet(params: HashMap<Int, Local?>) {
//        println("updateParamsSet $paramsUsed")
        for (k in paramsUsed.keys) {
            paramsUsed[k] = params[k]
        }
    }

    private fun getCurrentParamsDesc(): List<ParamsExceptionDesc> {
        val res = mutableListOf<ParamsExceptionDesc>()
        paramsUsed.forEach { t, u ->
            if (u != null) {
                res.add(ParamsExceptionDesc(t, u, null))
            }
        }
        return res
    }
}

// check if it is params checking
object ExceptionStmtChecking {

    val exceptionSet = hashSetOf("BadParcelableException", "IllegalArgumentException",
            "SecurityException", "NetworkOnMainThreadException")

    val paramsCheckingKeywords =  hashMapOf<String, HashSet<String>>("params checking1" to hashSetOf("check", "params"),
            "params checking2" to hashSetOf("check", "param"))

    // get all exceptions
    fun getExceptionName(ts: String?): String? {
        if (ts == null) return null
        if (ts.endsWith("Exception")) {
            val shortNameList = ts.split(".")
            val short = shortNameList.last()
            return short
        }
        return null
    }

    // get exceptions that used to check params
    fun filterExceptionByName(ts: String?): String? {
        if (ts == null) return null
        if (ts.endsWith("Exception")) {
            val shortNameList = ts.split(".")
            val short = shortNameList.last()
            if (exceptionSet.contains(short)) {
                return short
            }
        }
        return null
    }

    /*
        check method parameters
        @return Pair<param index, Exception>
     */
    fun getCheckingParamsInMethod(mtd: SootMethod, paramsUsed: HashMap<Int, Local?>): HashSet<Local> {
        val body = SootTool.tryGetMethodBody(mtd)
        val paramSet = HashSet<Local>()
        body?.units?.forEach { u ->
            if (u is IdentityStmt) {
                val right = u.rightOp
                if (right is ParameterRef) {
                    val left = u.leftOp
//                    println("${u.javaClass} $u")
//                    println("${right.index} ${right.javaClass} $left = $right ")
                    if (paramsUsed.containsKey(right.index )) {
                        paramSet.add(left as Local)
                    }
                }
            }
        }
        return paramSet
    }

    fun getDeclaredParamsInMethod(mtd: SootMethod): HashMap<Int, Local?> {
        val declared = HashMap<Int, Local?>()
        val body = SootTool.tryGetMethodBody(mtd)
        body?.units?.forEach { u ->
            if (u is IdentityStmt) {
                val right = u.rightOp
                if (right is ParameterRef) {
                    val left = u.leftOp
                    val idx = right.index
                    declared[idx] = null
                    if (left is Local) {
                        declared[idx] = left
                    }
                }
            }
        }
        return declared
    }

    // filter out exceptions
    fun paramsAreCheckingInMethods(mtd: SootMethod, params: HashSet<Local>): HashMap<Local, String> {
        val expMap = HashMap<Local, String>()
        val body = SootTool.tryGetMethodBody(mtd)
        if (body == null) return expMap
        val graph = ExceptionalUnitGraph(body)
        body.units?.forEach { u->
            if (u is IfStmt) {
                val checking = getConditionExprParams(u.condition as ConditionExpr, params)
                if (checking.isNotEmpty()) {
                    val branch = graph.getSuccsOf(u)
                    branch.forEach { t ->
                        val exp = SootTool.getAssignTypeFromUnit(t)
                        if (exp != null) {
                            val expName = ExceptionStmtChecking.filterExceptionByName(exp)
                            if (expName != null) {
                                checking.forEach { param ->
                                    expMap[param] = expName
                                }
                            }
                        }
                    }
                }
            }
        }
        return expMap
    }

    fun getExceptionInParamsCheckings(mtd: SootMethod, params: HashSet<Local>): HashSet<String> {
        val expSet = HashSet<String>()
        val body = SootTool.tryGetMethodBody(mtd)
        if (body == null) return expSet
        val graph = ExceptionalUnitGraph(body)
        body.units?.forEach { u->
            if (u is IfStmt) {
                val checking = getConditionExprParams(u.condition as ConditionExpr, params)
                if (checking.isNotEmpty()) {
                    val branch = graph.getSuccsOf(u)
                    branch.forEach { t ->
                        val exp = SootTool.getAssignTypeFromUnit(t)
                        if (exp != null) {
                            val expName = ExceptionStmtChecking.getExceptionName(exp)
                            if (expName != null) {
                                expSet.add(expName)
                            }
                        }
                    }
                }
            }
        }
        return expSet
    }

    fun getMethodInvokedParams(mtd: SootMethod, inv: SootMethod): HashMap<Int, Local?> {
        val params = hashMapOf<Int, Local?>()
        val u = SootTool.getInvokeUnitInMethod(mtd, inv)
//        println("$mtd $inv")
        val extractParams: (InvokeExpr) -> kotlin.Unit = { expr ->
            for (i in 0..(expr.argCount - 1)) {
                val arg = expr.args[i]
                if (arg is Local) params[i] = arg
                else params[i] = null
            }
        }

        if (u is Stmt) {
            if (u.containsInvokeExpr()) {
                val expr = u.invokeExpr
                extractParams(expr)
            }
        }
//        println("$u $params")
        return params
    }

    fun paramsIsCheckedInMethod(mtd: SootMethod, params: List<Local>) {
//        val params = mtd.parameterTypes
        val paramsSet = hashSetOf<Local>()

    }

    // if there is exception throw
    fun checkExceptionInFun(mtd: SootMethod, lev: Int = 2): String? {
        val isParamsCheck = isParamsCheckingFun(mtd.name)
        if (lev == 0) {
            return isParamsCheck
        }

        if (isParamsCheck != null) return isParamsCheck

        val body = SootTool.tryGetMethodBody(mtd)
//        DebugTool.exitHere("checkExceptionInFun $mtd")
        body?.units?.forEach { u ->
            var ink: SootMethod? = null
            if (u is AssignStmt) {
                val right = u.rightOp
                if (right is InvokeExpr) {
                    ink = right.method
                }
            } else if (u is InvokeExpr) {
                ink = u.method
            }
            if (ink != null) {
                val res = checkExceptionInFun(ink, lev - 1)
                if (res != null) return res
            }

            val exp = SootTool.getAssignTypeFromUnit(u)
            if (exp != null) {
                val expName = ExceptionStmtChecking.filterExceptionByName(exp)
                if (expName != null) {
                    return expName
                }
            }
        }
        return null
    }

    fun getInvokeParams(expr: InvokeExpr): HashMap<Int, Local?> {
        val params = hashMapOf<Int, Local?>()
        for (i in 0..(expr.argCount - 1)) {
            val arg = expr.args[i]
            if (arg is Local) params[i] = arg
            else params[i] = null
        }
        return params
    }

    private fun getConditionExprParams(expr: ConditionExpr, used: HashSet<Local>): List<Local> {
        val paramsUsed = mutableListOf<Local>()
        run l1@ {
            expr.useBoxes.forEach { u ->
                if (u is ImmediateBox) {
                    val v = u.value
                    if (v is Local && used.contains(v)) {
                        paramsUsed.add(v)
                    }
                }
            }
        }

        return paramsUsed
    }

    private fun isParamsCheckingFun(name: String): String? {
        val words = ParamsAssociateAnalysis.splitWord(name)
        val wordsSet = hashSetOf<String>()
        for (w in words) {
            wordsSet.add(w)
        }
        var isCheckingApi = true
        for (item in paramsCheckingKeywords) {
            val checking = item.value
            for (part in checking) {
                if (!wordsSet.contains(part)) {
                    isCheckingApi = false
                }
            }
            if (isCheckingApi) {
                return "${item.key}: $name"
            }
        }
        return null
    }
}