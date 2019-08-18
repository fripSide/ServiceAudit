package com.serviceaudit.snk.services

import com.serviceaudit.snk.analysis.PermissionMap
import com.serviceaudit.snk.utils.SootTool
import soot.SootClass
import soot.SootMethod
import java.util.*
import kotlin.collections.HashMap
import kotlin.collections.HashSet

/*
Only used in methods from the same chain so methods with common name can be regarded as the same method.
 */
data class MethodParams(var paramName: String, var paramType: String) {
    override fun hashCode(): Int {
//        val str = paramName + paramType
        return paramName.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other is MethodParams) {
            return paramName == other.paramName
        }
        return super.equals(other)
    }

    override fun toString(): String {
        return "$paramName<$paramType>"
    }
}

data class MethodDesc(var mtdName: String, var params: List<MethodParams>?) {
    override fun hashCode(): Int {
//        return toString().hashCode()
        return mtdName.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other is MethodDesc) {
            return other.mtdName == mtdName
        }
        return super.equals(other)
    }

    override fun toString(): String {
        return "$mtdName $params"
    }
}

/*
Method in Service helper: helperClass->calledMethod(call chain)->interfaceMtd (check for the whole call chain)
Method in Service Impl: interfaceMtd->implClass->implMethod (check only one level)
 */
class ServiceMethod(m: SootMethod) {
    var interfaceMtd: SootMethod = m
    var iInterface: SootClass? = null
    var helperClass: SootClass? = null
    var implClass: SootClass? = null
    var implMethod: SootMethod? = null
    var calledMethod: SootMethod? = null


    // method level call graph
    var callChain = LinkedList<SootMethod>()

    // methods in call graph
    var mtdDesc: HashMap<SootMethod, HashSet<MethodDesc>> = HashMap()

    val checkingBypassList = mutableListOf<Pair<String, String>>()

    var vulTag: String? = null // which kind of vulnerability

    val enforcementList = mutableListOf<Pair<String, String>>()

    var exceptionBypass: MutableList<String>? = null

    // permissions only verified in service helper but not checked in service implementations
    var permissionBypass: List<String>? = null

    private var hasCheckImplPermission = false

    override fun hashCode(): Int {
        val h = "$interfaceMtd $calledMethod"
        return h.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other is ServiceMethod) {
            return interfaceMtd == other
        }
        return super.equals(other)
    }

    override fun toString(): String {
        return "{$interfaceMtd | $calledMethod | $iInterface | chain(${callChain.size})}"
    }

    fun analysisInvokes() {
//        val solver = InvokeExprParamsSolver()
    }

    // do not add to enforcement list
    fun isImplMethodNeedPermission(): Boolean {
        if (interfaceMtd == implMethod) return false
        val sm = implMethod!!
        val customPermissionChecking = PermissionMap.checkCustomPermissionApi(sm)
        if (customPermissionChecking != "") {
            return true
        }
        // api permission checking
        val methods = SootTool.getInvokeMethodListInMethod(sm)
        methods.forEach { mtd ->
            val permissions = PermissionMap.checkMethodPermission(mtd)
            if (permissions.isNotEmpty()) return true
        }
        return false
    }

    // add to enforce list
    fun checkImplMethodNeedPermission(): Boolean {
        if (interfaceMtd == implMethod) return false
        analysisImplementApiPermission(implMethod!!)
        return enforcementList.isNotEmpty()
    }

    // check if impl API contains permission checking invokes, execute only once
    private fun analysisImplementApiPermission(sm: SootMethod) {
        if (hasCheckImplPermission) return
        enforcementList.clear()
        val kPermissionEnforce = "CallerCheckingEnforcement"
        val customPermissionChecking = PermissionMap.checkCustomPermissionApi(sm)
        if (customPermissionChecking != "") {
            enforcementList.add(Pair(customPermissionChecking, kPermissionEnforce))
        }
        // api permission checking
        val methods = SootTool.getInvokeMethodListInMethod(sm)
        methods.forEach { mtd ->
            val permissions = PermissionMap.checkMethodPermission(mtd)
            permissions.forEach { p ->
                enforcementList.add(Pair(p, "PScout Permission"))
            }
        }
        hasCheckImplPermission = true
    }


    fun asVulnerableApi(): VulServiceApi {
        val bypass = mutableListOf<String>()
        val enforce = mutableListOf<String>()
        checkingBypassList.forEach {
            bypass.add("${it.first} ${it.second}")
        }
        enforcementList.forEach {
            enforce.add("${it.first} ${it.second}")
        }
        return VulServiceApi(interfaceMtd.signature, implMethod!!.signature, listOf(), bypass, enforce, vulTag, exceptionBypass, permissionBypass)
    }
}