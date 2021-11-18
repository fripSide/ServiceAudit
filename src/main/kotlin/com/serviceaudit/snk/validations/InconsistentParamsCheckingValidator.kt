package com.serviceaudit.snk.validations

import com.serviceaudit.snk.analysis.ParamsAssociateAnalysis
import com.serviceaudit.snk.analysis.PermissionCheckingResolver
import com.serviceaudit.snk.services.MethodDesc
import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod

/*
https://github.com/lilicoding/SimiDroid/blob/master/src/lu/uni/snt/simidroid/plugin/method/MethodSimilarityAnalysis.java
1. Fake ID (user identify is send to IPC method as a parameter)
2. System environment checking bypass (Identify is checked before IPC method)
 */
class InconsistentParamsCheckingValidator: IValidator {
    override val tag: String = "InconsistentParamsCheckingValidator"

    override val order: Int = 10

    private val vulScore = 1

    /*
        getOpPackageName
     */
    var keyWordsMap = hashMapOf<String, String>("check" to "params")

    var sensitiveMethodName = listOf("getOpPackageName")

    var allMtdParams = mutableListOf<MutableList<String>>()

    var enforceCheckingApi = listOf("enforceCallingOrSelfPermission", "checkOp", "enforcePermission",
            "enforceUriPermission", "getCallingUserId")

    private val kPermissionEnforce = "CallerCheckingEnforcement"

    override fun validateApi(call: ServiceMethod): Int {
        val hm = call.calledMethod!!
//        val params = SootTool.extractParamsNameInMethod(call.callChain.last)
//        println("${call.callChain.last} $params")
        val inf = call.interfaceMtd
        if (inf.parameterCount == 0) return 0
        val methodDescList = mutableListOf<MethodDesc>()
        call.mtdDesc.forEach { t, u ->
            methodDescList.addAll(u)
        }

//        LogNow.info("$methodDescList")
        methodDescList.forEach { ms ->
            val sensitiveParams = ParamsAssociateAnalysis.sensitiveParamsAnalysis(ms.params)
            val sensitiveApiCalled = ParamsAssociateAnalysis.methodWordSynonymsAnalysis(ms.mtdName)
            if (sensitiveApiCalled != "") {
                call.checkingBypassList.add(Pair(ms.mtdName, sensitiveApiCalled))
            }
        }
        if (checkingBypassAnalysis(call)) {
            checkVulType(call)
            return vulScore
        }
        return 0
    }

    private fun checkingBypassAnalysis(call: ServiceMethod): Boolean {
//        println("checkingBypassAnalysis ${call.interfaceMtd}  ${call.checkingBypassList} ")
        if (call.checkingBypassList.isEmpty()) return false

        val isEnforce = call.checkImplMethodNeedPermission()
//        val isEnforce = isEnforcedInImplClass(call)
        if (isEnforce) {
//            println("isEnforcedInImplClass ${call.enforcementList}")
            if (!compareSecurityMechanisms(call)) return true
            return false
        }
        return true
    }

    private fun isEnforcedInImplClass(call: ServiceMethod): Boolean {
        if (call.implMethod == call.interfaceMtd) {
//            LogNow.info("$call")
//            DebugTool.exitHere()
            return false
        }

        val impl = call.implMethod!!
        val check = enforceCaller(impl)
        if (check != "") {
            call.enforcementList.add(Pair(check, kPermissionEnforce))
            return true
        }
//        val methods = SootTool.in
        LogNow.info("${call.implMethod} :need to check impl class")
        val mtdDesc = SootTool.getInvokeMtdsInMethodCall(call.implMethod!!)
        mtdDesc.forEach { mtd ->
            val enforce = checkPermissionEnforce(mtd.mtdName)
            if (enforce != "") {
                call.enforcementList.add(Pair(mtd.mtdName, enforce))
                return true
            }
        }
//        DebugTool.exitHere()
        return false
    }

    private fun compareSecurityMechanisms(call: ServiceMethod): Boolean {
        val checkingSet = HashSet<String>()
        val enforcementSet = HashSet<String>()
        call.checkingBypassList.forEach {
            val str = it.second
            val kinds = str.split(":")
            if (kinds.isNotEmpty())
                checkingSet.add(kinds[0])
        }
        call.enforcementList.forEach {
            val str = it.second
            val kinds = str.split(":")
            if (kinds.isNotEmpty())
                enforcementSet.add(kinds[0])
        }

        if (enforcementSet.contains(kPermissionEnforce)) return true
        for (check in checkingSet) {
            if (!enforcementSet.contains(check)) return false
        }
        return true
    }

    private fun checkPermissionEnforce(name: String): String {
        val sensitiveApiCalled = ParamsAssociateAnalysis.methodWordSynonymsAnalysis(name)
        if (ParamsAssociateAnalysis.isPermissionCheckingApi(name)) {
            return kPermissionEnforce
        }
        return sensitiveApiCalled
    }

    private fun enforceCaller(sm: SootMethod): String {
        val res = PermissionCheckingResolver(sm).checkEnforceExist()
        // level 1
//        for (check in enforceCheckingApi) {
//            if (SootTool.checkMtdContainsMethodCall(sm, check)) {
//                return check
//            }
//        }
//        // level 2
//        val body = SootTool.tryGetMethodBody(sm)
//        body?.useBoxes?.forEach { box ->
//            if (box.value is InvokeExpr) {
//                val expr = box.value as InvokeExpr
//                try {
//                    val curMtd = expr.method
//                    if (curMtd.name.startsWith("enforce")) {
//                        for (check in enforceCheckingApi) {
//                            if (SootTool.checkMtdContainsMethodCall(curMtd, check)) {
//                                return check
//                            }
//                        }
//                    }
//                } catch (ex: Exception) {
//                }
//            }
//        }
        return res
    }

    // check if the parameters are getUserId or getPackageName
    private fun checkVulType(call: ServiceMethod) {
        call.vulTag = VulnerableTags.FakeID
        val target = call.interfaceMtd.name
        val last = call.callChain.last
        val desc = call.mtdDesc[last]
        val paramsSet = hashSetOf<String>()
        run l1@{
            desc?.forEach { d ->
                if (d.mtdName == target) {
                    d.params?.forEach { p ->
//                        val sensitiveApiCalled = ParamsAssociateAnalysis.methodWordSynonymsAnalysis(p.paramName)
//                        if (sensitiveApiCalled != "") {
//                        }
                        paramsSet.add(p.paramType)
                    }
                    return@l1
                }
            }
        }

        call.interfaceMtd.parameterTypes.forEach { t ->
            paramsSet.add(t.toString())
//            println("adding $t")
        }

        if (isEnvMethod(paramsSet)) {
            call.vulTag = VulnerableTags.SysEnv
        }
    }

    private fun isEnvMethod(paramsSet: HashSet<String>): Boolean {
        val identifyTypes = hashSetOf("java.lang.String", "int")
        paramsSet.forEach { v ->
            if (identifyTypes.contains(v)) {
                return false
            }
        }
        return true
    }
}