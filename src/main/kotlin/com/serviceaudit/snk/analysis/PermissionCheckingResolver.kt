package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod
import soot.jimple.InvokeExpr

class PermissionCheckingResolver(var mtd: SootMethod) {

    // from associate rules analysis
    private var enforceCheckingApi = listOf("enforceCallingOrSelfPermission", "enforceCallingPermission", "checkPackageName", "enforcePackageName", "checkCallingOrSelfPermission", "checkOp", "enforcePermission",
            "enforceUriPermission", "getCallingUserId", "checkReadPermission", "canCallerAccessMockLocation", "checkComponentPermission", "enforceCallerMatchesPackage")

    private var enforcementKind = ""

    private val maxLev = 3

    fun checkEnforceExist(): String {
        checkEnforceMethods(mtd)
        return enforcementKind
    }

    private fun checkEnforceMethods(sm: SootMethod, lev: Int = maxLev) {
        if (lev <= 0 || enforcementKind != "") return
        // level 1
//        println("checkEnforceMethods $mtd")
        for (check in enforceCheckingApi) {
            if (SootTool.checkMtdContainsMethodCall(sm, check)) {
                enforcementKind = check
                return
            }
        }
        // check next level
        val body = SootTool.tryGetMethodBody(sm)
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val expr = box.value as InvokeExpr
                try {
                    val curMtd = expr.method
                    checkEnforceMethods(curMtd, lev - 1)
                } catch (ex: Exception) {
                }
            }
        }
    }

}