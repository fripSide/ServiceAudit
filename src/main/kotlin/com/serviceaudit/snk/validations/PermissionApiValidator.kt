package com.serviceaudit.snk.validations

import com.serviceaudit.snk.analysis.InvokeExprParamsSolver
import com.serviceaudit.snk.analysis.PermissionMap
import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool

// Privilege Escalation Detecting
class PermissionApiValidator(override val tag: String = "PermissionApiValidator", override val order: Int = 1000): IValidator {

    // now use fixed score, these score can be train via ml methods
    val vulScore = 1

    val permissionChecking = listOf("enforceCallingOrSelfPermission")

    /*
    Notification->Security
     */
    override fun validateApi(call: ServiceMethod): Int {
//        PermissionMap.checkMethodPermission()
        val permissionSet = mutableSetOf<String>()
        call.callChain.forEach { mtd->
            permissionSet.addAll(PermissionMap.checkMethodPermission(mtd))
        }
        if (permissionSet.isNotEmpty()) {
            LogNow.info("By pass permission $permissionSet")
//            call.permissionBypass = permissionSet.toList()
//            return vulScore
        }
        return 0
    }

    // the permission need by IPC methods
    private fun iIpcMethodsNeedPermission(call: ServiceMethod): List<String> {
        val ret = mutableListOf<String>()
        // api permission checking
        val methods = SootTool.getInvokeMethodListInMethod(call.interfaceMtd)
        methods.forEach { mtd ->
            val permissions = PermissionMap.checkMethodPermission(mtd)
            ret.addAll(permissions)
        }
        return ret
    }

    // which permissions are checking by Service
    private fun ipcMethodsPermissionChecking() {

    }
}