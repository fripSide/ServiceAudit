package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.CONFIG
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod
import java.io.File
import java.lang.Exception

/*
Obtain api permission with PScout.
If a service impl method need some permissions and the permission checking are perform between the control flow of
helper method and impl method, these checking can be bypassed.
 */
object PermissionMap {

    // method -> permission
    val permissionMap = HashMap<String, HashSet<String>>()

    init { // load PScout permission map results
        loadPscoutData()
    }

    // check api permission via pscout
    fun checkMethodPermission(mtd: SootMethod): List<String> {
        val permissionSet = HashSet<String>()
        val name = mtd.signature
        if (permissionMap.containsKey(name)) {
            permissionSet.addAll(permissionMap[name]!!)
        }
        return permissionSet.toList()
    }

    fun checkCustomPermissionApi(sm: SootMethod): String {
        return PermissionCheckingResolver(sm).checkEnforceExist()
    }

    fun loadPscoutData() {
        LogNow.info("Load pscout data!")
        val pt = CONFIG.PSCOUT_PATH
        try {
            var permission = ""
            File(pt).forEachLine { li ->
                if (li.startsWith("Permission:")) {
                    permission = li.replace("Permission:", "")
                } else if (li.startsWith("<")) {
                    val method = li.split(" (")[0]
//                    println(method)
                    if (!permissionMap.containsKey(method)) {
                        permissionMap[method] = HashSet()
                    }
                    permissionMap[method]!!.add(permission)
                }
            }
//            permissionMap.forEach{ local, u ->
//                if (u.size > 1) {
//                    println("$local $u")
//                }
//            }
        } catch (ex: Exception) {
            DebugTool.panic(ex)
        }
    }
}