package com.serviceaudit.snk.utils

import com.serviceaudit.snk.services.ServiceApi
import com.serviceaudit.snk.services.VulServiceApi
import soot.Scene
import java.lang.StringBuilder

object Statistics {

    val save_path = "report_26.txt"

    var vulResults = HashSet<VulServiceApi>()

    val vulKinds = mutableMapOf<String, HashSet<VulServiceApi>>()
    /*
    1.Total class
    2.Total service helpers
    3.Vulnerabilities
     */
    fun statClasses(api: ServiceApi) {
        LogNow.show("=========================================================")
        LogNow.show("                        Statistic                        ")
        LogNow.show("=========================================================")
        statBasicClassNum()
        LogNow.show("Service Helper Num: ${api.serviceHelperSet.size}")
        LogNow.show("Service IPC methods Num: ${api.entryPointMethodSet.size}")
        statVulDetail()
        genReport()
    }

    private fun statBasicClassNum() {
        val totalCls = Scene.v().classes.size
        LogNow.show("Class Num: $totalCls")
    }

    private fun statVulDetail() {
        vulResults.forEach { res ->
            if (res.vulType != null) {
                if (!vulKinds.containsKey(res.vulType!!)) {
                    vulKinds[res.vulType!!] = HashSet<VulServiceApi>()
                }
                vulKinds[res.vulType!!]!!.add(res)
            }
        }
        LogNow.show("Vulnerable Type: ")
        var total = 0
        val totalIPC = HashSet<String>()
        vulKinds.forEach { t, u ->
            val infNum = HashSet<String>()
            u.forEach { v ->
                val short = getServiceName(v)
                infNum.add(short)
                totalIPC.add(short)
            }
            LogNow.show("\t$t API Num:${u.size} Service Num:${infNum.size}")
            total += u.size
        }
        LogNow.show("Total Vulnerable API: $total\nTotal Vulnerable Service: ${totalIPC.size}")
//        println(totalIPC)
    }

    private fun getServiceName(vul: VulServiceApi): String {
        // <interface: method> -> <interface
        val names = vul.serviceApi.split(":")
        // <interface -> interface
        val short = names[0].substring(1)
        return short
    }

    private fun genReport() {
        val str = StringBuilder()
        vulKinds.forEach { t, u ->
            str.append("$t(${u.size})\n")
            u.forEach { v ->
               str.append("\t${v.serviceApi}\n")
            }
        }
        Results.saveResult(str.toString(), Results.REPORT)
    }
}