package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.CONFIG
import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod
import java.io.File
import java.lang.Exception

/*
Resolve implicit control flow with EdgeMiner.
 */
object ImplicitControFlowResolver {

    val callbacks = HashSet<String>()

    init { // use EdgeMiner results
        loadEdgeMinerCallbacks()
    }

    /*
    Get possible method implement for implicit call if can not retrieve active body.
     */
    fun checkAndResolveImplicitCall(call: SootMethod): List<SootMethod> {
        val cls = call.declaringClass
        val mtdImpl = mutableListOf<SootMethod>()
        cls.interfaces.forEach { inf ->
            if (inf.declaresMethod(call.signature)) {
                val mtd = inf.getMethod(call.signature)
                if (filterMethodImpl(mtd))
                    mtdImpl.add(mtd)
            }
        }
        return mtdImpl
    }

    private fun filterCallbacks(cb: String): Boolean {
        when {
            cb.startsWith("android.R$") -> return false
            cb.startsWith("android.test") -> return false
        }
        return true
    }

    private fun filterMethodImpl(mtd: SootMethod): Boolean {
        if (mtd.isConstructor || mtd.isStaticInitializer)
            return false
        if (!mtd.isConcrete) return false
        if (SootTool.isEmptyMtd(mtd)) return false
        return true
    }

    private fun loadEdgeMinerCallbacks() {
        val pt = CONFIG.EDGE_MINER
        try {
            File(pt).forEachLine { li ->
                if (li.startsWith("android")) {
                    if (filterCallbacks(li))
                        callbacks.add(li)
                }
            }
        } catch (ex: Exception) {
            DebugTool.panic(ex)
        }
        LogNow.info("Load EdgeMiner. Total callbacks: ${callbacks.size}")
    }
}