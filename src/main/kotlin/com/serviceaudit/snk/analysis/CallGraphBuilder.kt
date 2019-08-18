package com.serviceaudit.snk.analysis

import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod
import soot.jimple.InvokeExpr
import java.lang.Exception
import java.util.*
import kotlin.collections.HashSet

/*
Build method level call graph on-the-fly, only isIn the call site from start method to target method.
 */
class CallGraphBuilder(val start: SootMethod, val targetSet: HashSet<SootMethod>) {

    val workList = ArrayDeque<LinkedList<SootMethod>>()
    val callSet = HashSet<ServiceMethod>()
    val methodNameSet = HashSet<String>()
    val visitedSet = HashSet<String>()

    fun build(): HashSet<ServiceMethod> {
        targetSet.forEach { mtd ->
            methodNameSet.add(mtd.subSignature)
        }
        bfsCallGraph()
        return callSet
    }

    fun bfsCallGraph() {
        val entry = LinkedList<SootMethod>()
        entry.addLast(start)
        workList.add(entry)
        while (workList.isNotEmpty()) {
            val chain = workList.poll()
            val cur = chain.last
            if (visitedSet.contains(cur.signature)) continue
            visitedSet.add(cur.signature)
            val body = SootTool.tryGetMethodBody(cur)
            body?.useBoxes?.forEach { box ->
                if (box.value is InvokeExpr) {
                    val expr = box.value as InvokeExpr
                    try {
                        val curMtd = expr.method
                        // handle implicit call

                        if (methodNameSet.contains(curMtd.subSignature)) {
                            val called = getCalledMethod(curMtd.name)!!
                            val sm = ServiceMethod(called)
                            sm.helperClass = start.declaringClass
                            sm.calledMethod = start
                            sm.implClass = called.declaringClass
                            sm.iInterface = SootTool.getInfForImpl(called.declaringClass)
                            sm.callChain = chain
                            callSet.add(sm)
                        } else {
                            val lst = LinkedList(chain)
                            lst.addLast(curMtd)
                            workList.push(lst)
                        }
                    } catch (ex: Exception) {
                        // method is empty
                    }
                }
            }
        }
    }

    private fun getCalledMethod(name: String): SootMethod? {
        for (mtd in targetSet) {
            if (mtd.name == name) return mtd
        }
        return null
    }

    private fun resolveImplicitCall() {

    }
}