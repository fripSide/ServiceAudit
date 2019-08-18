package com.serviceaudit.snk.validations

import com.serviceaudit.snk.services.ServiceMethod
import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod
import soot.jimple.Stmt

// Fake status detecting
class MethodStatusValidator(override val tag: String = "MethodStatusValidator",  override val order: Int = 100): IValidator {

    // now use fixed score, these score can be train via ml methods
    val vulScore = 1

    val fakeStatusExceptions = hashSetOf("java.lang.IllegalStateException")

    /*
    Notification->Security
     */
    override fun validateApi(call: ServiceMethod): Int {
        if (checkLastLevelFakeStatus(call) && !isImplProtectedStatus(call)) {
            call.vulTag = VulnerableTags.FakeStatus
            return vulScore
        }
        return 0
    }

    private fun extractExceptionBeforeInvoke(sm: SootMethod, invoke: SootMethod) : HashSet<String> {
        val ret = HashSet<String>()
        val body = SootTool.tryGetMethodBody(sm)
        val inv = SootTool.getInvokeUnitInMethod(sm, invoke)
        body?.units?.forEach { u ->
            val s = SootTool.getAssignTypeFromUnit(u)
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
        if (checkStatus && !call.checkImplMethodNeedPermission()) {
            return true
        }
        return false
    }

    private fun isImplProtectedStatus(call: ServiceMethod): Boolean {
        if (call.implMethod == call.interfaceMtd) return false
        val mtd = call.implMethod!!
        val exceptions = HashSet<String>()
        val body = SootTool.tryGetMethodBody(mtd)
        body?.units?.forEach { u ->
            var s: String? = null
            if (u is Stmt && u.containsInvokeExpr()) {
                val ink = u.invokeExpr
                s = isMethodCheckStatus(ink.method)
            } else {
                s = SootTool.getAssignTypeFromUnit(u)
            }
            if (s != null && fakeStatusExceptions.contains(s)) {
                exceptions.add(s)
            }
        }
        exceptions.forEach { exp ->
            if (fakeStatusExceptions.contains(exp)) {
                return true
            }
        }
        return false
    }

    // check in level 1 method
    private fun isMethodCheckStatus(mtd: SootMethod): String? {
        val body = SootTool.tryGetMethodBody(mtd)
        body?.units?.forEach { u ->
            val s = SootTool.getAssignTypeFromUnit(u)
            if (s != null && fakeStatusExceptions.contains(s)) {
               return s
            }
        }
        return null
    }
}