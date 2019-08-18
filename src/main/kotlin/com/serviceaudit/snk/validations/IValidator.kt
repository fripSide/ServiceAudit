package com.serviceaudit.snk.validations

import com.serviceaudit.snk.services.ServiceMethod
import soot.SootClass
import soot.SootMethod

interface IValidator {
    val order: Int
    val tag: String
    fun validateApi(call: ServiceMethod): Int {
        return 0
    }
}