package com.serviceaudit.snk.utils

import com.serviceaudit.snk.services.MethodDesc
import com.serviceaudit.snk.services.MethodParams
import soot.*
import soot.jimple.*
import soot.jimple.internal.ImmediateBox
import soot.jimple.internal.JInstanceFieldRef
import soot.jimple.internal.JVirtualInvokeExpr
import soot.jimple.internal.JimpleLocal
import soot.jimple.spark.SparkTransformer
import soot.options.Options
import soot.jimple.ReturnVoidStmt
import soot.jimple.IdentityStmt
import java.util.*
import kotlin.collections.HashSet


object SootTool {

    lateinit var OBJECT: SootClass

    /*
    In fact we don'local need to build whole program call graph, as we can perform cha algorithm when we need to resolve a
    virtual call.
    Building whole program call graph need to set the entry points which isIn all the service helper public class.
     */
    fun initSootCallGraph(class_path: String, load_path: String, useSpark: Boolean = false) {
        soot.G.reset()
        Options.v().set_allow_phantom_refs(true)
        Options.v().set_whole_program(true)
        Options.v().set_src_prec(Options.src_prec_class)
        Options.v().set_process_dir(arrayListOf(load_path))
        Options.v().set_soot_classpath(class_path)
        Options.v().set_keep_line_number(true)
        Options.v().set_output_format(Options.output_format_jimple)
        Options.v().set_validate(false)
        Options.v().set_no_bodies_for_excluded(true)
        // use cha callgraph
        var args = arrayOf("-p", "cg", "enabled:true", "-p", "cg.cha", "enabled:true")
        if (useSpark) { // build spark callgraph in special options
            args = arrayOf("-p", "cg", "enabled:true", "-p", "cg.spark", "enabled:true")
        }
        Options.v().parse(args)
//        Options.v().parse(args)
        Scene.v().loadNecessaryClasses()
        OBJECT = Scene.v().getSootClass("java.lang.Object")
        PackManager.v().runPacks()
//        println(Scene.v().callGraph)
//        println(Scene.v().entryPoints)
    }


    private fun generateSparkCallGraph() {
        val opt = HashMap<String, String>()
        opt.put("verbose", "false")
        opt.put("propagator", "worklist") //worklist
        opt.put("simple-edges-bidirectional", "true")
        opt.put("on-fly-cg", "true")
        opt.put("set-impl", "double")
        opt.put("double-set-old", "hybrid")
        opt.put("double-set-new", "hybrid")
        opt.put("dump-html", "false")
        opt.put("dump-pag", "false")
        opt.put("string-constants", "false")
        SparkTransformer.v().transform("Spark", opt)
//        SparkTransformer.v().transform()
    }

    // only load class, do not need to run packs
    fun initSootSimply(class_path: String, load_path: String) {
        soot.G.reset()
        Options.v().set_allow_phantom_refs(true)
//        Options.v().set_whole_program(true) // we do not use whole program call graph
        Options.v().set_src_prec(Options.src_prec_class)
        Options.v().set_process_dir(arrayListOf(load_path))
//        Options.v().set_soot_classpath(class_path) // In fact we don'local need jce.jar rt.jar.
        Options.v().set_keep_line_number(true)
        Options.v().set_output_format(Options.output_format_jimple)
        Options.v().set_validate(false)
        Options.v().set_no_bodies_for_excluded(true)
        Options.v().setPhaseOption("jb", "use-original-names:true")
        val args = arrayOf("-p", "cg", "enabled:false", "-p", "cg.cha", "enabled:false")
        Options.v().parse(args)
        Scene.v().loadNecessaryClasses()
        OBJECT = Scene.v().getSootClass("java.lang.Object")
//        initSootCallGraph(class_path, load_path, true)
//        PackManager.v().runPacks()
    }

    //--------------------------------------------------------------------------
    // Soot debug functions
    //-------------------------------------------------------------------------

    fun printSootClasses() {
        println("****************PrintSootClasses List****************")
        val classes = soot.Scene.v().applicationClasses
        for (sc in classes) {
            val isPhantom = if (sc.isPhantomClass) "Is PhantomClass" else "Not PhantomClass"
            println(String.format("%-100s %s", "PrintSootClasses: $sc", isPhantom))
        }
        println("**************End PrintSootClasses: " + classes.size + "***************")
    }


    fun dumpClass(name: String) {
        if (!Scene.v().containsClass(name)) {
            println("Soot can not find class: $name")
            return
        }
        val sc = Scene.v().getSootClass(name)
        dumpClass(sc)
    }

    fun dumpClass(sc: SootClass) {
        if (!Scene.v().containsClass(sc.name)) {
            sc.setApplicationClass()
        }
        println("****************DumpSootClass Start****************")
        println("Class Name: $sc")
        println("Class Fields:")
        for (f in sc.fields) {
            println(f)
        }
        println("Class Methods:")
        for (m in sc.methods) {
            println(m.toString())
        }
        println("Sub Class:")
        val hir = Scene.v().activeHierarchy
        if (sc.isInterface) {
            println(hir.getImplementersOf(sc))
        } else {
            println(hir.getSubclassesOf(sc))
        }
        println("Super Class: ${sc.superclass} ${sc.interfaces}")
        println("****************DumpSootClass End****************")
    }

    // https://github.com/MIT-PAC/droidsafe-src/blob/master/src/main/java/droidsafe/utils/SootUtils.java
    fun isInitMethod(mtd: SootMethod): Boolean {
        return "void <clinit>()" == mtd.subSignature
    }

    fun getClsFromValue(value: Value): SootClass? {
        if (value.type is RefType) {
            val sc = value.type as RefType
            return sc.sootClass
        }
        if (value is ClassConstant) {
//            val cls = value as ClassConstant
            val ref = value.toSootType() as RefType
            return ref.sootClass
        }
        return null
    }

    fun getClsFromType(type: Type): SootClass? {
        if (type is RefType) {
            return type.sootClass
        }
        return null
    }

    fun findMethodInClass(cls: SootClass, mtd: String): SootMethod? {
        cls.methods.forEach { m ->
            val name = m.name
            if (name == mtd) {
                return m
            }
        }
        return null
    }


    fun getReturnFromMethod(mtd: SootMethod, notNull: Boolean = false): Value? {
        val b = mtd.retrieveActiveBody()
        for (expr in b.units) {
            if (expr is ReturnStmt) {
                if (notNull && expr.op.type == NullType.v()) {
                    continue
                }
//                println(expr.op)
                return expr.op
            }
        }
        return null
    }

    fun getSubClassList(sc: SootClass): List<SootClass> {
        val hir = Scene.v().activeHierarchy
        if (sc.isInterface) {
            return hir.getImplementersOf(sc)
        }
        return hir.getSubclassesOf(sc)
    }

    fun tryGetMethodBody(mtd: SootMethod): Body? {
        try {
            return mtd.retrieveActiveBody()
        } catch (ex: java.lang.Exception) { // native method or missing method
            LogNow.debug("Failed to get retrieveActiveBody of $mtd")
        }
        return null
    }

//    fun getImmediateValue(u: Value): Value {
//        println("$u ${u.javaClass}")
//        for (box in u.useBoxes) {
//            if (box is ImmediateBox) return box.value
//        }
////        JCastExpr
//        return u
//    }

    fun getExprValue(u: Value): Value {
        if (u is CastExpr) {
            for (box in u.useBoxes) {
                if (box is ImmediateBox) return box.value
            }
        } else if (u is InstanceFieldRef) {
            return u.base
        } else if (u is JimpleLocal) { // valid
            return u
        } else if (u is ParameterRef) { // ignore
            return u
        }
        LogNow.warn("Failed to extract value: $u ${u.javaClass}")
        return u
    }

    fun getRightValueParamName(u: Value): MethodParams {
        var paramName = ""
        var paramType = ""
        if (u is JInstanceFieldRef) {
//            println("Field ref ${u.field} ${u.fieldRef.javaClass} $u")
            paramName = u.field.name
            paramType = u.field.declaration
        } else if (u is JVirtualInvokeExpr) {
//            println("VirtualInvoke ${u.method.name} $u")
            paramName = u.method.name
            paramType = "virtualinvoke"
        } else if (u is JimpleLocal) {
//            println("JimpleLocal ${u.name}")
//            paramName = u.name
            LogNow.debug("We don'local need JimpleLocal here: $u")
        }
        return MethodParams(paramName, paramType)
    }

    fun checkClsContainsMethodCall(cls: SootClass, mtdName: String, clsName: String? = null): Boolean {
        for (mtd in cls.methods) {
            val body = SootTool.tryGetMethodBody(mtd)
            body?.useBoxes?.forEach { box ->
                if (box.value is InvokeExpr) {
                    val expr = box.value as InvokeExpr
                    try {
                        val curMtd = expr.method
                        val sc = curMtd.declaringClass
                        if (curMtd.name == mtdName) {
                            if (clsName != null) {
                                if (clsName == sc.name)
                                    return true
                            } else {
                                return true
                            }
                        }
                    } catch (ex: Exception) {
//                        LogNow.warn("Failed to get method of $expr")
                    }
                }
            }
        }
        return false
    }

    fun checkMtdContainsMethodCall(mtd: SootMethod, mtdName: String, clsName: String? = null): Boolean {
        val body = SootTool.tryGetMethodBody(mtd)
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val expr = box.value as InvokeExpr
                try {
                    val curMtd = expr.method
                    val sc = curMtd.declaringClass
                    if (curMtd.name == mtdName) {
                        if (clsName != null) {
                            if (clsName == sc.name)
                                return true
                        } else {
                            return true
                        }
                    }
                } catch (ex: Exception) {
//                        LogNow.warn("Failed to get method of $expr")
                }
            }
        }
        return false
    }

    fun getInvokeMtdsInMethodCall(mtd: SootMethod): List<MethodDesc> {
        val mtdList = mutableListOf<MethodDesc>()
        val body = SootTool.tryGetMethodBody(mtd)
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val expr = box.value as InvokeExpr
                val argsList = mutableListOf<MethodParams>()
                for (arg in expr.args) {
                    argsList.add(getRightValueParamName(arg))
                }
                mtdList.add(MethodDesc(expr.method.name, argsList))
            }
        }
        return mtdList
    }

    fun getInvokeMethodListInMethod(mtd: SootMethod): List<SootMethod> {
        val mtdList = mutableListOf<SootMethod>()
        val body = SootTool.tryGetMethodBody(mtd)
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val expr = box.value as InvokeExpr
                val argsList = mutableListOf<MethodParams>()
                for (arg in expr.args) {
                    argsList.add(getRightValueParamName(arg))
                }
                mtdList.add(expr.method)
            }
        }
        return mtdList
    }

    fun getInvokeExprInMethod(mtd: SootMethod, called: SootMethod): InvokeExpr? {
        val body = SootTool.tryGetMethodBody(mtd)
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val expr = box.value as InvokeExpr
                if (expr.method == called) {
                    return expr
                }
            }
        }
        return null
    }

    fun getInvokeUnitInMethod(mtd: SootMethod, called: SootMethod): Stmt? {
        val body = SootTool.tryGetMethodBody(mtd)
        body?.units?.forEach { u ->
            val stmt = u as Stmt
            if (stmt.containsInvokeExpr()) {
                val inv = stmt.invokeExpr
                if (inv.method == called) {
                    return u
                }
            }
        }
        return null
    }

    fun getInfForClass(cls: SootClass): List<SootClass> {
        val allCls = ArrayDeque<SootClass>()
        val ret = HashSet<SootClass>()
        allCls.add(cls)
        if (cls.isInterface) ret.add(cls)
        while (allCls.isNotEmpty()) {
            val cur = allCls.poll()
            if (cur == OBJECT) continue
//            println("analysis $cur ${cur.isConcrete} ${cur.interfaces} ${cur.superclass}")
            if (cur.superclass != OBJECT)
                allCls.add(cur.superclass)

            allCls.addAll(cur.interfaces)
            ret.addAll(cur.interfaces)
        }
        return ret.toList()
    }

    // get iInterface for service helper or service impl
    fun getInfForImpl(sc: SootClass): SootClass {
        val infList = SootTool.getInfForClass(sc)
//        LogNow.info("getInfForImpl ${infList}")
        val iInterface = "android.os.IInterface"
        infList.forEach { inf ->
            inf.interfaces.forEach {
                if (it.name == iInterface) {
                    return inf
                }
            }
        }

        return sc
    }

    fun extractParamsNameInMethod(mtd: SootMethod): HashSet<String> {
        val nameSet = HashSet<String>()
        val body = SootTool.tryGetMethodBody(mtd)
//        println(body)
        body?.allUnitBoxes?.forEach { box ->
            if (box is InvokeExpr) {
                println("extractParamsNameInMethod $mtd ${box}")
//                println("${box} ${box.invokeExprBox}")
//                val name = InvokeExprParamsSolver()
            } else {

            }
//            println("not ${box.javaClass} ${box.unit.javaClass} ${box.unit}")
            println("unit ${box.javaClass} $box")
        }
        return nameSet
    }

    fun isEmptyMtd(mtd: SootMethod): Boolean {
        val activeBody = tryGetMethodBody(mtd)
        activeBody?.units?.forEach { u ->
            if (!(u is IdentityStmt || u is ReturnVoidStmt))
                return false
        }
        return true
    }

    fun getAssignTypeFromUnit(u: soot.Unit): String? {
        if (u is AssignStmt) {
            return u.rightOp.type.toString()
        }
        return null
    }

    fun unitInvokeMethod(u: soot.Unit, inv: SootMethod): Boolean {
        when (u) {
            is InvokeStmt -> {
                if (u.invokeExpr.method == inv) return true
            }
            is AssignStmt -> {
                val rightOp = u.rightOp
                if (rightOp is InvokeExpr) {
                    if (rightOp.method == inv) return true
                }
            }
        }
        return false
    }
}