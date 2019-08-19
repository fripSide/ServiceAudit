package com.serviceaudit.snk.services

import com.serviceaudit.snk.utils.DebugTool
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.SootTool
import soot.RefType
import soot.Scene
import soot.SootClass
import soot.SootMethod

// Resolve the service impl which is used by service helper class.
/*
Find service impl usages in service helper class.
 */
object ServiceImplResolver {

    private val kBinderCls = "android.os.Binder"

    // service Impl identify api
    private val kServiceImplInterface = "android.os.IInterface"
    private val kServiceImplRegister1 = "publishBinderService"
    private val kServiceImplCls = "ServiceManager"
    private val kServiceImplMtd = "addService"

    private var implList = HashSet<SootClass>()
    private var iInterfaceList = HashSet<SootClass>()

    private var kExcludeInterfaceSet = hashSetOf<String>("android.os.IMessenger", "android.content.IContentProvider")

    /*
    Some
     */
    fun searchFromServiceRegister() {

    }

    /*
    Extract the service impl class used by the service helper and process all the corner cases here.
    A service impl class is the real implement for Service which implements the interface of the Service.aidl .
    eg. ActivityManagerNative extends Binder implements IActivityManager
     */
    fun searchServiceImplClass(helperCls: SootClass): List<SootClass> {
        implList.clear()
        // ImplClass is a filed of current class or a field of the its class fields
        searchInFields(helperCls)
        // ImplClass is used as a Singleton class and do not save as a field in current class
        searchInMethods(helperCls)

        return implList.toList()
    }

    /*
        Only search fields or methods
     */
    fun searchImplInterface(cls: SootClass): List<SootClass> {
        iInterfaceList.clear()
        cls.fields.forEach { fi ->
            val sc = SootTool.getClsFromType(fi.type)
            if (sc != null) {
                if (checkIsIInterface(sc)) {
                    if (cls != sc && !kExcludeInterfaceSet.contains(sc.name)) {
                        iInterfaceList.add(sc)
                    }
                }
            }
        }
        return iInterfaceList.toList()
    }

    // search n-level fields to find stub class
    private fun searchInFields(sc: SootClass, lev: Int = 2) {
        if (lev <= 0) return
        sc.fields.forEach { fi ->
            if (fi.type is RefType) {
                val ref = fi.type as RefType
                val cls = ref.sootClass
//                checkAndGetServiceImplStubClassRaw(cls)
                checkAndGetServiceImplStubClass(cls)
                // search in lower level class fields
                searchInFields(cls, lev - 1)
            }
        }
    }

    private fun checkIsIInterface(cls: SootClass): Boolean {
        if (!cls.isInterface) return false
        var isIInterface = false
        for (inf in cls.interfaces) {
            if (inf.name == kServiceImplInterface) {
                isIInterface = true
                break
            }
        }
        return isIInterface
    }

    /*
        Find stub class for IInterface and Binder
        @params sc, Service Interface Class
        @return Service Impl Stub
     */
    private fun checkAndGetServiceImplStubClass(sc: SootClass): Boolean {
//        val focusCls = "android.content.IContentService"
//        if (sc.name == focusCls) println("Search: $focusCls")
//        if (sc.name != focusCls) return false

        if (!checkIsIInterface(sc)) return false
        iInterfaceList.add(sc)
//        println("checkAndGetServiceImplStubClass $sc")

        var find = false
        // the target Impl (abstract/interface/concrete) class should extends IBinder and implements current Interface
        val hir = Scene.v().activeHierarchy
        val subList = hir.getImplementersOf(sc)
        for (sub in subList) {
            val supCls = sub.superclass
//            LogNow.info("$sub ${supCls.name}")
            if (supCls.name == kBinderCls) { // current class
                if (sub.isConcrete) {
                    implList.add(sub)
//                    println("Find Class1: $sub")
                    find = true
                } else { // is the sub class of current class
                    val subClsOfImpl = SootTool.getSubClassList(sub)
                    for (subImpl in subClsOfImpl) {
                        if (subImpl.isConcrete) {
                            implList.add(subImpl)
//                            LogNow.info(subImpl.methods)
//                            println("Find Class2: $subImpl")
                            find = true
                        }
                    }
                }
            }
        }
        // add interface here
        return find
    }

    //
    private fun searchInMethods(cls: SootClass, lev: Int = 2) {
//        val name = "android.app.IActivityManager"
//        val sc = Scene.v().getSootClass(name)
////        SootTool.dumpClass(sc)
////        println(checkAndGetServiceImplStubClass((sc)))
//        SootTool.exitHere()
        if (lev <= 0) return
        cls.methods.forEach { mtd ->
            val clsList = getIInterfaceFromMethod(mtd)
            clsList.forEach { sc ->
                checkAndGetServiceImplStubClass(sc)
                searchInMethods(sc, lev - 1)
            }
        }
    }


    private fun getIInterfaceFromMethod(mtd: SootMethod): List<SootClass> {
        val clsList = mutableListOf<SootClass>()
//        println(interfaceMtd)
        return clsList
    }

    private fun checkAndGetServiceImplStubClassRaw(sc: SootClass): Boolean {
//        val focusCls = "android.content.IContentService"
//        if (sc.name == focusCls) println("Search: $focusCls")
//        if (sc.name != focusCls) return false

        if (!sc.isInterface) return false
        val hir = Scene.v().activeHierarchy
        var isIInterface = false
        for (inf in sc.interfaces) {
            if (inf.name == kServiceImplInterface) {
                isIInterface = true
                break
            }
        }
        if (!isIInterface) return false
        var find = false
        // the target Impl (abstract/interface/concrete) class should extends IBinder and implements current Interface
        val subList = hir.getImplementersOf(sc)
        for (sub in subList) {
            val supCls = sub.superclass
            if (supCls.name == kBinderCls) {
                implList.add(sub)
                find = true
            }
        }
        return find
    }
}