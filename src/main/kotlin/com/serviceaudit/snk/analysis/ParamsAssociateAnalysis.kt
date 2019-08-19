package com.serviceaudit.snk.analysis

import com.beust.klaxon.Klaxon
import com.serviceaudit.snk.analysis.ParamsAssociateAnalysis.runFpGrowth
import com.serviceaudit.snk.services.MethodParams
import com.serviceaudit.snk.services.ServiceApi
import com.serviceaudit.snk.utils.LogNow
import com.serviceaudit.snk.utils.Results
import com.serviceaudit.snk.utils.SootTool
import soot.SootMethod
import soot.jimple.InvokeExpr
import java.util.*
import kotlin.collections.HashMap
import kotlin.collections.HashSet

data class AssociateMethods(var keywords: List<String>, var identityAccessMethods: List<String>, var identityEnforceMethods: List<String>)

/*
Load cache results or generate associate params data.
Use nlp (FP-Growth) approach to get the associate of the parameters.
 */
object ParamsAssociateAnalysis {

    fun runTestFPGrowth() {
        // test node
        val root = ParamsAssociateAnalysis.FpNode("pyramid", 9, null)
        root.children["eye"] = ParamsAssociateAnalysis.FpNode("eye", 12, null)
        root.children["phoenix"] = ParamsAssociateAnalysis.FpNode("phoenix", 3, null)
        root.children["eye"]!!.children["mix"] = ParamsAssociateAnalysis.FpNode("mix", 6, null)
        root.display()

        val dataSet = listOf<List<String>>(
                listOf("Cola", "Egg", "Ham"),
                listOf("Cola", "Diaper", "Beer"),
                listOf("Cola", "Diaper", "Beer", "Ham"),
                listOf("Diaper", "Beer")
        )

        val dataSet2 = listOf<List<String>>(
                listOf("r", "z", "h", "j", "p"),
                listOf("z", "y", "x", "w", "v", "u", "local", "s"),
                listOf("z"),
                listOf("r", "x", "n", "o", "s"),
                listOf("y", "r", "x", "z", "q", "local", "p"),
                listOf("y", "z", "x", "e", "q", "s", "local", "m")
        )

        val fp = FpTree(hashSetOf())
//        fp.fpGrowth(dataSet)
        fp.fpGrowth(dataSet2)
        println(fp.freqList)
    }

    class FpNode(var name: String, var freq: Int, var parent: FpNode?) {

        var nodeLink: FpNode? = null
        var children = HashMap<String, FpNode>()

        fun inc(numOccur: Int) {
            freq += numOccur
        }

        fun display(ind: Int = 0) {
            var suf = ""
            for (i in 0..(ind-1)) suf += " "
            suf += "-"
            println("$suf$name $freq")
            children.values.forEach { node ->
                node.display(ind + 1)
            }
        }

        override fun toString(): String {
            var str = "$name $freq ["
            for (node in children) {
                str += "$node, "
            }
            return "$str]"
        }
    }

    /*
    Fp-Growth implementation.
    https://en.wikipedia.org/wiki/Association_rule_learning#FP-growth_algorithm
    // https://github.com/baiyyang/FP-growth/blob/master/src/baiyyang/FPTree.java
     */
    class FpTree(val sensitiveSet: HashSet<String>) {

        val minSupport = 3
        var freqList = mutableListOf<List<String>>()

        fun fpGrowth(dataSet: List<List<String>>) {
            freqList.clear()
            mineTree(dataSet, listOf())
        }

        private fun mineTree(records: List<List<String>>, postFreqList: List<String>) {
            val headerTable = buildHeaderTable(records)
//            println(headerTable)
            val treeRoot = buildFpTree(records, headerTable)
//            println("=====================")
//            println("$records $headerTable")
//            treeRoot.display()
//            return
            if (headerTable.isEmpty()) {
                return
            }

            val data = HashMap<String, Int>()
            headerTable.forEach { t, u ->
                data[t] = u.first
            }
            var sortedData = data.toList()
            sortedData = sortedData.sortedBy { it.second }
//            sortedData = listOf(Pair("y", 3), Pair("y", 3), Pair("local", 3), Pair("r", 3), Pair("x", 4), Pair("z", 5))
            sortedData.forEach {
                val header = it.first
                val item = headerTable[it.first]!!.second!!
                val newPostPattern = LinkedList<String>()
                newPostPattern.add(header)
                newPostPattern.addAll(postFreqList)
//                println(newPostPattern)
                freqList.add(newPostPattern)
//                println(" ${sortedData} $newPostPattern Find: ${item.name} ${item.freq}")
                val newTranSet = findPrefixPath(item)
//                item.display()
//                println("newTranSet$newTranSet\n")
                mineTree(newTranSet, newPostPattern)
            }
        }


        private fun buildFpTree(records: List<List<String>>, FI: HashMap<String, Pair<Int, FpNode?>>): FpNode {
            val root = FpNode("RootNode", 0, null)
            records.forEach { items ->
                val orderedItem = sortedByFI(items.toList(), FI)
//                println("orderedItem $items $orderedItem $v $FI")
                if (orderedItem.isNotEmpty()) {
                    updateTree(orderedItem, root, FI)
//                    root.display()
                }
            }
            return root
        }

        private fun buildHeaderTable(records: List<List<String>>): HashMap<String, Pair<Int, FpNode?>> {
            val headerTable = HashMap<String, Pair<Int, FpNode?>>()
            val mp = HashMap<String, Int>()
            records.forEach { items ->
                items.forEach { it ->
                    if (!mp.containsKey(it)) {
                        var freq = 1
                        // name in sensitive set should be header
//                        if (sensitiveSet.contains(it)) {
//                           freq = 10000
//                        }
                        // make sure sensitive methods are in final results
                        if (ParamsAssociateAnalysis.checkIsSensitiveKeyword(it)) {
                            freq = 3
                        }
                        mp[it] = freq
                    } else {
                        mp[it] = mp[it]!! + 1
                    }
                }
            }
            mp.forEach{ k, v ->
                if (v >= minSupport) {
                    headerTable[k] = Pair<Int, FpNode?>(v, null)
                }
            }
//            println(headerTable)
            return headerTable
        }

        private fun sortedByFI(items: List<String>, FI: HashMap<String, Pair<Int, FpNode?>>): LinkedList<String> {
            val mp = HashMap<String, Int>()
            for (it in items) {
                if (FI.containsKey(it)) {
                    mp[it] = FI[it]!!.first
                }
            }
            var data = mp.toList()
            //println("Before $data")
            data = data.sortedByDescending { it.second }
//            println("Soted $data ${data.reversed()}")
            val ret = LinkedList<String>()
            data.forEach { it ->
                ret.add(it.first)
            }
            return ret
        }

        private fun findPrefixPath(node: FpNode): List<List<String>> {
            val condPats = mutableListOf<MutableList<String>>()
            var backNode: FpNode? = node
//            println("node count: ${node.name} ${node.freq}")
            while (backNode != null) {
                val prefixPath = mutableListOf<String>()
                var leafNode = backNode.parent!!
                while (leafNode.parent != null) {
//                    println("$backNode add $leafNode")
                    var cnt = backNode.freq
                    while (cnt-- > 0) {
                        prefixPath.add(leafNode.name)
                    }
                    leafNode = leafNode.parent!!
                }
//                println("condPats $prefixPath ${backNode.name} ${backNode.freq}")

//                condPats[prefixPath] = backNode.freq
                condPats.add(prefixPath)
//                println("backnode $backNode ${backNode.nodeLink}")
                backNode = backNode.nodeLink
            }
            return condPats
        }

        private fun updateTree(orderedItem: LinkedList<String>, inTree: FpNode, FI: HashMap<String, Pair<Int, FpNode?>>) {
            val name = orderedItem.pollFirst()
            if (inTree.children.containsKey(name)) {
                inTree.children[name]!!.freq += 1
            } else {
                val child = FpNode(name, 1, inTree)
                inTree.children[name] = child
                if (FI[name]!!.second == null) {
                    FI[name] = Pair<Int, FpNode?>(FI[name]!!.first, child)
//                    println("reset $name ${FI[name]}")
                } else {
                    var tmp = FI[name]!!.second!!
                    while (tmp.nodeLink != null) {
                        tmp = tmp.nodeLink!!
                    }
                    tmp.nodeLink = child
                }
            }
            if (orderedItem.isNotEmpty()) {
//                println("updateTree $orderedItem")
                updateTree(orderedItem, inTree.children[name]!!, FI)
            }
        }

        private fun addNodes(parent: FpNode, record: LinkedList<String>, FI: List<FpNode>) {
            if (record.isEmpty()) return
            while (record.isNotEmpty()) {
                val item = record.poll()
                val leafNode = FpNode(item, 1, parent)
                parent.children[item] = leafNode

                FI.forEach { FI ->
                    if (FI.name == item) {
                        var cur = FI
                        if (cur.nodeLink != null) {
                            cur = cur.nodeLink!!
                        }
                        cur.nodeLink = leafNode
                    }
                }

                addNodes(leafNode, record, FI)
            }
        }
    }

    class Keyword(var name: String) {

        fun isIn(tag: String): Boolean {
            val lowerCase = tag.toLowerCase()
            return lowerCase.contains(name)
        }

        override fun hashCode(): Int {
            return name.hashCode()
        }

        override fun equals(other: Any?): Boolean {
            if (other is Keyword) {
                return other.name == name
            } else if (other is String) {
                return other == name
            }
            return super.equals(other)
        }

        override fun toString(): String {
            return name
        }
    }

    val containKeywords = HashSet<Keyword>()
    val startWithKeywords = HashSet<Keyword>()
    val identityAccessingKeywords = HashSet<Keyword>()
    val identityEnforceKeywords = HashSet<Keyword>()
    val pkgKeywordsSet = HashSet<Keyword>()
    val uidKeywordsSet = HashSet<Keyword>()
    val permissionKeywordSet = HashSet<Keyword>()

    val singleWords = hashSetOf<String>("myUserId")


    // summary the results of fp-growth


    val combinedKeywords = hashMapOf<String, HashSet<String>>(
            "params checking1" to hashSetOf("check", "params"),
//            "params checking2" to hashSetOf("check", "param"),
            "enforce package" to hashSetOf("enforce", "Package")
//            "enforce package" to hashSetOf("check", "Package")
    )

    val permissionEnforceApi = hashSetOf("enforceAccessPermission", "enforceCallingOrSelfPermission")

    val sensitiveApiMatch = hashMapOf<String, HashSet<String>>(
            "identity checking" to hashSetOf("uid", "pid", "gid", "ppid", "getPackageName", "getOpPackageName"),
//            "params checking" to hashSetOf("param", "params"),
//            "access checking" to hashSetOf("access"),
            "enforcement" to hashSetOf("enforce")
        )

    init {
        val keywords = listOf("userid", "uid", "pid", "identity", "package", "enforce", "permission")
        keywords.forEach { w ->
            containKeywords.add(Keyword(w))
        }
        startWithKeywords.add(Keyword("check"))
    }

    fun checkIsSensitiveKeyword(name: String): Boolean {
        for (key in containKeywords) {
            if (key.isIn(name)) {
                return true
            }
        }

        for (key in startWithKeywords) {
            if (name.startsWith(key.name)) return true
        }
        return false
    }

    fun extractInvokedInMethodBody(sm: SootMethod, mtd: HashSet<SootMethod>,  lev: Int = 3) {
        if (lev <= 0) return
        // level 1
        val body = SootTool.tryGetMethodBody(sm)
        body?.useBoxes?.forEach { box ->
            if (box.value is InvokeExpr) {
                val expr = box.value as InvokeExpr
                try {
                    val curMtd = expr.method
                    mtd.add(curMtd)
                    // check next level
                    extractInvokedInMethodBody(curMtd, mtd, lev - 1)
                } catch (ex: Exception) {
                }
            }
        }
    }

    fun splitWord(name: String): List<String> {
        val ret = mutableListOf<String>()
        var pos = 0
        val last = name.length - 1
        var upCase = true
        for (i in 0..last) {
            if (!upCase && name[i].isUpperCase()) {
                val word = name.subSequence(pos, i).toString().toLowerCase()
                ret.add(word)
                pos = i
            }
            upCase = name[i].isUpperCase()
        }
        val word = name.subSequence(pos, name.length).toString().toLowerCase()
        ret.add(word)
        return ret
    }

    fun sensitiveParamsAnalysis(params: List<MethodParams>?): String {
        if (params == null) return ""

        return ""
    }

    fun isPermissionCheckingApi(name: String): Boolean {
        return permissionEnforceApi.contains(name)
    }

    fun methodWordSynonymsAnalysis(name: String): String {
        singleWords.forEach { word ->
            if (name.contains(word)) return "Identify Checking: $word"
        }
        for (item in sensitiveApiMatch) {
            val checking = item.value
            if (checking.contains(name)) {
                return "${item.key}: $name"
            }
        }

        val words = splitWord(name)
        val wordsSet = hashSetOf<String>()
//        println("$name $words")
        for (w in words) {
            wordsSet.add(w)
        }
        var isCheckingApi = true
        for (item in combinedKeywords) {
            val checking = item.value
            for (part in checking) {
                if (!wordsSet.contains(part)) {
                    isCheckingApi = false
                }
            }
            if (isCheckingApi) {
                return "${item.key}: $name"
            }
        }

        return ""
    }

    private fun saveAssociateResults(associateParams: Map<String, HashSet<Keyword>>) {
        val keywords = associateParams.keys.toList()
        val accessing = hashSetOf("get")
        val enforce = hashSetOf("enforce", "check")
        val accessingList = hashSetOf<String>()
        val enforceList = hashSetOf<String>()
        // word similar analysis
        associateParams.forEach { t, u ->
            u.forEach l1@{ w ->
                for (k in accessing) {
                    if (w.name.startsWith(k)) {
                        accessingList.add(w.toString())
                        return@l1
                    }
                }

                for (k in enforce) {
                    if (w.name.startsWith(k)) {
                        enforceList.add(w.toString())
                        return@l1
                    }
                }
            }
        }
        val data = AssociateMethods(keywords, accessingList.toList(), enforceList.toList())
        val json = Klaxon().toJsonString(data)
        Results.saveResult(json, Results.ASSOCIATE_METHODS)
    }

    fun runFpGrowth(dataSet: List<List<String>>) {
        val fpTree = FpTree(hashSetOf())
        fpTree.fpGrowth(dataSet)
//        fpTree.freqList.forEach { f ->
//            println(f)
//        }
        // filter results
        val associateParams = mutableMapOf<String, HashSet<Keyword>>()
        fpTree.freqList.forEach { items ->
            items.forEach { w ->
                for (key in containKeywords) {
                    val ks = key.name
                    if (key.isIn(w)) {
                        if (!associateParams.containsKey(ks)) {
                            associateParams[ks] = hashSetOf()
                        }
                        associateParams[ks]!!.add(Keyword(w))
                    }
                }
            }
        }
        LogNow.show("Associate Rules Mining Results:")
        associateParams.forEach{ t, u ->
            LogNow.show("Keyword: $t ->")
            u.forEach { w ->
                LogNow.show("\t$w")
            }
        }
        saveAssociateResults(associateParams)
    }

}

fun runNlpApproach(api: ServiceApi) {
//    runTestFPGrowth()
    if (api.entryPointMethodSet.isEmpty()) {
        api.associateServiceMethods()
    }

    val excludeSet = hashSetOf("<init>")
    val paramsList = mutableListOf<MutableList<String>>()
    api.entryPointMethodSet.forEach { call ->
        var add = false
        var record = mutableListOf<String>()
        // add helper call chain
        for (m in call.mtdDesc.keys) {
            if (excludeSet.contains(m.name)) {
                add = false
                break
            }
            if (ParamsAssociateAnalysis.checkIsSensitiveKeyword(m.name)) {
                add = true
            }
            record.add(m.name)
        }
        if (add) {
//            println("record $record")
            paramsList.add(record)
        }

        // add impl methods calls
        add = false
        if (call.implMethod != null) {
            record = mutableListOf<String>()
            val mtd = hashSetOf<SootMethod>()
            ParamsAssociateAnalysis.extractInvokedInMethodBody(call.implMethod!!, mtd)
            for (m in mtd) {
                if (excludeSet.contains(m.name)) {
                    add = false
                    break
                }

                record.add(m.name)

                if (ParamsAssociateAnalysis.checkIsSensitiveKeyword(m.name)) {
//                    println(m.name)
                    add = true
                }
            }
            if (add) {
//                println("record $record")
                paramsList.add(record)
            }
        }
    }
//    println("${paramsList.size}")
    runFpGrowth(paramsList)
//    DebugTool.exitHere()
}
