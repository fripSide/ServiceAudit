package com.serviceaudit.snk.services

data class VulServiceApi(val serviceApi: String, val implApi: String, var failedValidatorList: List<String>, val checkingBypass: List<String>,
                         val enforcement: List<String>, var vulType: String?, var exceptionList: List<String>?,
                         var permissionBypass: List<String>?) {
    override fun hashCode(): Int {
        return serviceApi.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other is VulServiceApi) {
            return serviceApi == other.serviceApi
        }
        return super.equals(other)
    }

}

data class VulService(val interfaceName: String, val vulApiList: HashSet<VulServiceApi>)