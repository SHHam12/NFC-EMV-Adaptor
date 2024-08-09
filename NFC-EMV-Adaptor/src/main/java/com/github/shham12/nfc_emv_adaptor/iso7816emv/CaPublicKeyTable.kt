package com.github.shham12.nfc_emv_adaptor.iso7816emv

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken

class CaPublicKeyTable(pJSONString: String) {
    private val publicKeyList: List<CaPublicKey>

    init {
        publicKeyList = parseJsonToCaPublicKeys(pJSONString)
    }

    fun getPublicKeys(): List<CaPublicKey> {
        return publicKeyList
    }

    fun findPublicKey(rid: String, index: String): CaPublicKey? {
        return publicKeyList.find { it.rid == rid && it.index == index }
    }

    private fun parseJsonToCaPublicKeys(pJSONString: String): List<CaPublicKey> {
        val gson = GsonBuilder()
            .excludeFieldsWithoutExposeAnnotation()  // 필드에 @Expose 어노테이션이 없는 경우 제외
            .create()
        val type = object : TypeToken<List<CaPublicKey>>() {}.type
        val publicKeyList: List<CaPublicKey> = gson.fromJson(pJSONString, type)

        publicKeyList.forEach { it.name = "CA public key (${it.rid},${it.index})" }

        return publicKeyList
    }
}