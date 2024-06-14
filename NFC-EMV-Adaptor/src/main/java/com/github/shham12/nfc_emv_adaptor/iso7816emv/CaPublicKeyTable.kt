package com.github.shham12.nfc_emv_adaptor.iso7816emv

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

class CaPublicKeyTable(xmlString: String) {
    private val publicKeyList: List<CaPublicKey>

    init {
        publicKeyList = parseXmlToCaPublicKeys(xmlString)
    }

    fun getPublicKeys(): List<CaPublicKey> {
        return publicKeyList
    }

    fun findPublicKey(rid: String, index: String): CaPublicKey? {
        return publicKeyList.find { it.rid == rid && it.index == index }
    }

    private fun parseXmlToCaPublicKeys(xmlString: String): List<CaPublicKey> {
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        val xmlInput = ByteArrayInputStream(xmlString.toByteArray())
        val document = builder.parse(xmlInput)

        val publicKeyList = mutableListOf<CaPublicKey>()
        val capkElements = document.getElementsByTagName("CAPK")

        for (i in 0 until capkElements.length) {
            val element = capkElements.item(i) as Element
            val rid = element.getElementsByTagName("RID").item(0).textContent
            val index = element.getElementsByTagName("PKIndex").item(0).textContent
            val exponent = element.getElementsByTagName("Exponent").item(0).textContent
            val modulus = element.getElementsByTagName("Modulus").item(0).textContent

            val caPublicKey = CaPublicKey(rid, index, exponent, modulus)
            caPublicKey.name = "CA public key ($rid,$index)"
            publicKeyList.add(caPublicKey)
        }

        return publicKeyList
    }
}