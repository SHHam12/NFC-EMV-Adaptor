package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import com.github.shham12.nfc_emv_adaptor.exception.TLVException
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.containsSequence
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray
import com.google.gson.Gson
import com.google.gson.JsonArray


class Configuration {
    private val emvData: MutableMap<String, MutableMap<String, ByteArray>> = mutableMapOf()

    private lateinit var selectedAID: String

    private val mastercard = "A000000004" // For Kernel 2

    private val visa = "A000000003" // For Kernel 3

    private val amex = "A000000025" // For Kernel 4

    private val jcb = "A000000065" // For Kernel 5

    private val discover = "A000000152" // For Kernel 6

    init {
        val defaultAIDs = listOf(
            "A0000000031010",   // VISA Debit/Credit
            "A0000000032010",   // VISA Electron
            "A0000000033010",   // VISA Interlink
            "A0000000041010",   // MasterCard Debit/Credit
            "A0000000042203",   // US Maestro
            "A0000000043060",   // Maestro Debit
            "A00000002501",     // American Express
            "A00000002504",     // American Express Debit
            "A0000000651010",   // JCB
            "A0000000980840",   // VISA Common Debit
            "A0000001523010",   // Discover
            "A0000001524010",   // Discover Common Debit
            "A0000003330101"    // Union Pay will cover A000000333010101, A000000333010102, A000000333010103, A000000333010106, A000000333010108
        )

        defaultAIDs.forEach { aid ->
            emvData[aid] = mutableMapOf(
                "9C" to "00".toByteArray(), // 0x00: Goods/ Service, 0x09: CashBack, 0x01: Cash, 0x20: Refund, 0x30: Balance Inquiry

                "9F33" to "8028C8".toByteArray(),           // Terminal Capability
                "9F40" to "E0C8E06400".toByteArray(),       // Additional Terminal Capability
                "9F35" to "22".toByteArray(),               // Terminal Type

                "9F1A" to "0840".toByteArray(),             // Terminal Country Type
                "5F2A" to "0840".toByteArray(),             // Transaction Currency Code

                "9F4E" to "4E464320454D562041646170746F72".toByteArray(),  // Merchant Name & Location
                "9F15" to "5331".toByteArray(),             // Merchant Category Code set 5331 Variety Store as default

                "DF11" to "0000000000".toByteArray(),       // Terminal Action Code Default
                "DF12" to "0000000000".toByteArray(),       // Terminal Action Code Online
                "DF13" to "0000000000".toByteArray(),       // Terminal Action Code Denial

                "DF19" to "000000000000".toByteArray(),     // Terminal Contactless Offline floor limit
                "DF20" to "999999999999".toByteArray(),     // Terminal Contactless Transaction limit
                "DF21" to "000000001000".toByteArray(),     // Terminal Contactless CVM limit
            )
            if (aid.toByteArray().containsSequence("A000000025".toByteArray())) { // Kernel 4
                emvData[aid]?.put("9F6D", "C0".toByteArray()) // CVM Required 0XC8 CVM Not Required 0XC0
                emvData[aid]?.put("9F6E", "D8004000".toByteArray()) // Amex Enhanced Contactless Reader Capabilities
            } else if (aid.toByteArray().containsSequence("A000000003".toByteArray())
                || aid.contentEquals("A0000000980840")) { // Kernel 3
                emvData[aid]?.put("9F66", "22C04000".toByteArray())
            } else if (aid.toByteArray().containsSequence("A000000152".toByteArray())) { // Kernel 6
                emvData[aid]?.put("9F66", "22C04000".toByteArray())
            } else if (aid.toByteArray().containsSequence("A000000065".toByteArray())) { // kernel 7
                emvData[aid]?.put("9F66", "62C04000".toByteArray())
            } else if (aid.toByteArray().containsSequence("A000000004".toByteArray())) {
                emvData[aid]?.put("9F1D", "A980800000000000".toByteArray())
                emvData[aid]?.put("DF8117", "80".toByteArray())
                emvData[aid]?.put("DF8118", "20".toByteArray())
                emvData[aid]?.put("DF8119", "08".toByteArray())
                emvData[aid]?.put("DF811B", "80".toByteArray())
                emvData[aid]?.put("DF811F", "C8".toByteArray())
                emvData[aid]?.put("DF8120", emvData[aid]?.get("DF11")!!)
                emvData[aid]?.put("DF8121", emvData[aid]?.get("DF13")!!)
                emvData[aid]?.put("DF8122", emvData[aid]?.get("DF12")!!)
            }
        }
    }

    fun updateOrInsert(pAid: String, pTag: String, pValue: ByteArray) {
        emvData.getOrPut(pAid) { mutableMapOf() }[pTag] = pValue
    }

    fun getValue(pAid: String, pTag: String): ByteArray? {
        return emvData[pAid]?.get(pTag)
    }

    fun getAllData(): Map<String, Map<String, ByteArray>> = emvData

    private fun setAID(pAid: ByteArray) {
        val aid = bytesToString(pAid).uppercase()
        selectedAID = when {
            aid.startsWith("A00000002501") -> "A00000002501"
            aid.startsWith("A00000002504") -> "A00000002504"
            aid.startsWith("A0000003330101") -> "A0000003330101"
            aid.startsWith("A0000000031010") -> "A0000000031010"
            aid.startsWith("A0000000033010") -> "A0000000033010"
            aid.startsWith("A0000000041010") -> "A0000000041010"
            aid.startsWith("A0000000042203") -> "A0000000042203"
            aid.startsWith("A0000000043060") -> "A0000000043060"
            aid.startsWith("A0000000651010") -> "A0000000651010"
            aid.startsWith("A0000000980840") -> "A0000000980840"
            aid.startsWith("A0000001523010") -> "A0000001523010"
            aid.startsWith("A0000001524010") -> "A0000001524010"
            else -> aid
        }
    }

    fun loadAID(pAid: ByteArray): Map<String, ByteArray> {
        setAID(pAid)
        return emvData[selectedAID] ?: throw TLVException("Declined (Not support AID: $selectedAID)")
    }

    fun getSelectedAID(): String = selectedAID

    fun isExceedCVMLimit(pAmount: ByteArray): Boolean {
        return emvData[selectedAID]?.get("DF20")?.let {
            BytesUtils.compareByteArrays(pAmount, it) > 0
        } ?: throw TLVException("Declined (Not support AID: $selectedAID)")
    }

    fun isExceedFloorLimit(pAmount: ByteArray): Boolean {
        return emvData[selectedAID]?.get("DF19")?.let {
            BytesUtils.compareByteArrays(pAmount, it) > 0
        } ?: throw TLVException("Declined (Not support AID: $selectedAID)")
    }

    fun isKernel2(): Boolean = selectedAID.startsWith(mastercard)
    fun isKernel3(): Boolean = selectedAID.startsWith(visa) || selectedAID == "A0000000980840"
    fun isKernel4(): Boolean = selectedAID.startsWith(amex)
    fun isKernel5(): Boolean = selectedAID.startsWith(jcb)
    fun isKernel6(): Boolean = selectedAID.startsWith(discover)

    fun isKernel2SupportCVM(pTag: String, pBit: Int): Boolean{
        // bit 8: Plain Offline PIN
        // bit 7: Encrypted Online PIN
        // bit 6: Sign
        // bit 5: Encrypted Offline PIN
        // bit 4: NO CVM
        var isSupport = false
        // Use DF8118 and DF8119 at this moment
        val tagValue = emvData[selectedAID]?.get(pTag)
        tagValue?.let {
            isSupport = BytesUtils.matchBitByBitIndex(it[0], pBit)
        }
        return isSupport
    }

    fun setConfiguration(pAIDsJSON: String) {
        val emvTagPattern = Regex("^[0-9A-Fa-f]{2,6}$")

        val gson = Gson()

        val aidsFromJson = mutableSetOf<String>()

        try {
            // Parse the JSON string into a JsonArray
            val jsonArray: JsonArray = gson.fromJson(pAIDsJSON, JsonArray::class.java)

            // Iterate over each element in the JsonArray
            for (jsonElement in jsonArray) {
                val jsonObject = jsonElement.asJsonObject
                val aid = jsonObject.get("9F06")?.asString.orEmpty()

                if (aid.isNotEmpty()) {
                    aidsFromJson.add(aid)
                    emvData.remove(aid)
                    // Iterate over each entry in the JsonObject
                    for ((key, value) in jsonObject.entrySet()) {
                        // Skip processing if the key is "9F06"
                        if (key == "9F06") continue

                        if (key.matches(emvTagPattern)) {
                            val stringValue = value.asString
                            val byteArray = stringValue.toByteArray()

                            if (byteArray.isNotEmpty()) {
                                updateOrInsert(aid, key, byteArray)
                            }
                        }
                    }
                }
            }

            val keysToRemove = emvData.keys.filter { it !in aidsFromJson }
            keysToRemove.forEach { aid ->
                emvData.remove(aid)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}