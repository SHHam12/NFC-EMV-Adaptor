package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu


class APDUResponse(response: ByteArray) {
    private val responseData: ByteArray
    private val sw1: Byte
    private val sw2: Byte

    init {
        // Assuming the last two bytes are SW1 and SW2
        val responseLength = response.size
        if (responseLength < 2) {
            throw IllegalArgumentException("Invalid APDU response length")
        }

        sw1 = response[responseLength - 2]
        sw2 = response[responseLength - 1]
        responseData = response.copyOfRange(0, responseLength - 2)
    }

    fun isSuccess(): Boolean {
        return sw1 == 0x90.toByte() && sw2 == 0x00.toByte()
    }

    fun isInvalidated(): Boolean {
        return sw1 == 0x69.toByte() && sw2 == 0x84.toByte()
    }

    fun toBytes(): ByteArray {
        return responseData + sw1 + sw2
    }

    fun getData(): ByteArray {
        return responseData
    }
}

