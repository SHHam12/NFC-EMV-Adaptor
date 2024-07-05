package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import com.github.shham12.nfc_emv_adaptor.util.BytesUtils

class TerminalInterchangeProfile {
    private var byte1 = 0x00.toByte()
    private var byte2 = 0x00.toByte()
    private var byte3 = 0x00.toByte()

    init {
        byte1 = 0x50.toByte() // Support Signature & Device CVM
        byte2 = 0x00.toByte()
        byte3 = 0x00.toByte()
    }

    fun getValue(): ByteArray {
        return byteArrayOf(byte1, byte2, byte3)
    }

    // Byte 1 bit 8 CVM required by reader / N/A
    fun setCVMRequired() {
        byte1 = BytesUtils.setBit(byte1, 7, true)
    }
    // Byte 1 bit 7 Signature supported
    // Byte 1 bit 6 Online PIN supported
    // Byte 1 bit 5 On-Device CVM supported
    // Byte 1 bit 4 RFU
    // Byte 1 bit 3 Reader is a Transit Reader
    // Byte 1 bit 2 EMV contact chip supported
    // Byte 1 bit 1 (Contact Chip) Offline PIN supported

    // Byte 2 bit 8 Issuer Update supported
    // Byte 2 bit 7 ~ 1 RFU

    // Byte 3 bit 8 ~ 1 RFU
}