package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import com.github.shham12.nfc_emv_adaptor.util.BytesUtils

class TransactionStatusIndicator {
    private var byte1 = 0x00.toByte()
    private var byte2 = 0x00.toByte()

    init {
        byte1 = 0x00.toByte()
        byte2 = 0x00.toByte()
    }

    fun resetValue() {
        byte1 = 0x00.toByte()
        byte2 = 0x00.toByte()
    }

    fun getValue(): ByteArray {
        return byteArrayOf(byte1, byte2)
    }

    // Byte 1 bit 8 Offline data authentication was performed
    fun setODAPerformed() {
        byte1 = BytesUtils.setBit(byte1, 7, true)
    }
    // Byte 1 bit 7 Cardholder verification was performed
    fun setCardholderVerificationPerformed() {
        byte1 = BytesUtils.setBit(byte1, 6, true)
    }
    // Byte 1 bit 6 Card risk management was performed
    fun setCardRiskManagementPerformed() {
        byte1 = BytesUtils.setBit(byte1, 5, true)
    }
    // Byte 1 bit 5 Issuer Authentication was performed
    fun setIssuerAuthenticationPerformed() {
        byte1 = BytesUtils.setBit(byte1, 4, true)
    }
    // Byte 1 bit 4 Terminal risk management was performed
    fun setTermRiskManagementPerformed() {
        byte1 = BytesUtils.setBit(byte1, 3, true)
    }
    // Byte 1 bit 3 Issuer Script processing was performed
    fun setIssuerScriptProcessingPerformed() {
        byte1 = BytesUtils.setBit(byte1, 2, true)
    }
    // Byte 1 bit 2 RFU
    // Byte 1 bit 1 RFU

    // Byte 2 bit 8 RFU
    // Byte 2 bit 7 RFU
    // Byte 2 bit 6 RFU
    // Byte 2 bit 5 RFU
    // Byte 2 bit 4 RFU
    // Byte 2 bit 3 RFU
    // Byte 2 bit 2 RFU
    // Byte 2 bit 1 RFU
}