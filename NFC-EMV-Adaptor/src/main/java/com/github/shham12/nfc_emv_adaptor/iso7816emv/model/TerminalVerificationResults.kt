package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import com.github.shham12.nfc_emv_adaptor.util.BytesUtils

class TerminalVerificationResults {
    private var byte1 = 0x00.toByte()
    private var byte2 = 0x00.toByte()
    private var byte3 = 0x00.toByte()
    private var byte4 = 0x00.toByte()
    private var byte5 = 0x00.toByte()

    init {
        byte1 = 0x00.toByte()
        byte2 = 0x00.toByte()
        byte3 = 0x00.toByte()
        byte4 = 0x00.toByte()
        byte5 = 0x00.toByte()
    }

    fun resetValue() {
        byte1 = 0x00.toByte()
        byte2 = 0x00.toByte()
        byte3 = 0x00.toByte()
        byte4 = 0x00.toByte()
        byte5 = 0x00.toByte()
    }

    fun getValue(): ByteArray {
        return byteArrayOf(byte1, byte2, byte3, byte4, byte5)
    }

    // Byte 1 bit 8 Offline data authentication was not performed
    fun setODANotPerformed() {
        byte1 = BytesUtils.setBit(byte1, 7, true)
    }
    // Byte 1 bit 7 SDA failed
    fun setSDAFailed() {
        byte1 = BytesUtils.setBit(byte1, 6, true)
    }
    // Byte 1 bit 6 ICC data missing
    fun setICCDataMissing() {
        byte1 = BytesUtils.setBit(byte1, 5, true)
    }
    // Byte 1 bit 5 Card appears on terminal exception file

    // Byte 1 bit 4 DDA failed
    fun setDDAFailed() {
        byte1 = BytesUtils.setBit(byte1, 3, true)
    }
    // Byte 1 bit 3 CDA failed
    fun setCDAFailed() {
        byte1 = BytesUtils.setBit(byte1, 2, true)
    }
    // Byte 1 bit 2 SDA selected
    fun setSDASelected() {
        byte1 = BytesUtils.setBit(byte1, 1, true)
    }
    // Byte 1 bit 1 RFU

    // Byte 2 bit 8 ICC and terminal have different application versions
    fun checkAppVerNum(pCardAppVer: ByteArray?, pTermAppVer: ByteArray?) {
        if (pCardAppVer != null && pTermAppVer != null) {
            if (!pCardAppVer.contentEquals(pTermAppVer))
                byte2 = BytesUtils.setBit(byte2, 7, true)
        }
    }

    // Byte 2 bit 7 Expired application
    fun checkExpirationDate(pTransDate: ByteArray, pExpireDate: ByteArray?) {
        if (pExpireDate != null) {
            if (BytesUtils.compareDateByteArrays(pTransDate, pExpireDate) > 0)
                byte2 = BytesUtils.setBit(byte2, 6, true)
        }
    }
    // Byte 2 bit 6 Application not yet effective
    fun checkEffectiveDate(pTransDate: ByteArray, pEffectiveDate: ByteArray?) {
        if (pEffectiveDate != null) {
            if (BytesUtils.compareDateByteArrays(pTransDate, pEffectiveDate) < 0)
                byte2 = BytesUtils.setBit(byte2, 5, true)
        }
    }
    // Byte 2 bit 5 Service not allowed for card product
    fun checkAUC(pAUC :ByteArray?, pCardCountry: ByteArray?, pTermCountry: ByteArray) {
        if (pAUC != null && pCardCountry != null){
            // For now only support  0x00 goods
            if (pCardCountry.contentEquals(pTermCountry)) {
                if (!BytesUtils.matchBitByBitIndex(pAUC[0], 5))
                    byte2 = BytesUtils.setBit(byte2, 4, true)
            } else {
                if (!BytesUtils.matchBitByBitIndex(pAUC[0], 4))
                    byte2 = BytesUtils.setBit(byte2, 4, true)
            }
        }
    }

    // Byte 2 bit 4 New card
    // Byte 2 bit 3 RFU
    // Byte 2 bit 2 RFU
    // Byte 2 bit 1 RFU

    // Byte 3 bit 8 Cardholder verification was not successful
    fun setCardholderVerificationFailed() {
        byte3 = BytesUtils.setBit(byte3, 7, true)
    }
    // Byte 3 bit 7 Unrecognized CVM
    // Byte 3 bit 6 PIN Try Limit exceeded
    // Byte 3 bit 5 PIN entry required and PIN pad not present or not working
    // Byte 3 bit 4 PIN entry required, PIN pad present, but PIN was not entered
    // Byte 3 bit 3 Online PIN entered
    // Byte 3 bit 2 RFU
    // Byte 3 bit 1 RFUs

    // Byte 4 bit 8 Transaction exceeds floor limit
    fun setFloorLimitExceed() {
        byte4 = BytesUtils.setBit(byte4, 7, true)
    }
    // Byte 4 bit 7 Lower consecutive offline limit exceeded
    // Byte 4 bit 6 Upper consecutive offline limit exceeded
    // Byte 4 bit 5 Transaction selected randomly for online processing
    // Byte 4 bit 4 Merchant forced transaction online
    // Byte 4 bit 3 RFU
    // Byte 4 bit 2 RFU
    // Byte 4 bit 1 RFU

    // Byte 5 bit 8 Default TDOL used
    // Byte 5 bit 7 Issuer authentication failed
    fun setIssuerAuthenticationFailed() {
        byte5 = BytesUtils.setBit(byte5, 6, true)
    }
    // Byte 5 bit 6 Script processing failed before final GENERATE AC
    // Byte 5 bit 5 Script processing failed after final GENERATE AC
    // Byte 5 bit 4 Relay resistance threshold exceeded
    // Byte 5 bit 3 Relay resistance time limits exceeded
    // Byte 5 bit 2 Relay resistance time limits exceeded
    // Byte 5 bit 1 Relay resistance time limits exceeded


}