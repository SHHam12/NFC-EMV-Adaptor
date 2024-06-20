package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.compareByteArrays
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.compareDateByteArrays
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.containsSequence
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.matchBitByBitIndex
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.setBit
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray
import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import kotlin.experimental.or


class EMVTransactionRecord {
    private val defaultValues = mutableMapOf(
        "9F35" to "22".toByteArray(),
        "9F6E" to "D8004000".toByteArray(),
        "9F66" to "20404000".toByteArray(),
        "9F02" to "000000000001".toByteArray(),
        "9F03" to "000000000000".toByteArray(),
        "9F1A" to "0840".toByteArray(),
        "95" to "0000000000".toByteArray(),
        "5F2A" to "0840".toByteArray(),
        "9C" to "00".toByteArray(), // 0x00: Goods/ Service, 0x09: CashBack, 0x01: Cash, 0x20: Refund, 0x30: Balance Inquiry
        "9F45" to "0000".toByteArray(),
        "9F4C" to "0000".toByteArray(),
        "9F34" to "000000".toByteArray(),
        "9F40" to "E0C8E06400".toByteArray(),
        "9F1D" to "0000000000".toByteArray(),
        "9F33" to "8028C8".toByteArray(),
        "9F34" to "1F0000".toByteArray(),
        "9F4E" to "000000".toByteArray(),
        "9F6D" to "C0".toByteArray(), // CVM Required 0XC8 CVM Not Required 0XC0
        "9B" to "0000".toByteArray()
    )

    private val emvTags = mutableMapOf<String, ByteArray>()

    private val amex =
        byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x25.toByte())

    private val cvmLimit = "000000010000".toByteArray()

    private val floorLimit = "000000000000".toByteArray()

    private var exceedCVMLimit = false

    init {
        resetEmvTags()
    }

    fun clear() {
        resetEmvTags()
    }

    private fun resetEmvTags() {
        emvTags.clear()
        emvTags.putAll(defaultValues)
        setTransactionDate()
        setTransactionTime()
        setUnpredictableNumber()
        checkAndSetCVMLimit()
    }

    private fun setFloorLimitIfNeeded() {
        if (emvTags["9F02"]?.contentEquals(floorLimit) == false) {
            setFloorLimitExceed()
        }
    }

    private fun checkAndSetCVMLimit() {
        val value9F02 = emvTags["9F02"]
        if (value9F02 != null && compareByteArrays(value9F02, cvmLimit) > 0) {
            emvTags["9F6D"] = "C8".toByteArray()
            exceedCVMLimit = true
        }
    }

    fun getEMVTags(): MutableMap<String, ByteArray> {
        return emvTags
    }

    fun setAmount1(value: ByteArray) {
        emvTags["9F02"] = value
        checkAndSetCVMLimit()
    }

    fun setAmount2(value: ByteArray) {
        emvTags["9F03"] = value
    }

    fun setModifiedTerminalType() {
        emvTags["9F35"] = byteArrayOf(emvTags["9F35"]!![0] or emvTags["9F6D"]!![0])
    }

    fun setTransactionType(value: ByteArray) {
        emvTags["9C"] = value
    }

    private fun setTransactionDate() {
        addEMVTagValue(
            "9A",
            LocalDate.now().format(DateTimeFormatter.ofPattern("yyMMdd")).toByteArray()
        )
    }

    private fun setTransactionTime() {
        addEMVTagValue(
            "9F21",
            LocalTime.now().format(DateTimeFormatter.ofPattern("HHmmss")).toByteArray()
        )
    }

    private fun setUnpredictableNumber() {
        addEMVTagValue("9F37", generateUnpredictableNumber())
    }

    fun setAID(value: ByteArray) {
        addEMVTagValue("4F", value)
    }

    fun getAID(): ByteArray {
        return emvTags["4F"]!!
    }

    fun setApplicationInterchangeProfile(value: ByteArray) {
        addEMVTagValue("82", value)
    }

    fun isCardSupportSDA(): Boolean {
        return BytesUtils.matchBitByBitIndex(emvTags["82"]!![0], 6)
    }

    fun isCardSupportDDA(): Boolean {
        return BytesUtils.matchBitByBitIndex(emvTags["82"]!![0], 5)
    }

    fun isCardSupportCDA(): Boolean {
        return BytesUtils.matchBitByBitIndex(emvTags["82"]!![0], 0)
    }

    fun isSupportODA(): Boolean {
        return isCardSupportSDA() && isCardSupportDDA() && isCardSupportCDA()
    }

    fun hasAmexRID(): Boolean {
        return getAID().containsSequence(amex)
    }

    fun getIssuerPublicKeyRemainder(): ByteArray {
        return emvTags["92"] ?: byteArrayOf()
    }

    fun getPAN(): ByteArray? {
        return emvTags["5A"]
    }

    fun getIssuerPublicKeyExponent(): ByteArray {
        return emvTags["9F32"] ?: byteArrayOf()
    }

    fun getICCPublicKeyExponent(): ByteArray? {
        return emvTags["9F47"] ?: byteArrayOf()
    }

    fun getICCPublicKeyCertificate(): ByteArray? {
        return emvTags["9F46"]
    }

    fun getICCPublicKeyRemainder(): ByteArray? {
        return emvTags["9F48"]
    }

    fun getStaticDataAuthenticationTagList(): ByteArray? {
        return emvTags["9F4A"]
    }

    fun getSignedDynamicApplicationData(): ByteArray? {
        return emvTags["9F4B"]
    }

    fun getSignedStaticApplicationData(): ByteArray? {
        return emvTags["93"]
    }

    fun getCryptogramInformationData(): ByteArray? {
        return emvTags["9F27"]
    }

    fun getUnpredictableNumber(): ByteArray {
        return emvTags["9F37"]!!
    }

    fun getPDOL(): ByteArray {
        return emvTags["9F38"]!!
    }

    fun getCDOL1(): ByteArray {
        return emvTags["8C"]!!
    }

    fun setODANotPerformed() {
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 7, true)
    }

    fun setSDAFailed() {
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 6, true)
    }

    fun setDDAFailed() {
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 3, true)
    }

    fun setCDAFailed() {
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 2, true)
    }

    fun setSDASelected() {
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 1, true)
    }

    fun getResponseMessageTemplate2(): ByteArray {
        return emvTags["77"]!!
    }

    fun addEMVTagValue(tag: String, value: ByteArray) {
        emvTags[tag] = value
    }

    fun checkAppVerNum() {
        val cardAppVer = emvTags["9F08"]
        val termAppVer = emvTags["9F09"]
        if (cardAppVer != null && termAppVer != null) {
            if (!cardAppVer.contentEquals(termAppVer))
                emvTags["95"]!![1] = setBit(emvTags["95"]!![1], 7, true)
        }
    }

    fun checkAUC() {
        val AUC = emvTags["9F07"]
        val cardCountry = emvTags["9F57"]
        val termCountry = emvTags["9F1A"]
        if (AUC != null && cardCountry != null){
            // For now only support  0x00 goods
            if (cardCountry.contentEquals(termCountry)) {
                if (!matchBitByBitIndex(AUC[0], 5))
                    emvTags["95"]!![1] = setBit(emvTags["95"]!![1], 4, true)
            } else {
                if (!matchBitByBitIndex(AUC[0], 4))
                    emvTags["95"]!![1] = setBit(emvTags["95"]!![1], 4, true)
            }
        }
    }

    private fun checkEffectiveDate() {
        val effectiveDate = emvTags["5F25"]
        if (effectiveDate != null) {
            if (compareDateByteArrays(emvTags["9A"]!!, effectiveDate) < 0)
                emvTags["95"]!![1] = setBit(emvTags["95"]!![1], 5, true)
        }
    }

    private fun checkExpirationDate() {
        val expireDate = emvTags["5F24"]
        if (expireDate != null) {
            if (compareDateByteArrays(emvTags["9A"]!!, expireDate) > 0)
                emvTags["95"]!![1] = setBit(emvTags["95"]!![1], 6, true)
        }
    }

    fun checkEffectiveAndExpirationDate() {
        checkEffectiveDate()
        checkExpirationDate()
    }

    fun setICCDataMissing() {
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 5, true)
    }

    private fun setFloorLimitExceed() {
        emvTags["95"]!![3] = setBit(emvTags["95"]!![3], 7, true)
    }

    private fun setCardholderVerificationFailed() {
        emvTags["95"]!![2] = setBit(emvTags["95"]!![2], 7, true)
    }

    fun processCVM(){
        // Check card support Customer Verification
        val AIP = emvTags["82"]
        val cvmList = emvTags["8E"]
        if (AIP != null) {
            if (cvmList != null) {
                if (exceedCVMLimit) {
                    if (matchBitByBitIndex(AIP[0], 4)) {
                        // Support Cardholder verification
                        // Only support signature
                        if (cvmList.containsSequence("1E06".toByteArray())) {
                            // Signature
                            addEMVTagValue("9F34", "1E0000".toByteArray())
                            setTSICardholderVerificationPerformed()
                        } else if (cvmList.containsSequence("1F02".toByteArray())) {
                            // No CVM required
                            addEMVTagValue("9F34", "1F0002".toByteArray())
                            setTSICardholderVerificationPerformed()
                        } else {
                            // No matching CVM
                            addEMVTagValue("9F34", "3F0001".toByteArray())
                            setTSICardholderVerificationPerformed()
                            setCardholderVerificationFailed()
                        }
                    } else {
                        // Not suuport Cardholder verification
                        addEMVTagValue("9F34", "3F0000".toByteArray())
                    }
                } else {
                    // No CVM performed
                    addEMVTagValue("9F34", "3F0000".toByteArray())
                }
            } else {
                setICCDataMissing()
                addEMVTagValue("9F34", "3F0000".toByteArray())
            }
        }
    }

    fun processTermRiskManagement(){
        val AIP = emvTags["82"]
        if (AIP != null) {
            if (matchBitByBitIndex(AIP[0], 3)) {
                setFloorLimitIfNeeded()
            }
            // Random Transaction Selection
            // Readers must not support random transaction selection processing for contactless transactions.

            // Velocity Checking
            // Readers must not support velocity checking processing for contactless transactions.

            // Exception File Checking
            // Terminal Exception File/ Hotlist is not supported
        }
    }

    private fun setTSICardholderVerificationPerformed() {
        emvTags["9B"]!![0] = setBit(emvTags["9B"]!![0], 6, true)
    }

    private fun generateUnpredictableNumber(): ByteArray {
        val random = SecureRandom()
        val un = ByteArray(4)
        random.nextBytes(un)
        return un
    }
}