package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import com.github.shham12.nfc_emv_adaptor.exception.TLVException
import com.github.shham12.nfc_emv_adaptor.iso7816emv.CaPublicKeyTable
import com.github.shham12.nfc_emv_adaptor.parser.SignedDynamicApplicationDataDecoder
import com.github.shham12.nfc_emv_adaptor.parser.SignedStaticApplicationDataDecoder
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.compareByteArrays
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
        "9F6E" to "D8004000".toByteArray(), // Amex Enhanced Contactless Reader Capabilities
        "9F66" to "23C00000".toByteArray(), // Need for VISA, Discover, Union Pay
        "9F02" to "000000000001".toByteArray(),
        "9F03" to "000000000000".toByteArray(),
        "9F1A" to "0840".toByteArray(),
        "5F2A" to "0840".toByteArray(),
        "9C" to "00".toByteArray(), // 0x00: Goods/ Service, 0x09: CashBack, 0x01: Cash, 0x20: Refund, 0x30: Balance Inquiry
        "9F34" to "000000".toByteArray(),
        "9F40" to "E0C8E06400".toByteArray(),
        "9F1D" to "A980800000".toByteArray(),
        "9F33" to "8028C8".toByteArray(),
        "9F4E" to "000000".toByteArray(),
        "9F6D" to "C0".toByteArray() // CVM Required 0XC8 CVM Not Required 0XC0
    )

    private val emvTags = mutableMapOf<String, ByteArray>()

    private val amex =
        byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x25.toByte())

    private val cvmLimit = "000000010000".toByteArray()

    private val floorLimit = "000000000000".toByteArray()

    private val defaultDDOL = "9F3704".toByteArray()

    private val defaultDDOLfDDA = "9F37049F02065F2A02".toByteArray()

    private val tvr = TerminalVerificationResults()

    private val tsi = TransactionStatusIndicator()

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
            tvr.setFloorLimitExceed()
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
        // Need to add TVR
        addEMVTagValue("95", tvr.getValue())
        // Need to add TSI
        addEMVTagValue("9B", tsi.getValue())
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
        return matchBitByBitIndex(emvTags["82"]!![0], 6)
    }

    fun isCardSupportDDA(): Boolean {
        return matchBitByBitIndex(emvTags["82"]!![0], 5)
    }

    fun isCardSupportCDA(): Boolean {
        return matchBitByBitIndex(emvTags["82"]!![0], 0)
    }

    fun isSupportODA(): Boolean {
        return isCardSupportSDA() || isCardSupportDDA() || isCardSupportCDA()
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
        return emvTags["9F47"]
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

    fun getPDOL(): ByteArray? {
        return emvTags["9F38"]
    }

    fun getCDOL1(): ByteArray {
        return emvTags["8C"]!!
    }

    fun getResponseMessageTemplate2(): ByteArray {
        return emvTags["77"]!!
    }

    fun addEMVTagValue(tag: String, value: ByteArray) {
        emvTags[tag] = value
    }

    fun processCVM(){
        // Check card support Customer Verification
        val aip = emvTags["82"]
        val cvmList = emvTags["8E"]
        if (aip != null) {
            if (cvmList != null) {
                if (exceedCVMLimit) {
                    if (matchBitByBitIndex(aip[0], 4)) {
                        // Support Cardholder verification
                        // Only support signature
                        if (cvmList.containsSequence("1E06".toByteArray())) {
                            // Signature
                            addEMVTagValue("9F34", "1E0000".toByteArray())
                            tsi.setCardholderVerificationPerformed()
                        } else if (cvmList.containsSequence("1F02".toByteArray())) {
                            // No CVM required
                            addEMVTagValue("9F34", "1F0002".toByteArray())
                            tsi.setCardholderVerificationPerformed()
                        } else {
                            // No matching CVM
                            addEMVTagValue("9F34", "3F0001".toByteArray())
                            tsi.setCardholderVerificationPerformed()
                            tvr.setCardholderVerificationFailed()
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
                tvr.setICCDataMissing()
                addEMVTagValue("9F34", "3F0000".toByteArray())
            }
        }
    }

    fun processTermRiskManagement(){
        val aip = emvTags["82"]
        if (aip != null) {
            if (matchBitByBitIndex(aip[0], 3)) {
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

    private fun generateUnpredictableNumber(): ByteArray {
        val random = SecureRandom()
        val un = ByteArray(4)
        random.nextBytes(un)
        return un
    }

    fun processTermActionAnalysis(): Int {
        // Default values for TAC and IAC if not present in emvTags
        val defaultTAC = "0000000000".toByteArray()
        val defaultIAC = "1111111111".toByteArray()

        // Terminal Action Codes
        val tacDenial = emvTags["DF12"] ?: defaultTAC
        val tacOnline = emvTags["DF12"] ?: defaultTAC
        val tacDefault = emvTags["DF11"] ?: defaultTAC

        // Issuer Action Codes
        val iacDenial = emvTags["9F0E"] ?: defaultTAC
        val iacOnline = emvTags["9F0F"] ?: defaultIAC
        val iacDefault = emvTags["9F0D"] ?: defaultIAC
        // Compare TAC and IAC codes
        return when {
            compareCodes(tvr.getValue(), tacDenial) || compareCodes(tvr.getValue(), iacDenial) -> 0x00 // AAC
            compareCodes(tvr.getValue(), tacOnline) || compareCodes(tvr.getValue(), iacOnline) -> {
                if (isCardSupportCDA()) 0x90 else 0x80 // ARQC or CDA signature requested
            }
            else -> 0x40 // TC
        }
    }

    fun getDDOL(isfDDA: Boolean): ByteArray{
        return if (isfDDA) defaultDDOLfDDA else emvTags["9F49"]?: defaultDDOL
    }

    private fun compareCodes(tvr: ByteArray, actionCodes: ByteArray): Boolean {
        for (i in tvr.indices) {
            val tvrByte = tvr[i].toInt()
            val actionCodeByte = actionCodes[i].toInt()
            for (bit in 0 until 8) {
                val tvrBit = (tvrByte shr bit) and 1
                val actionBit = (actionCodeByte shr bit) and 1
                if (tvrBit == 1 && actionBit == 1) {
                    return true
                }
            }
        }
        return false
    }

    fun processRestriction() {
        // Application Version Number check for TVR B2b8
        tvr.checkAppVerNum(emvTags["9F08"], emvTags["9F09"])
        // Check Application Usage Control
        tvr.checkAUC(emvTags["9F07"], emvTags["9F57"], emvTags["9F1A"]!!)
        // Check Effective Date & Expiration Date
        tvr.checkExpirationDate(emvTags["9A"]!!, emvTags["5F24"])
        tvr.checkEffectiveDate(emvTags["9A"]!!, emvTags["5F25"])
    }

    fun processODA(capkTable: CaPublicKeyTable?) {
        if (isSupportODA()) {
            val rid = BytesUtils.bytesToString(getAID().sliceArray(0 until 5)).uppercase()
            val capkIndex = BytesUtils.bytesToString(emvTags["8F"]!!).uppercase()
            val capk = capkTable?.findPublicKey(rid, capkIndex)

            capk?.let {
                when {
                    isCardSupportSDA() && !isCardSupportDDA() && !isCardSupportCDA() -> {
                        tvr.setSDASelected()
                        SignedStaticApplicationDataDecoder.validate(this, it)
                        tsi.setODAPerformed()
                    }
                    isCardSupportDDA() && !isCardSupportCDA() -> {
                        when {
                            emvTags.containsKey("9F69") -> {
                                SignedDynamicApplicationDataDecoder.validatefDDA(this, it)
                                tsi.setODAPerformed()
                            }
                            emvTags.containsKey("9F4B") -> {
                                SignedDynamicApplicationDataDecoder.retrievalApplicationCryptogram(this, it)
                                tsi.setODAPerformed()
                            }
                        }
                    }
                    isCardSupportCDA() -> {
                        if (emvTags.containsKey("9F4B")) {
                            SignedDynamicApplicationDataDecoder.retrievalApplicationCryptogram(this, it)
                            tsi.setODAPerformed()
                        }
                    }
                }
            } ?: throw TLVException("Not supported AID")
        } else {
            tvr.setODANotPerformed()
        }
    }

    fun setDDAFailed() {
        tvr.setDDAFailed()
    }

    fun setCDAFailed() {
        tvr.setCDAFailed()
    }

    fun setSDAFailed() {
        tvr.setSDAFailed()
    }
}