package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.compareByteArrays
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.containsSequence
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
        "9F33" to "802800".toByteArray(),
        "9F4E" to "000000".toByteArray(),
        "9F6D" to "C0".toByteArray(), // CVM Required 0XC8 CVM Not Required 0XC0
    )

    private val emvTags = mutableMapOf<String, ByteArray>()

    private val amex = byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x25.toByte())

    private val cvmLimit = "000000010000".toByteArray()

    init {
        emvTags.putAll(defaultValues)
        setTransactionDate()
        setTransactionTime()
        setUnpredictableNumber()
        if (!emvTags["9F02"].contentEquals("000000000000".toByteArray()))
            setFloorLimitExceed()
        if (compareByteArrays(emvTags["9F02"]!!, cvmLimit) > 0)
            emvTags["9F6D"] = "C8".toByteArray()
    }

    fun getEMVTags(): MutableMap<String, ByteArray>{
        return emvTags
    }

    fun clear(){
        emvTags.clear()
        emvTags.putAll(defaultValues)
        setTransactionDate()
        setTransactionTime()
        setUnpredictableNumber()
        if (!emvTags["9F02"].contentEquals("000000000000".toByteArray()))
            setFloorLimitExceed()
    }

    fun setAmount1(value: ByteArray){
        emvTags["9F02"] = value
    }

    fun setAmount2(value: ByteArray){
        emvTags["9F03"] = value
    }

    fun setModifiedTerminalType(){
        emvTags["9F35"] = byteArrayOf(emvTags["9F35"]!![0] or emvTags["9F6D"]!![0])
    }

    fun setTransactionType(value: ByteArray){
        emvTags["9C"] = value
    }

    private fun setTransactionDate(){
        addEMVTagValue("9A", LocalDate.now().format(DateTimeFormatter.ofPattern("yyMMdd")).toByteArray())
    }

    private fun setTransactionTime(){
        addEMVTagValue("9F21", LocalTime.now().format(DateTimeFormatter.ofPattern("HHmmss")).toByteArray())
    }

    private fun setUnpredictableNumber(){
        addEMVTagValue("9F37", generateUnpredictableNumber())
    }

    fun setAID(value: ByteArray){
        addEMVTagValue("4F", value)
    }

    fun getAID(): ByteArray{
        return emvTags["4F"]!!
    }

    fun setApplicationInterchangeProfile(value: ByteArray){
        addEMVTagValue("82", value)
    }

    fun isCardSupportSDA(): Boolean{
        return BytesUtils.matchBitByBitIndex(emvTags["82"]!![0], 6)
    }

    fun isCardSupportDDA(): Boolean{
        return BytesUtils.matchBitByBitIndex(emvTags["82"]!![0], 5)
    }

    fun isCardSupportCDA(): Boolean{
        return BytesUtils.matchBitByBitIndex(emvTags["82"]!![0], 0)
    }

    fun hasAmexRID(): Boolean{
        return getAID().containsSequence(amex)
    }

    fun getIssuerPublicKeyRemainder(): ByteArray{
        return emvTags["92"] ?: byteArrayOf()
    }

    fun getPAN(): ByteArray?{
        return emvTags["5A"]
    }

    fun getIssuerPublicKeyExponent(): ByteArray{
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
        return  emvTags["9F4A"]
    }

    fun getSignedDynamicApplicationData(): ByteArray?{
        return emvTags["9F4B"]
    }

    fun getCryptogramInformationData(): ByteArray?{
        return emvTags["9F27"]
    }

    fun getUnpredictableNumber(): ByteArray{
        return emvTags["9F37"]!!
    }

    fun getPDOL(): ByteArray{
        return emvTags["9F38"]!!
    }

    fun getCDOL1(): ByteArray{
        return emvTags["8C"]!!
    }

    fun setODAPerformed(){
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 7, true)
    }

    fun setDDAFailed(){
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 3, true)
    }

    fun setCDAFailed(){
        emvTags["95"]!![0] = setBit(emvTags["95"]!![0], 2, true)
    }

    fun getResponseMessageTemplate2(): ByteArray{
        return emvTags["77"]!!
    }

    fun addEMVTagValue(tag: String, value: ByteArray){
        emvTags[tag] = value
    }

    private fun setFloorLimitExceed(){
        emvTags["95"]!![3] = setBit(emvTags["95"]!![3], 7, true)
    }

    private fun generateUnpredictableNumber(): ByteArray {
        val random = SecureRandom()
        val un = ByteArray(4)
        random.nextBytes(un)
        return un
    }
}