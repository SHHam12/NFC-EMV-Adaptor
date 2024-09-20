package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

import android.util.Log
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.containsSequence

class CardholderVerificationMethod {
    private var byte1 = 0x00.toByte()
    private var byte2 = 0x00.toByte()
    private var byte3 = 0x00.toByte()

    private lateinit var amountX : ByteArray
    private lateinit var amountY : ByteArray
    private var exceedAmountX = false
    private var exceedAmountY = false

    private lateinit var cvmList : ByteArray

    private var isSignatureCVM  = false
    private var isNoCVMPerformed = false

    init {
        byte1 = 0x3F.toByte() // Set 3F0000 No CVM Performed as default
        byte2 = 0x00.toByte()
        byte3 = 0x00.toByte()
    }

    fun getValue(): ByteArray {
        return byteArrayOf(byte1, byte2, byte3)
    }

    fun parseCVMList(pCvmList: ByteArray, pAmount1: ByteArray) {
        // parse Amount X
        amountX = pCvmList.copyOfRange(0, 4)

        // parse Amount Y
        amountY = pCvmList.copyOfRange(4, 8)

        // parse cvm list
        cvmList = pCvmList.copyOfRange(8, pCvmList.size)

        exceedAmountX = BytesUtils.compareByteArraysWithPadding(pAmount1, amountX) > 0
        exceedAmountY = BytesUtils.compareByteArraysWithPadding(pAmount1, amountY) > 0
    }

    private fun checkCV(cvmList: ByteArray?, prefix: String, range: IntRange): Pair<Boolean, List<String>> {
        val cvmRange = range.map { String.format("%02X", it) }  // ex: 1F00 ~ 1F09
        var matched: List<String>  = cvmRange.filter { cvmList?.containsSequence((prefix + it).toByteArray()) == true }

        // List of suffixes to check
        val suffixes = listOf("00", "03", "06", "07", "08", "09")

        // Check if matched values contain any of the specified suffixes in Byte 2
        val hasMatchingByte = matched.any { suffixes.any { suffix -> it.endsWith(suffix) } }

        // Return a pair of the matching result and the matched values
        return Pair(hasMatchingByte, matched)
    }

    fun checkPossibleCVMList() {
        // At this moment, only supports Signature and No CVN
        val (signFlag, signMatched) = checkCV(cvmList, "1E", 0..9)
        val (signFlagAlt, signMatchedAlt) = checkCV(cvmList, "5E", 0..9)
        val (noCVMFlag, noCVMMatched) = checkCV(cvmList, "1F", 0..9)

        // Helper function to set byte1 and byte2
        fun setByteValues(byte1Value: Byte, cvByte2: String) {
            byte1 = byte1Value
            byte2 = cvByte2.toInt(16).toByte()

            if (byte1 == 0x1E.toByte() || byte1 == 0x5E.toByte())
                isSignatureCVM = true
            else if (byte1 == 0x1E.toByte())
                isNoCVMPerformed = true
        }

        // Process based on the flag conditions
        when {
            signFlag -> {
                val cvByte2 = signMatched[0]
                when {
                    cvByte2 == "00" || cvByte2 == "03" -> setByteValues(0x1E.toByte(), cvByte2)
                    cvByte2 == "06" && !exceedAmountX -> setByteValues(0x1E.toByte(), cvByte2)
                    cvByte2 == "07" && exceedAmountX -> setByteValues(0x1E.toByte(), cvByte2)
                    cvByte2 == "08" && !exceedAmountY -> setByteValues(0x1E.toByte(), cvByte2)
                    cvByte2 == "09" && exceedAmountY -> setByteValues(0x1E.toByte(), cvByte2)
                }
            }
            signFlagAlt -> {
                val cvByte2 = signMatchedAlt[0]
                when {
                    cvByte2 == "00" || cvByte2 == "03" -> setByteValues(0x5E.toByte(), cvByte2)
                    cvByte2 == "06" && !exceedAmountX -> setByteValues(0x5E.toByte(), cvByte2)
                    cvByte2 == "07" && exceedAmountX -> setByteValues(0x5E.toByte(), cvByte2)
                    cvByte2 == "08" && !exceedAmountY -> setByteValues(0x5E.toByte(), cvByte2)
                    cvByte2 == "09" && exceedAmountY -> setByteValues(0x5E.toByte(), cvByte2)
                }
            }
            noCVMFlag -> {
                val cvByte2 = noCVMMatched[0]
                when {
                    cvByte2 == "00" || cvByte2 == "03" -> setByteValues(0x1F.toByte(), cvByte2)
                    cvByte2 == "06" && !exceedAmountX -> setByteValues(0x1F.toByte(), cvByte2)
                    cvByte2 == "07" && exceedAmountX -> setByteValues(0x1F.toByte(), cvByte2)
                    cvByte2 == "08" && !exceedAmountY -> setByteValues(0x1F.toByte(), cvByte2)
                    cvByte2 == "09" && exceedAmountY -> setByteValues(0x1F.toByte(), cvByte2)
                }
            }
        }
    }

    fun isSignature() : Boolean = isSignatureCVM

    fun isNoCVM() : Boolean = isNoCVMPerformed

    fun setCVMfailed() {
        byte1 = 0x3F.toByte()
        byte2 = 0x00.toByte()
        byte3 = 0x01.toByte()
        Log.d("TLVDATA", "CVM verification failed: byte1 set to 3F, byte2 set to 00, byte3 set to 01")
    }
}