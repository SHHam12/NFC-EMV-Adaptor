package com.github.shham12.nfc_emv_adaptor.util

import com.github.shham12.nfc_emv_adaptor.iso7816emv.TLV
import java.io.ByteArrayOutputStream

object TLVParser {
    fun parseEx(hexByteArray: ByteArray): TLVList {
        val tlvData: TLVList?
        var subLists: MutableList<TLVList>? = null

        tlvData = parseAsListEx(hexByteArray, false)
        tlvData.getTLVList().forEach { tlv ->
            if (tlv.tag.isConstructed()) {
                if (subLists == null)
                    subLists = mutableListOf()
                subLists?.add(parseAsListEx(tlv.value, true))
            }
        }

        if (subLists != null && subLists!!.isNotEmpty()) {
            // Parse again for CONSTRUCTED
            subLists!!.forEach { tlvList ->
                tlvList.getTLVList().forEach { tlv ->
                    if (tlv.tag.isConstructed()) {
                        subLists = mutableListOf()
                        subLists?.add(parseAsListEx(tlv.value, true))
                    }
                }
            }
            // Merge
            subLists!!.forEach { list ->
                list.getTLVList().forEach { item ->
                    if (!tlvData.containsByTag(item.tag.getTag()))
                        tlvData.add(item)
                }
            }
        }
        return tlvData
    }

    private fun parseAsListEx(hex: ByteArray, isSubTag: Boolean = false): TLVList {
        val tlvData = TLVList()
        var length = 0
        val hexTag = StringBuilder()
        val hexValue = ByteArrayOutputStream()

        try {
            val decimalArray : IntArray = convertToDecimalArray(hex)
            val totalLength = decimalArray.size
            var cursor = 0

            while (cursor < totalLength) {
                hexTag.clear()
                hexValue.reset()
                length = 0

                val firstTag = decimalArray[cursor]
                cursor++

                // Tag
                if (!isValidTag(firstTag))
                    continue

                hexTag.append(firstTag.toString(16).padStart(2, '0'))
                if (isMultiByteTag(firstTag)) {
                    var isLastByte = false
                    while (!isLastByte) {
                        // next byte with tag value
                        val secTag = decimalArray[cursor]
                        cursor++
                        hexTag.append(secTag.toString(16).padStart(2, '0'))
                        isLastByte = isLastByteTag(secTag)
                    }
                }

                // Length
                val firstLength = decimalArray[cursor]
                cursor++

                val tmpLen = getLengthOfLengthByte(firstLength)
                length = when (tmpLen) {
                    1 -> firstLength
                    2 -> {
                        val secLen = decimalArray[cursor]
                        cursor++
                        secLen
                    }
                    3 -> {
                        val secLen = decimalArray[cursor]
                        cursor++
                        val thirdLen = decimalArray[cursor]
                        cursor++
                        Integer.parseInt(secLen.toString(16) + thirdLen.toString(16), 16)
                    }
                    else -> {
                        val errorInfo = "hexString : $hex,  isSubTag : $isSubTag, firstLength : $firstLength, tmpLen : $tmpLen, hexTag : $hexTag\n\n"
                        var strTagList = ""
                        val tagList = tlvData.generateList(
                            exclusiveConstructed = false,
                            filteredTags = false
                        )
                        for ((key, value) in tagList) {
                            strTagList += "\nTag : $key, Value : $value"
                        }
                        throw Exception("Invalid TLV Format Data.\n$errorInfo$strTagList")
                    }
                }

                // Value
                repeat(length) {
                    hexValue.write(decimalArray[cursor])
                    cursor++
                }

                tlvData.add(hexTag.toString().uppercase(), length, hexValue.toByteArray())
            }
        } catch (e: IndexOutOfBoundsException) {
            tlvData.add(hexTag.toString().uppercase(), length, hexValue.toByteArray())
        }

        return tlvData
    }

    private fun convertToDecimalArray(hex: ByteArray): IntArray {
        return hex.map { it.toInt() and 0xFF }.toIntArray()
    }

    private fun convertToHexString(bytes: IntArray): String {
        return bytes.joinToString("") { it.toString(16).padStart(2, '0') }
    }

    private fun isGarbageTag(value: Int): Boolean {
        return value == 0xC2 || value == 0xE2
    }


    private fun isValidTag(value: Int): Boolean {
        return value != 0x00
    }


    private fun isMultiByteTag(value: Int): Boolean {
        return 0x1F == (value and 0x1F)
    }


    private fun isLastTag(value: Int): Boolean {
        return 0x00 == (value shr 7)
    }

    private fun isValidLength(value: Int): Boolean {
        return value != 0x80 && value in 0x00..0x84
    }

    private fun getTLV(tag: String, length: Int, value: ByteArray): TLV {
        return TLV(tag, length, value)
    }

    private fun isLastByteTag(value: Int): Boolean {
        // 0x80. b8 = 0 : this is the last byte
        return 0x80 != (value and 0x80)
    }

    private fun getLengthOfLengthByte(value: Int): Int {
        var len = 1

        if (0x80 == (0x80 and value)) {
            len += 0x0F and value
        }

        return len
    }
}

