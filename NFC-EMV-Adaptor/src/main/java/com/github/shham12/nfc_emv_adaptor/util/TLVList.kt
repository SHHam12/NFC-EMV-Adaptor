package com.github.shham12.nfc_emv_adaptor.util

import com.github.shham12.nfc_emv_adaptor.iso7816emv.EMVTags
import com.github.shham12.nfc_emv_adaptor.iso7816emv.TLV
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString

class TLVList {
    private val listOfTLV: MutableList<TLV> = mutableListOf()

    fun getTLVList() : MutableList<TLV>{
        return listOfTLV
    }

    fun add(item: TLV) {
        listOfTLV.add(item)
    }

    fun add(
        tag: String,
        length: Int,
        value: ByteArray
    ) {
        add(TLV(tag, length, value))
    }

    fun containsByTag(tag: String): Boolean {
        return listOfTLV.any { it.tag.getTag().equals(tag, ignoreCase = true) }
    }

    fun searchByTag(tag: String): TLV? {
        val selTLVList = listOfTLV.filter {it.tag.getTag().equals(tag, ignoreCase = true) }
        return when {
            selTLVList.isEmpty() -> null
            selTLVList.size == 1 -> selTLVList.first()
            else -> throw Exception("There are more than one '$tag' tag in TLV Data.")
        }
    }

    fun generate(exclusiveConstructed: Boolean, filteredTags: Boolean): String {
        val result = StringBuilder()
        listOfTLV
            .filterNot { it.value.isEmpty() }
            .filterNot {
                exclusiveConstructed && it.tag.isConstructed()
            }
            .filterNot { filteredTags && !EMVTags.TAGS.containsKey(it.tag.getTag()) }
            .forEach {
                val length = it.value.size
                result.append(it.tag.getTag())
                    .append(length.toString(16).padStart(2, '0'))
                    .append(bytesToString(it.value))
            }
        return result.toString()
    }

    fun generateEx(exclusiveConstructed: Boolean, filteredTags: Boolean): String {
        val result = StringBuilder()
        listOfTLV
            .filterNot { it.value.isEmpty() || it.value.size < 2 }
            .filterNot {
                exclusiveConstructed && it.tag.isConstructed()
            }
            .filterNot { filteredTags && !EMVTags.TAGS.containsKey(it.tag.getTag()) }
            .forEach {
                val length = it.value.size / 2
                if (length.toString(16).length % 2 != 0) {
                    if (length.toString(16).length > 2)
                        result.append(it.tag)
                            .append("820")
                            .append(length.toString(16))
                            .append(it.value)
                    else
                        result.append(it.tag)
                            .append("810")
                            .append(length.toString(16))
                            .append(it.value)
                } else {
                    result.append(it.tag)
                        .append(length.toString(16).padStart(2, '0'))
                        .append(it.value)
                }
            }
        return result.toString()
    }

    fun generateList(exclusiveConstructed: Boolean, filteredTags: Boolean): Map<String, ByteArray> {
        val result = mutableMapOf<String, ByteArray>()
        listOfTLV
            .filterNot { it.value.isEmpty() || it.value.size < 2 }
            .filterNot {
                exclusiveConstructed && it.tag.isConstructed()
            }
            .filterNot { filteredTags && !EMVTags.TAGS.containsKey(it.tag.getTag()) }
            .forEach { result[it.tag.getTag()] = it.value }
        return result
    }

    fun concat(param0: TLVList): TLVList {
        val tlvList = TLVList()
        tlvList.listOfTLV.addAll(listOfTLV)
        tlvList.listOfTLV.addAll(param0.listOfTLV)
        return tlvList
    }

    fun addRange(param0: TLVList) {
        listOfTLV.addAll(param0.listOfTLV)
    }

    fun removeByTag(tag: String): Int {
        val initialSize = listOfTLV.size
        listOfTLV.removeAll { it.tag.getTag().equals(tag, ignoreCase = true) }
        return initialSize - listOfTLV.size
    }
}


