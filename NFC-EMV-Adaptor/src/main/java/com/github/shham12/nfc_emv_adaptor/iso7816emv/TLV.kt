package com.github.shham12.nfc_emv_adaptor.iso7816emv

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.Tag

data class TLV(
        var tag: ITag,
        var length: Int,
        var value: ByteArray,
) {
    constructor(tag: String, length: Int, value: ByteArray) : this(
        Tag(tag),
        length,
        value
    )

    override fun toString(): String {
        return "Tag: $tag, Length: $length, Name: ${tag.getTag()}, Class: ${tag.getTagClass()}, TagType: ${tag.getType()}, VALUE: $value"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TLV

        if (tag != other.tag) return false
        if (length != other.length) return false
        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + length
        result = 31 * result + value.contentHashCode()
        return result
    }

}

