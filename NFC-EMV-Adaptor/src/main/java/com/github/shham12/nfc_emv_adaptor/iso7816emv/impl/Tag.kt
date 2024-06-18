package com.github.shham12.nfc_emv_adaptor.iso7816emv.impl

import com.github.shham12.nfc_emv_adaptor.iso7816emv.EMVTags
import com.github.shham12.nfc_emv_adaptor.iso7816emv.ITag
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray


class Tag(
    idBytes: ByteArray?,
    name: String?
) :
    ITag {
    private val idBytes: ByteArray
    val name: String?
    private var tagClass: ITag.Class? = null
    private var type: ITag.TagType? = null

    constructor(
        id: String
    ) : this(
        id.toByteArray(),
        EMVTags.TAGS.getOrDefault(id, "unknown tag")
    )

    init {
        requireNotNull(idBytes) { "Param id cannot be null" }
        require(idBytes.isNotEmpty()) { "Param id cannot be empty" }
        this.idBytes = idBytes
        this.name = name

        type = if (BytesUtils.matchBitByBitIndex(this.idBytes[0], 5)) {
            ITag.TagType.CONSTRUCTED
        } else {
            ITag.TagType.PRIMITIVE
        }
        // Bits 8 and 7 of the first byte of the tag field indicate a class.
        // The value 00 indicates a data object of the universal class.
        // The value 01 indicates a data object of the application class.
        // The value 10 indicates a data object of the context-specific class.
        // The value 11 indicates a data object of the private class.
        val classValue = (this.idBytes[0].toInt() ushr 6 and 0x03).toByte()
        tagClass = when (classValue) {
            0x01.toByte() -> ITag.Class.APPLICATION
            0x02.toByte() -> ITag.Class.CONTEXT_SPECIFIC
            0x03.toByte() -> ITag.Class.PRIVATE
            else -> ITag.Class.UNIVERSAL
        }
    }

    override fun getTag(): String {
        return BytesUtils.bytesToString(idBytes)
    }

    override fun isConstructed(): Boolean {
        return type === ITag.TagType.CONSTRUCTED
    }

    override fun getTagBytes(): ByteArray? {
        return idBytes
    }

    override fun getType(): ITag.TagType? {
        return type
    }

    override fun getTagClass(): ITag.Class? {
        return tagClass
    }

    override fun equals(other: Any?): Boolean {
        if (other !is ITag) {
            return false
        }
        val that = other
        if (getTagBytes()!!.size != that.getTagBytes()!!.size) {
            return false
        }

        return getTagBytes().contentEquals(that.getTagBytes())
    }

    override fun hashCode(): Int {
        var hash = 3
        hash = 59 * hash + idBytes.contentHashCode()
        return hash
    }

    override fun getNumTagBytes(): Int {
        return idBytes.size
    }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("Tag[")
        sb.append(BytesUtils.bytesToString(getTagBytes()!!))
        sb.append("] Name=")
        sb.append(name)
        sb.append(", TagType=")
        sb.append(getType())
        sb.append(", Class=")
        sb.append(tagClass)
        return sb.toString()
    }
}