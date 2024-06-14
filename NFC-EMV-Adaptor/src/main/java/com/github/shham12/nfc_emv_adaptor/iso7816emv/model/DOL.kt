package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

data class DOL(
    val tag: String,
    val length: Int,
    var defaultValue: ByteArray? = null,
    var value: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DOL

        if (tag != other.tag) return false
        if (length != other.length) return false
        if (defaultValue != null) {
            if (other.defaultValue == null) return false
            if (!defaultValue.contentEquals(other.defaultValue)) return false
        } else if (other.defaultValue != null) return false
        if (value != null) {
            if (other.value == null) return false
            if (!value.contentEquals(other.value)) return false
        } else if (other.value != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + length
        result = 31 * result + (defaultValue?.contentHashCode() ?: 0)
        result = 31 * result + (value?.contentHashCode() ?: 0)
        return result
    }
}
