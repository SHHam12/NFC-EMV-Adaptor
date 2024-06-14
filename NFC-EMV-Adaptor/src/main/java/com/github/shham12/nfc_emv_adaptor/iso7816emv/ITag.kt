package com.github.shham12.nfc_emv_adaptor.iso7816emv

interface ITag {
    enum class Class {
        UNIVERSAL, APPLICATION, CONTEXT_SPECIFIC, PRIVATE
    }

    enum class TagType {
        PRIMITIVE,
        CONSTRUCTED
    }

    fun isConstructed(): Boolean

    fun getTag(): String

    fun getTagBytes(): ByteArray?

    fun getType(): TagType?

    fun getTagClass(): Class?

    fun getNumTagBytes(): Int
}