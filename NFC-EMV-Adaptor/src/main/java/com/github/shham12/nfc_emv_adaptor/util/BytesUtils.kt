package com.github.shham12.nfc_emv_adaptor.util

import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or
import kotlin.experimental.xor


object BytesUtils {
    fun fromString(id: String): ByteArray {
        // Ensure the string has an even number of characters
        require(id.length % 2 == 0) { "Hex string must have an even length" }

        // Convert each pair of hex characters to a byte
        return id.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }

    fun matchBitByBitIndex(byte: Byte, bitIndex: Int): Boolean {
        return byte.toInt() and (1 shl bitIndex) != 0
    }

    fun setBit(byte: Byte, bitIndex: Int, value: Boolean): Byte {
        return if (value) {
            (byte.toInt() or (1 shl bitIndex)).toByte()
        } else {
            (byte.toInt() and (1 shl bitIndex).inv()).toByte()
        }
    }

    fun bytesToString(bytes: ByteArray): String {
        return bytes.joinToString(separator = "") { "%02x".format(it) }
    }

    fun ByteArray.containsSequence(sequence: ByteArray): Boolean {
        for (i in 0..this.size - sequence.size) {
            if (this.sliceArray(i until i + sequence.size).contentEquals(sequence)) {
                return true
            }
        }
        return false
    }

    fun byteArrayAnd(array1: ByteArray, array2: ByteArray): ByteArray {
        return ByteArray(array1.size) { i -> (array1[i] and array2[i]).toByte() }
    }

    fun byteArrayOr(array1: ByteArray, array2: ByteArray): ByteArray {
        return ByteArray(array1.size) { i -> (array1[i] or array2[i]).toByte() }
    }

    fun byteArrayXor(array1: ByteArray, array2: ByteArray): ByteArray {
        return ByteArray(array1.size) { i -> (array1[i] xor array2[i]).toByte() }
    }

    fun byteArrayNot(array: ByteArray): ByteArray {
        return ByteArray(array.size) { i -> array[i].inv().toByte() }
    }

    fun hexString(b: ByteArray, offset: Int, len: Int): String {
        val d = StringBuilder(b.size * 2)
        for (i in 0 until len) {
            val byteI = b[offset + i]
            toHex(d, byteI)
        }
        return d.toString()
    }

    fun toHex(s: java.lang.StringBuilder, b: Byte) {
        val hi = Character.forDigit((b.toInt() shr 4) and 0x0F, 16)
        val lo = Character.forDigit(b.toInt() and 0x0F, 16)
        s.append(hi.uppercaseChar())
        s.append(lo.uppercaseChar())
    }

    fun hexTobyte(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}