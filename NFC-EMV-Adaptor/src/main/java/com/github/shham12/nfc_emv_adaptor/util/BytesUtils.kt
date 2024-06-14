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

    fun hexTobyte(s: String): ByteArray {
        if (s.length % 2 == 0) {
            return hexTobyte(s.toByteArray(), 0, s.length shr 1)
        } else {
            throw RuntimeException("Uneven number(" + s.length + ") of hex digits passed to hex2byte.")
        }
    }

    fun hexTobyte(b: ByteArray, offset: Int, len: Int): ByteArray {
        val d = ByteArray(len)
        for (i in 0 until len * 2) {
            val shift = if (i % 2 == 1) 0 else 4
            d[i shr 1] =
                (d[i shr 1].toInt() or (Char(b[offset + i].toUShort()).digitToIntOrNull(16)
                    ?: -1 shl shift)).toByte()
        }
        return d
    }
}