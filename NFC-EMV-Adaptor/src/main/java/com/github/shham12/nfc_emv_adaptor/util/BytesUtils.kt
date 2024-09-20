package com.github.shham12.nfc_emv_adaptor.util

import java.time.LocalDate
import java.time.Year
import java.time.format.DateTimeFormatterBuilder
import java.time.temporal.ChronoField
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or
import kotlin.experimental.xor


object BytesUtils {
    fun String.toByteArray(): ByteArray {
        // Ensure the string has an even number of characters
        require(this.length % 2 == 0) { "Hex string must have an even length" }

        // Convert each pair of hex characters to a byte
        return this.chunked(2)
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
        return ByteArray(array1.size) { i -> (array1[i] and array2[i]) }
    }

    fun byteArrayOr(array1: ByteArray, array2: ByteArray): ByteArray {
        return ByteArray(array1.size) { i -> (array1[i] or array2[i]) }
    }

    fun byteArrayXor(array1: ByteArray, array2: ByteArray): ByteArray {
        return ByteArray(array1.size) { i -> (array1[i] xor array2[i]) }
    }

    fun byteArrayNot(array: ByteArray): ByteArray {
        return ByteArray(array.size) { i -> array[i].inv() }
    }

    fun hexString(b: ByteArray, offset: Int, len: Int): String {
        val d = StringBuilder(b.size * 2)
        for (i in 0 until len) {
            val byteI = b[offset + i]
            toHex(d, byteI)
        }
        return d.toString()
    }

    private fun toHex(s: java.lang.StringBuilder, b: Byte) {
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

    fun ByteArray.padStart(newSize: Int, padByte: Byte = 0x00): ByteArray {
        if (this.size >= newSize) return this
        val padding = ByteArray(newSize - this.size) { padByte }
        return padding + this
    }

    fun compareByteArraysWithPadding(arr1: ByteArray, arr2: ByteArray): Int {
        val maxLength = maxOf(arr1.size, arr2.size)

        val paddedArr1 = arr1.padStart(maxLength)
        val paddedArr2 = arr2.padStart(maxLength)

        return compareByteArrays(paddedArr1, paddedArr2)
    }

    fun compareByteArrays(array1: ByteArray, array2: ByteArray): Int {
        require(array1.size == array2.size) { "Both byte arrays must have the same length" }

        for (i in array1.indices) {
            val byte1 = array1[i]
            val byte2 = array2[i]

            if (byte1 != byte2) {
                return byte1.compareTo(byte2)
            }
        }
        return 0 // Arrays are equal
    }

    fun compareDateByteArrays(date1: ByteArray, date2: ByteArray): Int {
        val dateString1 = bytesToString(date1)
        val dateString2 = bytesToString(date2)

        val currentYear = Year.now().value // Get the current year (e.g., 2024)

        // Determine the base year: if the current year is 2024, use 2000; if 2124, use 2100, etc.
        val baseYear = (currentYear / 100) * 100

        val formatter = DateTimeFormatterBuilder()
            .appendValueReduced(ChronoField.YEAR, 2, 2, baseYear) // Dynamic base year
            .appendPattern("MMdd")
            .toFormatter()

        val parsedDate1: LocalDate = LocalDate.parse(dateString1, formatter)
        val parsedDate2: LocalDate = LocalDate.parse(dateString2, formatter)

        return parsedDate1.compareTo(parsedDate2)
    }
}