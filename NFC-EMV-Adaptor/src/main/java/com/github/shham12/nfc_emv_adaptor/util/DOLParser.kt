package com.github.shham12.nfc_emv_adaptor.util

import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.DOL
import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalTime
import java.time.format.DateTimeFormatter

object DOLParser {
    private val defaultValues = mapOf(
            "9F35" to hexStringToByteArray("22"),
            "9F6E" to hexStringToByteArray("D8004000"),
            "9F66" to hexStringToByteArray("20404000"),
            "9F02" to hexStringToByteArray("000000000001"),
            "9F03" to hexStringToByteArray("000000000000"),
            "9F1A" to hexStringToByteArray("0840"),
            "95" to hexStringToByteArray("0000000000"),
            "5F2A" to hexStringToByteArray("0840"),
            "9C" to hexStringToByteArray("00"), // 0x00: Goods/ Service, 0x09: CashBack, 0x01: Cash, 0x20: Refund, 0x30: Balance Inquiry
            "9F45" to hexStringToByteArray("0000"),
            "9F4C" to hexStringToByteArray("0000"),
            "9F34" to hexStringToByteArray("000000"),
            "9F40" to hexStringToByteArray("E0C8E06400"),
            "9F1D" to hexStringToByteArray("0000000000"),
            "9F33" to hexStringToByteArray("802800"),
            "9F4E" to hexStringToByteArray("000000"),
            "9F6D" to hexStringToByteArray("C8") // Amex C4 Contactless Reader Capabilities
    )

    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
        }
        return data
    }

    private fun generateUnpredictableNumber(): ByteArray {
        val random = SecureRandom()
        val un = ByteArray(4)
        random.nextBytes(un)
        return un
    }

    fun parseDOL(pdol: ByteArray): List<DOL> {
        val pdolTags = mutableListOf<DOL>()
        var index = 0

        while (index < pdol.size) {
            // Parse tag
            val tagBytes = mutableListOf<Byte>()
            tagBytes.add(pdol[index])
            index++

            // Handle multi-byte tags
            if (tagBytes[0].toInt() and 0x1F == 0x1F) {
                while (pdol[index].toInt() and 0x80 == 0x80) {
                    tagBytes.add(pdol[index])
                    index++
                }
                tagBytes.add(pdol[index])
                index++
            }

            val tag = tagBytes.joinToString("") { "%02X".format(it) }

            // Parse length
            val lengthByte = pdol[index]
            var length = lengthByte.toInt()
            index++

            if (length and 0x80 == 0x80) {
                // Multi-byte length field
                val numLengthBytes = length and 0x7F
                length = 0
                for (i in 0 until numLengthBytes) {
                    length = (length shl 8) + pdol[index].toInt()
                    index++
                }
            }

            pdolTags.add(DOL(tag, length))
        }

        return pdolTags
    }


    fun setDefaultValues(dolTags: List<DOL>) {
        dolTags.forEach { tag ->
            tag.defaultValue = (defaultValues[tag.tag] ?: "00".repeat(tag.length)) as ByteArray?
        }
    }

    fun generateDOLdata(dolTags: List<DOL>?, needsCommandTemplate: Boolean): ByteArray {
        val commandDataField = StringBuilder()
        var length = 0

        if (dolTags != null) {
            for (tag in dolTags) {
                val defaultValueHex = defaultValues[tag.tag]?.joinToString("") { "%02X".format(it) }
                val tagValue = when (tag.tag) {
                    "9A" -> LocalDate.now().format(DateTimeFormatter.ofPattern("yyMMdd"))
                    "9F21" -> LocalTime.now().format(DateTimeFormatter.ofPattern("HHmmss"))
                    "9F37" -> generateUnpredictableNumber().joinToString("") { "%02X".format(it) }
                    else -> tag.value?.joinToString("") { "%02X".format(it) } ?: defaultValueHex?.padStart(tag.length * 2, '0') ?: "0".repeat(tag.length * 2)
                }

                // Debugging: Print the tag and its value
                println("Tag: ${tag.tag}, Value: $tagValue")

                // Handle cases where tagValue might be null
                if (null == tagValue) {
                    throw IllegalArgumentException("Tag value for ${tag.tag} is null and no default value is provided.")
                }

                commandDataField.append(tagValue)
                length += tag.length
            }
        }

        // Convert the length to hexadecimal format with leading zeros if necessary
        val lengthHex = length.toString(16).padStart(2, '0')

        // Adjust the command template based on whether it is a PDOL or not
        val commandTemplate = if (needsCommandTemplate) {
            "83$lengthHex$commandDataField" // PDOL
        } else {
            commandDataField.toString() // CDOL data
        }

        // Debugging: Print the final command template
        println("Command Template: $commandTemplate")

        // Convert the commandDataField to a ByteArray
        return commandTemplate.chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
    }

    fun containsTag(dolList: List<DOL>, targetTag: String): Boolean {
        return dolList.any { it.tag == targetTag }
    }

    fun updateDOLValue(dolList: List<DOL>, targetTag: String, newValue: ByteArray) {
        val dol = dolList.find { it.tag == targetTag }
        if (dol != null) {
            dol.value = newValue
        } else {
            println("Tag $targetTag not found.")
        }
    }
}
