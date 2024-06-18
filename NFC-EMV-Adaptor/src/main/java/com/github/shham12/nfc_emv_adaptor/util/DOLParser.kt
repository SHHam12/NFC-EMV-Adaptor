package com.github.shham12.nfc_emv_adaptor.util

import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.DOL
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.containsSequence
import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import kotlin.experimental.or

object DOLParser {
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

    fun generateDOLdata(dolTags: List<DOL>?, needsCommandTemplate: Boolean, pEMVRecord: EMVTransactionRecord): ByteArray {
        val commandDataField = StringBuilder()
        var length = 0

        if (dolTags != null) {
            // Check AID is AMEX and 9F6E tag is exist from PDOL. If not exist it needs to update 9F35 tag value with (9F35 & 9F6D) operation for GPO
            if (pEMVRecord.hasAmexRID() && !containsTag(dolTags, "9F6E")) {
                pEMVRecord.setModifiedTerminalType()
            }
            for (tag in dolTags) {
                val defaultValueHex = pEMVRecord.getEMVTags()[tag.tag]?.joinToString("") { "%02X".format(it) }
                val tagValue = tag.value?.joinToString("") { "%02X".format(it) } ?: defaultValueHex?.padStart(tag.length * 2, '0') ?: "0".repeat(tag.length * 2)

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
