package com.github.shham12.nfc_emv_adaptor.iso7816emv.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.TLV
import com.github.shham12.nfc_emv_adaptor.iso7816emv.enum.CommandEnum
import com.github.shham12.nfc_emv_adaptor.parser.ResponseFormat1Parser
import com.github.shham12.nfc_emv_adaptor.util.TLVList
import org.junit.Assert.*
import org.junit.Test

class ResponseFormat1ParserTest {

    @Test
    fun testParseGPO() {
        val command = CommandEnum.GPO
        val data = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06)

        val expectedTLVList = TLVList().apply {
            add(TLV("82", 2, byteArrayOf(0x01, 0x02)))
            add(TLV("94", 2, byteArrayOf(0x03, 0x04, 0x05, 0x06)))
        }

        val resultTLVList = ResponseFormat1Parser.parse(command, data)

        assertTrue(compareTLVLists(expectedTLVList, resultTLVList))
    }

    @Test
    fun testParseGENAC() {
        val command = CommandEnum.GENAC
        val data = byteArrayOf(
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
        )

        val expectedTLVList = TLVList().apply {
            add(TLV("9F27", 1, byteArrayOf(0x01)))
            add(TLV("9F36", 2, byteArrayOf(0x02, 0x03)))
            add(TLV("9F26", 8, byteArrayOf(0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B)))
            add(TLV("9F10", 11, byteArrayOf( 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16)))
        }

        val resultTLVList = ResponseFormat1Parser.parse(command, data)

        assertTrue(compareTLVLists(expectedTLVList, resultTLVList))
    }

    private fun compareTLVLists(expected: TLVList, actual: TLVList): Boolean {
        if (expected.getTLVList().size != actual.getTLVList().size) {
            return false
        }
        for (i in expected.getTLVList().indices) {
            val expectedTLV = expected.getTLVList()[i]
            val actualTLV = actual.getTLVList()[i]
            if (expectedTLV.tag != actualTLV.tag || expectedTLV.length != actualTLV.length || !expectedTLV.value.contentEquals(actualTLV.value)) {
                return false
            }
        }
        return true
    }
}
