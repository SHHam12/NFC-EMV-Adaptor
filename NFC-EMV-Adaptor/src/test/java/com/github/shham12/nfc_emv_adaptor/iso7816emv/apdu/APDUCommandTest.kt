package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu

import com.github.shham12.nfc_emv_adaptor.iso7816emv.enum.CommandEnum
import org.junit.Assert.*
import org.junit.Test


class APDUCommandTest {
    @Test
    fun testToBytesSelectCommandWithDataAndLe() {
        val data = byteArrayOf(0x01, 0x02, 0x03)
        val apdu = APDUCommand(CommandEnum.SELECT, data, 0x10)
        val expectedBytes =
            byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, data.size.toByte(), 0x01, 0x02, 0x03, 0x10)
        assertArrayEquals(expectedBytes, apdu.toBytes())
    }

    @Test
    fun testToBytesReadRecordCommandWithoutLe() {
        val apdu = APDUCommand(CommandEnum.READ_RECORD, 0x00, 0x01)
        val expectedBytes = byteArrayOf(0x00, 0xB2.toByte(), 0x00, 0x00, 0x00)
        assertArrayEquals(expectedBytes, apdu.toBytes())
    }

    @Test
    fun testToBytesGPOCommandWithOnlyClaIns() {
        val apdu = APDUCommand(CommandEnum.GPO, 0x00, 0x01)
        val expectedBytes = byteArrayOf(0x80.toByte(), 0xA8.toByte(), 0x00, 0x01)
        assertArrayEquals(expectedBytes, apdu.toBytes())
    }

    @Test
    fun testToBytesGenACCommandWithoutDataAndLe() {
        val apdu = APDUCommand(CommandEnum.GENAC, 0x00, 0x01)
        val expectedBytes = byteArrayOf(0x80.toByte(), 0xAE.toByte(), 0x00, 0x01)
        assertArrayEquals(expectedBytes, apdu.toBytes())
    }
}
