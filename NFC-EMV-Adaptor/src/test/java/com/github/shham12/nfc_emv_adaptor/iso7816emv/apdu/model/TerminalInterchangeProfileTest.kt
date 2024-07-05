package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.model

import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.TerminalInterchangeProfile
import org.junit.Assert.*
import org.junit.Test

class TerminalInterchangeProfileTest {

    @Test
    fun testInitialValues() {
        val tip = TerminalInterchangeProfile()
        assertArrayEquals(byteArrayOf(0x50.toByte(), 0x00, 0x00), tip.getValue())
    }

    @Test
    fun testSetCVMRequired() {
        val tip = TerminalInterchangeProfile()
        tip.setCVMRequired()
        assertEquals(0xD0.toByte(), tip.getValue()[0])  // 0x50 | 0x80 = 0xD0
    }
}
