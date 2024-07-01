package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.model

import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.TransactionStatusIndicator
import org.junit.Assert.*
import org.junit.Test

class TransactionStatusIndicatorTest {
    @Test
    fun testInitialValues() {
        val tsi = TransactionStatusIndicator()
        assertArrayEquals(byteArrayOf(0x00, 0x00), tsi.getValue())
    }

    @Test
    fun testResetValue() {
        val tsi = TransactionStatusIndicator()
        tsi.setODAPerformed()
        tsi.resetValue()
        assertArrayEquals(byteArrayOf(0x00, 0x00), tsi.getValue())
    }

    @Test
    fun testSetODAPerformed() {
        val tsi = TransactionStatusIndicator()
        tsi.setODAPerformed()
        assertEquals(0x80.toByte(), tsi.getValue()[0])
    }

    @Test
    fun testSetCardholderVerificationPerformed() {
        val tsi = TransactionStatusIndicator()
        tsi.setCardholderVerificationPerformed()
        assertEquals(0x40.toByte(), tsi.getValue()[0])
    }

    @Test
    fun testSetCardRiskManagementPerformed() {
        val tsi = TransactionStatusIndicator()
        tsi.setCardRiskManagementPerformed()
        assertEquals(0x20.toByte(), tsi.getValue()[0])
    }

    @Test
    fun testSetIssuerAuthenticationPerformed() {
        val tsi = TransactionStatusIndicator()
        tsi.setIssuerAuthenticationPerformed()
        assertEquals(0x10.toByte(), tsi.getValue()[0])
    }

    @Test
    fun testSetTermRiskManagementPerformed() {
        val tsi = TransactionStatusIndicator()
        tsi.setTermRiskManagementPerformed()
        assertEquals(0x08.toByte(), tsi.getValue()[0])
    }

    @Test
    fun testSetIssuerScriptProcessingPerformed() {
        val tsi = TransactionStatusIndicator()
        tsi.setIssuerScriptProcessingPerformed()
        assertEquals(0x04.toByte(), tsi.getValue()[0])
    }
}