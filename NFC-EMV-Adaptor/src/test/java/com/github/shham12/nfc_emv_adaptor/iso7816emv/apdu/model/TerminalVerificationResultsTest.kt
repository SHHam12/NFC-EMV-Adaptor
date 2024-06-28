package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.model

import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.TerminalVerificationResults
import org.junit.Assert.*
import org.junit.Test

class TerminalVerificationResultsTest {

    @Test
    fun testInitialValues() {
        val tvr = TerminalVerificationResults()
        assertArrayEquals(byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00), tvr.getValue())
    }

    @Test
    fun testSetODANotPerformed() {
        val tvr = TerminalVerificationResults()
        tvr.setODANotPerformed()
        assertEquals(0x80.toByte(), tvr.getValue()[0])
    }

    @Test
    fun testSetSDAFailed() {
        val tvr = TerminalVerificationResults()
        tvr.setSDAFailed()
        assertEquals(0x40.toByte(), tvr.getValue()[0])
    }

    @Test
    fun testSetICCDataMissing() {
        val tvr = TerminalVerificationResults()
        tvr.setICCDataMissing()
        assertEquals(0x20.toByte(), tvr.getValue()[0])
    }

    @Test
    fun testSetDDAFailed() {
        val tvr = TerminalVerificationResults()
        tvr.setDDAFailed()
        assertEquals(0x08.toByte(), tvr.getValue()[0])
    }

    @Test
    fun testSetCDAFailed() {
        val tvr = TerminalVerificationResults()
        tvr.setCDAFailed()
        assertEquals(0x04.toByte(), tvr.getValue()[0])
    }

    @Test
    fun testSetSDASelected() {
        val tvr = TerminalVerificationResults()
        tvr.setSDASelected()
        assertEquals(0x02.toByte(), tvr.getValue()[0])
    }

    @Test
    fun testCheckAppVerNum() {
        val tvr = TerminalVerificationResults()
        val cardAppVer = byteArrayOf(0x01, 0x02)
        val termAppVer = byteArrayOf(0x01, 0x03)
        tvr.checkAppVerNum(cardAppVer, termAppVer)
        assertEquals(0x80.toByte(), tvr.getValue()[1])
    }

    @Test
    fun testCheckExpirationDate() {
        val tvr = TerminalVerificationResults()
        val transDate = byteArrayOf(0x20, 0x06, 0x25)  // YYYYMMDD
        val expireDate = byteArrayOf(0x20, 0x06, 0x24)
        tvr.checkExpirationDate(transDate, expireDate)
        assertEquals(0x40.toByte(), tvr.getValue()[1])
    }

    @Test
    fun testCheckEffectiveDate() {
        val tvr = TerminalVerificationResults()
        val transDate = byteArrayOf(0x20, 0x06, 0x25)  // YYYYMMDD
        val effectiveDate = byteArrayOf(0x20, 0x06, 0x26)
        tvr.checkEffectiveDate(transDate, effectiveDate)
        assertEquals(0x20.toByte(), tvr.getValue()[1])
    }

    @Test
    fun testCheckAUC() {
        val tvr = TerminalVerificationResults()
        val auc = byteArrayOf(0xFF.toByte()) // Goods allowed
        val cardCountry = byteArrayOf(0x08, 0x40) // Example country code
        val termCountry = byteArrayOf(0x08, 0x40)
        tvr.checkAUC(auc, cardCountry, termCountry)
        assertEquals(0x00.toByte(), tvr.getValue()[1]) // Assuming the AUC matches
    }

    @Test
    fun testSetCardholderVerificationFailed() {
        val tvr = TerminalVerificationResults()
        tvr.setCardholderVerificationFailed()
        assertEquals(0x80.toByte(), tvr.getValue()[2])
    }

    @Test
    fun testSetFloorLimitExceed() {
        val tvr = TerminalVerificationResults()
        tvr.setFloorLimitExceed()
        assertEquals(0x80.toByte(), tvr.getValue()[3])
    }

    @Test
    fun testSetIssuerAuthenticationFailed() {
        val tvr = TerminalVerificationResults()
        tvr.setIssuerAuthenticationFailed()
        assertEquals(0x40.toByte(), tvr.getValue()[4])
    }
}
