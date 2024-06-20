package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.model

import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.time.LocalDate
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import kotlin.experimental.and
import kotlin.experimental.or

class EMVTransactionRecordTest {
    private lateinit var emvTransactionRecord: EMVTransactionRecord

    @Before
    fun setUp() {
        emvTransactionRecord = EMVTransactionRecord()
    }

    @Test
    fun testClear() {
        emvTransactionRecord.clear()
        val tags = emvTransactionRecord.getEMVTags()
        assertEquals("22", String(tags["9F35"]!!))
        assertEquals("D8004000", String(tags["9F6E"]!!))
        assertEquals("20404000", String(tags["9F66"]!!))
        assertEquals("000000000001", String(tags["9F02"]!!))
        assertEquals("000000000000", String(tags["9F03"]!!))
        assertEquals("0840", String(tags["9F1A"]!!))
        assertEquals("0000000000", String(tags["95"]!!))
        assertEquals("0840", String(tags["5F2A"]!!))
        assertEquals("00", String(tags["9C"]!!))
        assertEquals("0000", String(tags["9F45"]!!))
        assertEquals("0000", String(tags["9F4C"]!!))
        assertEquals("000000", String(tags["9F34"]!!))
        assertEquals("E0C8E06400", String(tags["9F40"]!!))
        assertEquals("0000000000", String(tags["9F1D"]!!))
        assertEquals("8028C8", String(tags["9F33"]!!))
        assertEquals("1F0000", String(tags["9F34"]!!))
        assertEquals("000000", String(tags["9F4E"]!!))
        assertEquals("C0", String(tags["9F6D"]!!))
    }

    @Test
    fun testSetAmount1() {
        val amount = "000000000100".toByteArray()
        emvTransactionRecord.setAmount1(amount)
        assertTrue(emvTransactionRecord.getEMVTags()["9F02"]!!.contentEquals(amount))
    }

    @Test
    fun testSetAmount2() {
        val amount = "000000000200".toByteArray()
        emvTransactionRecord.setAmount2(amount)
        assertTrue(emvTransactionRecord.getEMVTags()["9F03"]!!.contentEquals(amount))
    }

    @Test
    fun testSetModifiedTerminalType() {
        emvTransactionRecord.clear()
        emvTransactionRecord.setModifiedTerminalType()
        val modifiedTerminalType = emvTransactionRecord.getEMVTags()["9F35"]
        assertNotNull(modifiedTerminalType)
        val expectedValue = emvTransactionRecord.getEMVTags()["9F35"]!![0] or emvTransactionRecord.getEMVTags()["9F6D"]!![0]
        assertEquals(expectedValue, modifiedTerminalType!![0])
    }

    @Test
    fun testSetTransactionType() {
        val transactionType = "09".toByteArray()
        emvTransactionRecord.setTransactionType(transactionType)
        assertTrue(emvTransactionRecord.getEMVTags()["9C"]!!.contentEquals(transactionType))
    }

    @Test
    fun testSetTransactionDate() {
        emvTransactionRecord.clear()
        val expectedDate = LocalDate.now().format(DateTimeFormatter.ofPattern("yyMMdd")).toByteArray()
        assertArrayEquals(expectedDate, emvTransactionRecord.getEMVTags()["9A"])
    }

    @Test
    fun testSetTransactionTime() {
        emvTransactionRecord.clear()
        val expectedTime = LocalTime.now().format(DateTimeFormatter.ofPattern("HHmmss")).toByteArray()
        assertArrayEquals(expectedTime, emvTransactionRecord.getEMVTags()["9F21"])
    }

    @Test
    fun testSetUnpredictableNumber() {
        emvTransactionRecord.clear()
        val unpredictableNumber = emvTransactionRecord.getUnpredictableNumber()
        assertNotNull(unpredictableNumber)
        assertEquals(4, unpredictableNumber.size)
    }

    @Test
    fun testSetAID() {
        val aid = byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x25.toByte())
        emvTransactionRecord.setAID(aid)
        assertTrue(emvTransactionRecord.getAID().contentEquals(aid))
    }

    @Test
    fun testSetApplicationInterchangeProfile() {
        val profile = "1234".toByteArray()
        emvTransactionRecord.setApplicationInterchangeProfile(profile)
        assertTrue(emvTransactionRecord.getEMVTags()["82"]!!.contentEquals(profile))
    }

    @Test
    fun testIsCardSupportSDA() {
        val profile = byteArrayOf(0x40.toByte())  // Bit 6 is set
        emvTransactionRecord.setApplicationInterchangeProfile(profile)
        assertTrue(emvTransactionRecord.isCardSupportSDA())
    }

    @Test
    fun testIsCardSupportDDA() {
        val profile = byteArrayOf(0x20.toByte())  // Bit 5 is set
        emvTransactionRecord.setApplicationInterchangeProfile(profile)
        assertTrue(emvTransactionRecord.isCardSupportDDA())
    }

    @Test
    fun testIsCardSupportCDA() {
        val profile = byteArrayOf(0x01.toByte())  // Bit 0 is set
        emvTransactionRecord.setApplicationInterchangeProfile(profile)
        assertTrue(emvTransactionRecord.isCardSupportCDA())
    }

    @Test
    fun testIsSupportODA() {
        val profile = byteArrayOf(0x61.toByte())  // Bits 6, 5, and 0 are set
        emvTransactionRecord.setApplicationInterchangeProfile(profile)
        assertTrue(emvTransactionRecord.isSupportODA())
    }

    @Test
    fun testHasAmexRID() {
        val aid = byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x25.toByte())
        emvTransactionRecord.setAID(aid)
        assertTrue(emvTransactionRecord.hasAmexRID())
    }

    @Test
    fun testGetIssuerPublicKeyRemainder() {
        val remainder = "12345678".toByteArray()
        emvTransactionRecord.addEMVTagValue("92", remainder)
        assertArrayEquals(remainder, emvTransactionRecord.getIssuerPublicKeyRemainder())
    }

    @Test
    fun testGetPAN() {
        val pan = "1234567890123456".toByteArray()
        emvTransactionRecord.addEMVTagValue("5A", pan)
        assertArrayEquals(pan, emvTransactionRecord.getPAN())
    }

    @Test
    fun testGetIssuerPublicKeyExponent() {
        val exponent = "03".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F32", exponent)
        assertArrayEquals(exponent, emvTransactionRecord.getIssuerPublicKeyExponent())
    }

    @Test
    fun testGetICCPublicKeyExponent() {
        val exponent = "03".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F47", exponent)
        assertArrayEquals(exponent, emvTransactionRecord.getICCPublicKeyExponent())
    }

    @Test
    fun testGetICCPublicKeyCertificate() {
        val certificate = "1234567890".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F46", certificate)
        assertArrayEquals(certificate, emvTransactionRecord.getICCPublicKeyCertificate())
    }

    @Test
    fun testGetICCPublicKeyRemainder() {
        val remainder = "1234567890".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F48", remainder)
        assertArrayEquals(remainder, emvTransactionRecord.getICCPublicKeyRemainder())
    }

    @Test
    fun testGetStaticDataAuthenticationTagList() {
        val tagList = "123456".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F4A", tagList)
        assertArrayEquals(tagList, emvTransactionRecord.getStaticDataAuthenticationTagList())
    }

    @Test
    fun testGetSignedDynamicApplicationData() {
        val dynamicData = "1234567890".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F4B", dynamicData)
        assertArrayEquals(dynamicData, emvTransactionRecord.getSignedDynamicApplicationData())
    }

    @Test
    fun testGetSignedStaticApplicationData() {
        val staticData = "1234567890".toByteArray()
        emvTransactionRecord.addEMVTagValue("93", staticData)
        assertArrayEquals(staticData, emvTransactionRecord.getSignedStaticApplicationData())
    }

    @Test
    fun testGetCryptogramInformationData() {
        val cryptogramData = "123456".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F27", cryptogramData)
        assertArrayEquals(cryptogramData, emvTransactionRecord.getCryptogramInformationData())
    }

    @Test
    fun testGetUnpredictableNumber() {
        val unpredictableNumber = "1234".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F37", unpredictableNumber)
        assertArrayEquals(unpredictableNumber, emvTransactionRecord.getUnpredictableNumber())
    }

    @Test
    fun testGetPDOL() {
        val pdol = "123456".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F38", pdol)
        assertArrayEquals(pdol, emvTransactionRecord.getPDOL())
    }

    @Test
    fun testGetCDOL1() {
        val cdol1 = "123456".toByteArray()
        emvTransactionRecord.addEMVTagValue("8C", cdol1)
        assertArrayEquals(cdol1, emvTransactionRecord.getCDOL1())
    }

    @Test
    fun testSetODANotPerformed() {
        emvTransactionRecord.clear()
        emvTransactionRecord.setODANotPerformed()
        assertEquals(0x80.toByte(), emvTransactionRecord.getEMVTags()["95"]!![0] and 0x80.toByte())
    }

    @Test
    fun testSetSDAFailed() {
        emvTransactionRecord.clear()
        emvTransactionRecord.setSDAFailed()
        assertEquals(0x40.toByte(), emvTransactionRecord.getEMVTags()["95"]!![0] and 0x40.toByte())
    }

    @Test
    fun testSetDDAFailed() {
        emvTransactionRecord.clear()
        emvTransactionRecord.setDDAFailed()
        assertEquals(0x08.toByte(), emvTransactionRecord.getEMVTags()["95"]!![0] and 0x08.toByte())
    }

    @Test
    fun testSetCDAFailed() {
        emvTransactionRecord.clear()
        emvTransactionRecord.setCDAFailed()
        assertEquals(0x04.toByte(), emvTransactionRecord.getEMVTags()["95"]!![0] and 0x04.toByte())
    }

    @Test
    fun testSetSDASelected() {
        emvTransactionRecord.clear()
        emvTransactionRecord.setSDASelected()
        assertEquals(0x02.toByte(), emvTransactionRecord.getEMVTags()["95"]!![0] and 0x02.toByte())
    }

    @Test
    fun testGetResponseMessageTemplate2() {
        val responseMessage = "1234567890".toByteArray()
        emvTransactionRecord.addEMVTagValue("77", responseMessage)
        assertArrayEquals(responseMessage, emvTransactionRecord.getResponseMessageTemplate2())
    }

    @Test
    fun testAddEMVTagValue() {
        val tag = "DF01"
        val value = "123456".toByteArray()
        emvTransactionRecord.addEMVTagValue(tag, value)
        assertTrue(emvTransactionRecord.getEMVTags()[tag]!!.contentEquals(value))
    }

    @Test
    fun testCheckAppVerNum() {
        emvTransactionRecord.clear()
        val cardAppVer = "0102".toByteArray()
        val termAppVer = "0103".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F08", cardAppVer)
        emvTransactionRecord.addEMVTagValue("9F09", termAppVer)
        emvTransactionRecord.checkAppVerNum()
        assertEquals(0x80.toByte(), emvTransactionRecord.getEMVTags()["95"]!![1] and 0x80.toByte())
    }

    @Test
    fun testCheckAUC() {
        emvTransactionRecord.clear()
        val AUC = byteArrayOf(0x00)
        val cardCountry = "0840".toByteArray()
        val termCountry = "0840".toByteArray()
        emvTransactionRecord.addEMVTagValue("9F07", AUC)
        emvTransactionRecord.addEMVTagValue("9F57", cardCountry)
        emvTransactionRecord.addEMVTagValue("9F1A", termCountry)
        emvTransactionRecord.checkAUC()
        assertEquals(0x10.toByte(), emvTransactionRecord.getEMVTags()["95"]!![1] and 0x10.toByte())
    }

    @Test
    fun testCheckEffectiveAndExpirationDate() {
        emvTransactionRecord.clear()
        val effectiveDate = LocalDate.now().plusDays(1).format(DateTimeFormatter.ofPattern("yyMMdd")).toByteArray()
        val expireDate = LocalDate.now().minusDays(1).format(DateTimeFormatter.ofPattern("yyMMdd")).toByteArray()
        emvTransactionRecord.addEMVTagValue("5F25", effectiveDate)
        emvTransactionRecord.addEMVTagValue("5F24", expireDate)
        emvTransactionRecord.addEMVTagValue("9A", LocalDate.now().format(DateTimeFormatter.ofPattern("yyMMdd")).toByteArray())
        emvTransactionRecord.checkEffectiveAndExpirationDate()
        assertEquals(0x20.toByte(), emvTransactionRecord.getEMVTags()["95"]!![1] and 0x20.toByte())
        assertEquals(0x40.toByte(), emvTransactionRecord.getEMVTags()["95"]!![1] and 0x40.toByte())
    }

    @Test
    fun testProcessCVM_Signature() {
        emvTransactionRecord.clear()
        val AIP = byteArrayOf(0x10)  // Support CVM
        val cvmList = "000007D000000000410342031E06".toByteArray()  // Signature
        emvTransactionRecord.addEMVTagValue("82", AIP)
        emvTransactionRecord.addEMVTagValue("8E", cvmList)
        val amountExceedingLimit = "000000010001".toByteArray()  // CVM 제한을 초과하는 금액
        emvTransactionRecord.setAmount1(amountExceedingLimit)
        emvTransactionRecord.processCVM()
        assertArrayEquals("1E0000".toByteArray(), emvTransactionRecord.getEMVTags()["9F34"])
        assertEquals(0x40.toByte(), emvTransactionRecord.getEMVTags()["9B"]!![0] and 0x40.toByte())
    }

    @Test
    fun testProcessCVM_NoCVMRequired() {
        emvTransactionRecord.clear()
        val AIP = byteArrayOf(0x10)  // Support CVM
        val cvmList = "1F02".toByteArray()  // No CVM required
        emvTransactionRecord.addEMVTagValue("82", AIP)
        emvTransactionRecord.addEMVTagValue("8E", cvmList)
        val amountExceedingLimit = "000000010001".toByteArray()  // CVM 제한을 초과하는 금액
        emvTransactionRecord.setAmount1(amountExceedingLimit)
        emvTransactionRecord.processCVM()
        assertArrayEquals("1F0002".toByteArray(), emvTransactionRecord.getEMVTags()["9F34"])
        assertEquals(0x40.toByte(), emvTransactionRecord.getEMVTags()["9B"]!![0] and 0x40.toByte())
    }

    @Test
    fun testProcessCVM_NoMatchingCVM() {
        emvTransactionRecord.clear()
        val AIP = byteArrayOf(0x10)  // Support CVM
        val cvmList = "1E05".toByteArray()  // No matching CVM
        emvTransactionRecord.addEMVTagValue("82", AIP)
        emvTransactionRecord.addEMVTagValue("8E", cvmList)
        val amountExceedingLimit = "000000010001".toByteArray()  // CVM 제한을 초과하는 금액
        emvTransactionRecord.setAmount1(amountExceedingLimit)
        emvTransactionRecord.processCVM()
        assertArrayEquals("3F0001".toByteArray(), emvTransactionRecord.getEMVTags()["9F34"])
        assertEquals(0x40.toByte(), emvTransactionRecord.getEMVTags()["9B"]!![0] and 0x40.toByte())
    }

    @Test
    fun testProcessCVM_NotSupportCVM() {
        emvTransactionRecord.clear()
        val AIP = byteArrayOf(0x00)  // Not support CVM
        val cvmList = "1E06".toByteArray()  // Signature
        emvTransactionRecord.addEMVTagValue("82", AIP)
        emvTransactionRecord.addEMVTagValue("8E", cvmList)
        val amountExceedingLimit = "000000010001".toByteArray()  // CVM 제한을 초과하는 금액
        emvTransactionRecord.setAmount1(amountExceedingLimit)
        emvTransactionRecord.processCVM()
        assertArrayEquals("3F0000".toByteArray(), emvTransactionRecord.getEMVTags()["9F34"])
    }

    @Test
    fun testProcessCVM_NoCVMPerformed() {
        emvTransactionRecord.clear()
        val AIP = byteArrayOf(0x10)  // Support CVM
        val cvmList = "1E06".toByteArray()  // Signature
        emvTransactionRecord.addEMVTagValue("82", AIP)
        emvTransactionRecord.addEMVTagValue("8E", cvmList)
        val amountNotExceedingLimit = "000000000001".toByteArray()  // CVM 제한을 초과하지 않는 금액
        emvTransactionRecord.setAmount1(amountNotExceedingLimit)
        emvTransactionRecord.processCVM()
        assertArrayEquals("3F0000".toByteArray(), emvTransactionRecord.getEMVTags()["9F34"])
    }

    @Test
    fun testProcessCVM_NoCVMList() {
        emvTransactionRecord.clear()
        val AIP = byteArrayOf(0x10)  // Support CVM
        emvTransactionRecord.addEMVTagValue("82", AIP)
        val amountExceedingLimit = "000000010001".toByteArray()  // CVM 제한을 초과하는 금액
        emvTransactionRecord.setAmount1(amountExceedingLimit)
        emvTransactionRecord.processCVM()
        assertArrayEquals("3F0000".toByteArray(), emvTransactionRecord.getEMVTags()["9F34"])
        assertEquals(0x20.toByte(), emvTransactionRecord.getEMVTags()["95"]!![0] and 0x20.toByte())
    }

    @Test
    fun testSetICCDataMissing() {
        emvTransactionRecord.clear()
        emvTransactionRecord.setICCDataMissing()
        assertEquals(0x20.toByte(), emvTransactionRecord.getEMVTags()["95"]!![0] and 0x20.toByte())
    }

    @Test
    fun testProcessTermRiskManagement() {
        emvTransactionRecord.clear()
        val AIP = byteArrayOf(0x08)  // Support Terminal Risk Management
        emvTransactionRecord.addEMVTagValue("82", AIP)
        emvTransactionRecord.processTermRiskManagement()
        // floor limit always exceeds need to check TVR B4b8
        assertEquals(0x80.toByte(), emvTransactionRecord.getEMVTags()["95"]!![3] and 0x80.toByte())
    }
}