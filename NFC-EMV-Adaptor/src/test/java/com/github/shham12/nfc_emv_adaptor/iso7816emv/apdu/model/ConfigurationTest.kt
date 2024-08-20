package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.model

import com.github.shham12.nfc_emv_adaptor.exception.TLVException
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.Configuration
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class ConfigurationTest {
    private lateinit var configuration: Configuration

    @Before
    fun setUp() {
        configuration = Configuration()
    }

    @Test
    fun testLoadAIDWithExactMatch() {
        val aid = "A0000000031010".toByteArray()
        val result = configuration.loadAID(aid)
        assertEquals("22", result["9F35"]?.let { bytesToString(it) })
    }

    @Test
    fun testLoadAIDWithPrefix() {
        val aid = "A000000025010402".toByteArray()
        val result = configuration.loadAID(aid)
        assertEquals("22", result["9F35"]?.let { bytesToString(it) })
        assertEquals("A00000002501", configuration.getSelectedAID())
    }

    @Test
    fun testLoadAIDWithUnsupportedAID() {
        val aid = "B0000000031010".toByteArray()
        assertThrows<TLVException> {
            configuration.loadAID(aid)
        }
    }

    @Test
    fun testIsExceedCVMLimit() {
        configuration.loadAID("A0000000031010".toByteArray())
        assertFalse(configuration.isExceedCVMLimit("000000000500".toByteArray()))
        assertTrue(configuration.isExceedCVMLimit("000000001500".toByteArray()))
    }

    @Test
    fun testIsExceedFloorLimit() {
        configuration.loadAID("A0000000031010".toByteArray())
        assertFalse(configuration.isExceedFloorLimit("000000000000".toByteArray()))
        assertTrue(configuration.isExceedFloorLimit("000000000001".toByteArray()))
    }

    @Test
    fun testKernelChecks() {
        configuration.loadAID("A0000000031010".toByteArray())
        assertTrue(configuration.isKernel3())
        assertFalse(configuration.isKernel4())
        assertFalse(configuration.isKernel5())
        assertFalse(configuration.isKernel6())

        configuration.loadAID("A00000002501".toByteArray())
        assertFalse(configuration.isKernel3())
        assertTrue(configuration.isKernel4())
        assertFalse(configuration.isKernel5())
        assertFalse(configuration.isKernel6())
    }

    @Test
    fun testUpdateOrInsert() {
        val aid = "A0000000031010"
        val tag = "9F35"
        val newValue = "33".toByteArray()

        configuration.updateOrInsert(aid, tag, newValue)
        val result = configuration.loadAID(aid.toByteArray())
        assertEquals("33", result[tag]?.let { bytesToString(it) })
    }

    @Test
    fun testSetConfiguration() {
        val jsonConfig = """
            [
                {
                    "9F06": "A0000000031010",
                    "9F40": "E0C8E06400",
                    "AidRecommendedName": null,
                    "9F09": "",
                    "CardBrand": "VISA",
                    "DF8117": "",
                    "DF19": "000000000000",
                    "DF8118": "",
                    "9F6E": "D8004000",
                    "Host": null,
                    "9F6D": "C0",
                    "9F15": "1234",
                    "9F4E": "4E464320454D562041646170746F72",
                    "9F33": "8028C8",
                    "9F1A": "0840",
                    "5F2A": "0840",
                    "9F66": "23C04000",
                    "9F35": "23"
                }
            ]
        """.trimIndent()

        configuration.setConfiguration(jsonConfig)

        // Verifying that EMV tags are correctly set
        val result = configuration.loadAID("A0000000031010".toByteArray())
        assertEquals("E0C8E06400", result["9F40"]?.let { bytesToString(it).uppercase() })
        assertEquals("1234", result["9F15"]?.let { bytesToString(it) })
        assertEquals("23", result["9F35"]?.let { bytesToString(it).uppercase() })

        // Verifying that non-EMV tags are ignored
        assertNull(result["AidRecommendedName"])
        assertNull(result["CardBrand"])
        assertNull(result["Host"])

        // Simulate an update that removes the AID
        val newJsonConfig = """
            [
                {
                    "9F06": "A0000000031010" // Only one AID, no additional tags
                }
            ]
        """.trimIndent()

        // Apply the new configuration
        configuration.setConfiguration(newJsonConfig)

        // Verifying that EMV tags remain for the existing AID
        assertTrue(configuration.getAllData().isEmpty())
    }
}