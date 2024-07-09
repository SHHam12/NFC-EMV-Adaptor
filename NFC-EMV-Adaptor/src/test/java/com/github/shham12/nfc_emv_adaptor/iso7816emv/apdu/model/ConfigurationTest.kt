package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.model

import com.github.shham12.nfc_emv_adaptor.exception.TLVException
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.Configuration
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray
import org.junit.Assert.*
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
}