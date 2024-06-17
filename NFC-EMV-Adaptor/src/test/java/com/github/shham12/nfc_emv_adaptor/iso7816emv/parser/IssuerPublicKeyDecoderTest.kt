package com.github.shham12.nfc_emv_adaptor.iso7816emv.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.parser.IssuerPublicKeyDecoder
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.fromString
import org.junit.Assert.*
import org.junit.Test
class IssuerPublicKeyDecoderTest {

    @Test
    fun testRetrievalIssuerPublicKey() {
        // Sample data
        val emvTags = mutableMapOf(
            "90" to fromString("20DF7FF4B9968169B50DABED606B2FA12A0A26ED0A9791F5FE16965AC3A3AC60924B" +
                    "A722A7EA668D40C79A7A8F519949A2E7059CCD4685C16465084A47AA71192ABEF7D45AAE2513501D81BA" +
                    "150A6C533B02026C275888DA3E2D62C1554ED49BC9BECABF24387B1BDE7A06E9861B6CC0F0DACCC00139" +
                    "3D4E4CB976EBB3C2FC0165D4A32C0CB99BD8549B8295026620D028204524ACED3379558490450D21B6A0" +
                    "62204FAF5160FE24CF5AC5F2D9B20533"),
            "92" to fromString("8FC44EE8B5ECB266790274EEF50A9F6BD598C58C444508E6DF9AB7A5028DE7DEB5DA6BDB"),
            "9F32" to byteArrayOf(0x03.toByte()),
            "5A" to byteArrayOf(0x37.toByte(), 0x42.toByte(), 0x45.toByte(), 0x00.toByte(), 0x27.toByte(), 0x51.toByte(), 0x00.toByte(), 0x5F.toByte())
        )

        val caPublicKey = CaPublicKey(
            rid = "A000000025",
            index = "C9",
            exponent = "03",
            modulus = "B362DB5733C15B8797B8ECEE55CB1A371F760E0BEDD3715BB270424FD4EA26062C38C3F4AAA3732A83D36EA8E9602F6683EECC6BAFF63DD2D49014BDE4D6D603CD744206B05B4BAD0C64C63AB3976B5C8CAAF8539549F5921C0B700D5B0F83C4E7E946068BAAAB5463544DB18C63801118F2182EFCC8A1E85E53C2A7AE839A5C6A3CABE73762B70D170AB64AFC6CA482944902611FB0061E09A67ACB77E493D998A0CCF93D81A4F6C0DC6B7DF22E62DB"
        )

        // Execute
        val result = IssuerPublicKeyDecoder.retrievalIssuerPublicKeyModulus(emvTags, caPublicKey)

        // Validate
        assertNotNull(result)
        // Add more assertions as needed to validate the returned result
        val issuerPublicKeyModulus = "CAFACCC90D61D0469BFE90FB93EC91CFC778A4BAB22377D361D7FA536D85AB3D8546B26CE145A096462BF08247773FDAA4818D5B90789A4DFDDC148D520AA75C3775E4F2E0CD240536FDF05E90DD0C6CB2EC25B85B4480F64B6852C7B71D152C461D18E25571FE6C2069840EFBCDEF880F7EF8B0FB7C3E2B89C95F003F977A337B82C10EFF4E27A55A757C628FC44EE8B5ECB266790274EEF50A9F6BD598C58C444508E6DF9AB7A5028DE7DEB5DA6BDB"
        assertEquals(issuerPublicKeyModulus, bytesToString(result).uppercase())
    }
}