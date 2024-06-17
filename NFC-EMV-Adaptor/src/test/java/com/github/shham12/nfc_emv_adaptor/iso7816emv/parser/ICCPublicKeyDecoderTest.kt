package com.github.shham12.nfc_emv_adaptor.iso7816emv.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.parser.ICCPublicKeyDecoder
import com.github.shham12.nfc_emv_adaptor.parser.IssuerPublicKeyDecoder
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import org.junit.Assert
import org.junit.Test

class ICCPublicKeyDecoderTest {
    @Test
    fun testRetrievalIssuerPublicKey() {
        // Sample data
        val emvTags = mutableMapOf(
            "90" to BytesUtils.fromString(
                "20DF7FF4B9968169B50DABED606B2FA12A0A26ED0A9791F5FE16965AC3A3AC60924B" +
                        "A722A7EA668D40C79A7A8F519949A2E7059CCD4685C16465084A47AA71192ABEF7D45AAE2513501D81BA" +
                        "150A6C533B02026C275888DA3E2D62C1554ED49BC9BECABF24387B1BDE7A06E9861B6CC0F0DACCC00139" +
                        "3D4E4CB976EBB3C2FC0165D4A32C0CB99BD8549B8295026620D028204524ACED3379558490450D21B6A0" +
                        "62204FAF5160FE24CF5AC5F2D9B20533"
            ),
            "92" to BytesUtils.fromString("8FC44EE8B5ECB266790274EEF50A9F6BD598C58C444508E6DF9AB7A5028DE7DEB5DA6BDB"),
            "9F32" to byteArrayOf(0x03.toByte()),
            "5A" to byteArrayOf(0x37.toByte(), 0x42.toByte(), 0x45.toByte(), 0x00.toByte(), 0x27.toByte(), 0x51.toByte(), 0x00.toByte(), 0x5F.toByte()),
            "9F46" to BytesUtils.fromString("5F9CAF135C826BE612AFE7FE141E3D41E1E7A2AF8BB5EDE18745225954ABEA5362C94BBB" +
                    "F13C3CAD1F08BD1D6BD9C424EF0EF6DEDE36BD292E12DA7C24459E2FBEC191C625032F59B7F61E045DC6E536F0E53D0ACB0" +
                    "E8E342DC79F2384C37E346C7B56326898DEDB7766603FAC80691ABAE30593E909F4B5E39236D0EB4508214E2BD0344B72CB" +
                    "D1048B294A592B84BA01E646760ED07B5AF0034FB3EA9D78409CFE45E3BDF916DA1789C924F2379AE6"),
            "9F47" to byteArrayOf(0x03.toByte()),
            "9F32" to byteArrayOf(0x03.toByte()),
            "9F37" to byteArrayOf(0xA2.toByte(), 0x5B.toByte(), 0x09.toByte(), 0xED.toByte()),
            "9F4A" to byteArrayOf(0x82.toByte()),
            "82" to byteArrayOf(0x19.toByte(), 0xC0.toByte())
        )

        val caPublicKey = CaPublicKey(
            rid = "A000000025",
            index = "C9",
            exponent = "03",
            modulus = "B362DB5733C15B8797B8ECEE55CB1A371F760E0BEDD3715BB270424FD4EA26062C38C3F4AAA3732A83D36EA8E9602F6683EECC6BAFF63DD2D49014BDE4D6D603CD744206B05B4BAD0C64C63AB3976B5C8CAAF8539549F5921C0B700D5B0F83C4E7E946068BAAAB5463544DB18C63801118F2182EFCC8A1E85E53C2A7AE839A5C6A3CABE73762B70D170AB64AFC6CA482944902611FB0061E09A67ACB77E493D998A0CCF93D81A4F6C0DC6B7DF22E62DB"
        )

        // Execute
        val result = ICCPublicKeyDecoder.retrievalICCPublicKeyModulus(emvTags, caPublicKey)

        // Validate
        Assert.assertNotNull(result)
        // Add more assertions as needed to validate the returned result
    }
}