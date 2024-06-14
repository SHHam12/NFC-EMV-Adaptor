package com.github.shham12.nfc_emv_adaptor.iso7816emv.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.parser.IssuerPublicKeyDecoder
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import org.junit.Assert.*
import org.junit.Test
class IssuerPublicKeyDecoderTest {

    @Test
    fun testRetrievalIssuerPublicKey() {
        // Sample data
        val emvTags = mutableMapOf(
            "90" to byteArrayOf(0x20.toByte(), 0xDF.toByte(), 0x7F.toByte(), 0xF4.toByte(), 0xB9.toByte(), 0x96.toByte(), 0x81.toByte(), 0x69.toByte(),
                0xB5.toByte(), 0x0D.toByte(), 0xAB.toByte(), 0xED.toByte(), 0x60.toByte(), 0x6B.toByte(), 0x2F.toByte(), 0xA1.toByte(), 0x2A.toByte(),
                0x0A.toByte(), 0x26.toByte(), 0xED.toByte(), 0x0A.toByte(), 0x97.toByte(), 0x91.toByte(), 0xF5.toByte(), 0xFE.toByte(), 0x16.toByte(),
                0x96.toByte(), 0x5A.toByte(), 0xC3.toByte(), 0xA3.toByte(), 0xAC.toByte(), 0x60.toByte(), 0x92.toByte(), 0x4B.toByte(), 0xA7.toByte(),
                0x22.toByte(), 0xA7.toByte(), 0xEA.toByte(), 0x66.toByte(), 0x8D.toByte(), 0x40.toByte(), 0xC7.toByte(), 0x9A.toByte(), 0x7A.toByte(),
                0x8F.toByte(), 0x51.toByte(), 0x99.toByte(), 0x49.toByte(), 0xA2.toByte(), 0xE7.toByte(), 0x05.toByte(), 0x9C.toByte(), 0xCD.toByte(),
                0x46.toByte(), 0x85.toByte(), 0xC1.toByte(), 0x64.toByte(), 0x65.toByte(), 0x08.toByte(), 0x4A.toByte(), 0x47.toByte(), 0xAA.toByte(),
                0x71.toByte(), 0x19.toByte(), 0x2A.toByte(), 0xBE.toByte(), 0xF7.toByte(), 0xD4.toByte(), 0x5A.toByte(), 0xAE.toByte(), 0x25.toByte(),
                0x13.toByte(), 0x50.toByte(), 0x1D.toByte(), 0x81.toByte(), 0xBA.toByte(), 0x15.toByte(), 0x0A.toByte(), 0x6C.toByte(), 0x53.toByte(),
                0x3B.toByte(), 0x02.toByte(), 0x02.toByte(), 0x6C.toByte(), 0x27.toByte(), 0x58.toByte(), 0x88.toByte(), 0xDA.toByte(), 0x3E.toByte(),
                0x2D.toByte(), 0x62.toByte(), 0xC1.toByte(), 0x55.toByte(), 0x4E.toByte(), 0xD4.toByte(), 0x9B.toByte(), 0xC9.toByte(), 0xBE.toByte(),
                0xCA.toByte(), 0xBF.toByte(), 0x24.toByte(), 0x38.toByte(), 0x7B.toByte(), 0x1B.toByte(), 0xDE.toByte(), 0x7A.toByte(), 0x06.toByte(),
                0xE9.toByte(), 0x86.toByte(), 0x1B.toByte(), 0x6C.toByte(), 0xC0.toByte(), 0xF0.toByte(), 0xDA.toByte(), 0xCC.toByte(), 0xC0.toByte(),
                0x01.toByte(), 0x39.toByte(), 0x3D.toByte(), 0x4E.toByte(), 0x4C.toByte(), 0xB9.toByte(), 0x76.toByte(), 0xEB.toByte(), 0xB3.toByte(),
                0xC2.toByte(), 0xFC.toByte(), 0x01.toByte(), 0x65.toByte(), 0xD4.toByte(), 0xA3.toByte(), 0x2C.toByte(), 0x0C.toByte(), 0xB9.toByte(),
                0x9B.toByte(), 0xD8.toByte(), 0x54.toByte(), 0x9B.toByte(), 0x82.toByte(), 0x95.toByte(), 0x02.toByte(), 0x66.toByte(), 0x20.toByte(),
                0xD0.toByte(), 0x28.toByte(), 0x20.toByte(), 0x45.toByte(), 0x24.toByte(), 0xAC.toByte(), 0xED.toByte(), 0x33.toByte(), 0x79.toByte(),
                0x55.toByte(), 0x84.toByte(), 0x90.toByte(), 0x45.toByte(), 0x0D.toByte(), 0x21.toByte(), 0xB6.toByte(), 0xA0.toByte(), 0x62.toByte(),
                0x20.toByte(), 0x4F.toByte(), 0xAF.toByte(), 0x51.toByte(), 0x60.toByte(), 0xFE.toByte(), 0x24.toByte(), 0xCF.toByte(), 0x5A.toByte(),
                0xC5.toByte(), 0xF2.toByte(), 0xD9.toByte(), 0xB2.toByte(), 0x05.toByte(), 0x33.toByte()),
            "92" to byteArrayOf(0x8F.toByte(), 0xC4.toByte(), 0x4E.toByte(), 0xE8.toByte(), 0xB5.toByte(), 0xEC.toByte(), 0xB2.toByte(), 0x66.toByte(),
                0x79.toByte(), 0x02.toByte(), 0x74.toByte(), 0xEE.toByte(), 0xF5.toByte(), 0x0A.toByte(), 0x9F.toByte(), 0x6B.toByte(), 0xD5.toByte(),
                0x98.toByte(), 0xC5.toByte(), 0x8C.toByte(), 0x44.toByte(), 0x45.toByte(), 0x08.toByte(), 0xE6.toByte(), 0xDF.toByte(), 0x9A.toByte(),
                0xB7.toByte(), 0xA5.toByte(), 0x02.toByte(), 0x8D.toByte(), 0xE7.toByte(), 0xDE.toByte(), 0xB5.toByte(), 0xDA.toByte(), 0x6B.toByte(), 0xDB.toByte()),
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