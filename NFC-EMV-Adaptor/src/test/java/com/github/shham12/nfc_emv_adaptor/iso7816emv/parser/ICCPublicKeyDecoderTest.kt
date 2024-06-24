package com.github.shham12.nfc_emv_adaptor.iso7816emv.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.parser.ICCPublicKeyDecoder
import com.github.shham12.nfc_emv_adaptor.parser.IssuerPublicKeyDecoder
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray
import org.junit.Assert
import org.junit.Test

class ICCPublicKeyDecoderTest {
    @Test
    fun testRetrievalICCPublicKey() {
        // Sample data
        val emvRecord = EMVTransactionRecord()
        emvRecord.addEMVTagValue("90", ("20DF7FF4B9968169B50DABED606B2FA12A0A26ED0A9791F5FE16965AC3A3AC60924B" +
                "A722A7EA668D40C79A7A8F519949A2E7059CCD4685C16465084A47AA71192ABEF7D45AAE2513501D81BA" +
                "150A6C533B02026C275888DA3E2D62C1554ED49BC9BECABF24387B1BDE7A06E9861B6CC0F0DACCC00139" +
                "3D4E4CB976EBB3C2FC0165D4A32C0CB99BD8549B8295026620D028204524ACED3379558490450D21B6A0" +
                "62204FAF5160FE24CF5AC5F2D9B20533").toByteArray())
        emvRecord.addEMVTagValue("92", "8FC44EE8B5ECB266790274EEF50A9F6BD598C58C444508E6DF9AB7A5028DE7DEB5DA6BDB".toByteArray())
        emvRecord.addEMVTagValue("9F32", "03".toByteArray())
        emvRecord.addEMVTagValue("5A", "374245002751005F".toByteArray())
        emvRecord.addEMVTagValue("9F46", ("5F9CAF135C826BE612AFE7FE141E3D41E1E7A2AF8BB5EDE18745225954ABEA5362C94BBB" +
                "F13C3CAD1F08BD1D6BD9C424EF0EF6DEDE36BD292E12DA7C24459E2FBEC191C625032F59B7F61E045DC6E536F0E53D0ACB0" +
                "E8E342DC79F2384C37E346C7B56326898DEDB7766603FAC80691ABAE30593E909F4B5E39236D0EB4508214E2BD0344B72CB" +
                "D1048B294A592B84BA01E646760ED07B5AF0034FB3EA9D78409CFE45E3BDF916DA1789C924F2379AE6").toByteArray())
        emvRecord.addEMVTagValue("9F47", "03".toByteArray())
        emvRecord.addEMVTagValue("9F32", "03".toByteArray())
        emvRecord.addEMVTagValue("9F37", "A25B09ED".toByteArray())
        emvRecord.addEMVTagValue("9F4A", "82".toByteArray())
        emvRecord.addEMVTagValue("82", "19C0".toByteArray())

        val caPublicKey = CaPublicKey(
            rid = "A000000025",
            index = "C9",
            exponent = "03",
            modulus = "B362DB5733C15B8797B8ECEE55CB1A371F760E0BEDD3715BB270424FD4EA26062C38C3F4AAA3732A83D36EA8E9602F6683EECC6BAFF63DD2D49014BDE4D6D603CD744206B05B4BAD0C64C63AB3976B5C8CAAF8539549F5921C0B700D5B0F83C4E7E946068BAAAB5463544DB18C63801118F2182EFCC8A1E85E53C2A7AE839A5C6A3CABE73762B70D170AB64AFC6CA482944902611FB0061E09A67ACB77E493D998A0CCF93D81A4F6C0DC6B7DF22E62DB"
        )

        // Execute
        val result = ICCPublicKeyDecoder.retrievalICCPublicKeyModulus(emvRecord, caPublicKey)

        // Validate
        Assert.assertNotNull(result)
        // Add more assertions as needed to validate the returned result
        Assert.assertTrue(emvRecord.getEMVTags()["95"]!![0].toInt() == 0x00)
    }

    @Test
    fun testRetrievalICCPublicKey_2() {
        // Sample data
        val emvRecord = EMVTransactionRecord()
        emvRecord.addEMVTagValue("90", ("7F4C6034C33BF35BAFFF53F51C0F8A2B32C8FDE1D033DDB69DCA85C5B4797BD2F55BE970C026B75B76E9C" +
                "17E8564111FDEB97B26E350F59F6C63C30B0BD80E33123DF73CF8F87B28D54D28E4D6284F44E6E61AD95826474EBF6C28796B9B222DF14194A" +
                "539E92DB185D86D8EDDD8AA01ECBE93E0EC3F87383D879534FE0BD397D7D59FC6E37012258B894400EE715338").toByteArray())
        emvRecord.addEMVTagValue("92", "9A2FA99FC6CCA575875E108D7D847600A0D0863C549553E12EC75362597CEB2F16780BF1".toByteArray())
        emvRecord.addEMVTagValue("9F32", "03".toByteArray())
        emvRecord.addEMVTagValue("5A", "4578965000000016FFFF".toByteArray())
        emvRecord.addEMVTagValue("9F46", ("1640CA8EEC4BA011D575D46F601DFBB22252076BDFD5360D7773BC38BE971A8526A3CEE1EDFD9BDC69C" +
                "EE6E71D91A4B731C8B4290F5E4ADD046AAB8245CC07794030038C5FCB4270B15DEA6D895CCF67916314D5EC7F86BDD640792454870773BE5D2" +
                "8740FF1970C02A694C7AAEB9145D89F2BED9D8C982A2D388EFA0F26E86F73AFDB32A93913E28C6569F04DE4C509").toByteArray())
        emvRecord.addEMVTagValue("9F47", "03".toByteArray())
        emvRecord.addEMVTagValue("9F48", "2F40C2050FCB169EF11D".toByteArray())
        emvRecord.addEMVTagValue("9F32", "03".toByteArray())
        emvRecord.addEMVTagValue("9F37", "A25B09ED".toByteArray())
        emvRecord.addEMVTagValue("9F4A", "82".toByteArray())
        emvRecord.addEMVTagValue("82", "2000".toByteArray())


        val caPublicKey = CaPublicKey(
            rid = "A000000029",
            index = "95",
            exponent = "03",
            modulus = "BE9E1FA5E9A803852999C4AB432DB28600DCD9DAB76DFAAA47355A0FE37B1508AC6BF38860D3C6C2E5B12A3CAAF2A7005A7241EBAA7771112C74CF9A0634652FBCA0E5980C54A64761EA101A114E0F0B5572ADD57D010B7C9C887E104CA4EE1272DA66D997B9A90B5A6D624AB6C57E73C8F919000EB5F684898EF8C3DBEFB330C62660BED88EA78E909AFF05F6DA627B"
        )

        // Execute
        val result = ICCPublicKeyDecoder.retrievalICCPublicKeyModulus(emvRecord, caPublicKey)

        // Validate
        Assert.assertNotNull(result)
        // Add more assertions as needed to validate the returned result
        Assert.assertTrue(result.contentEquals(("A5ECC75561EFE21E8DD77F32C05B41F39902B6F430C09F270FB09B53CA22F3E" +
                "90CDD4613073AC20DF17528BACA7E18C2FDCECD33105D180FB2074727456AE104FE81FE1A0AB922A0CC8A394DE782D7888F6" +
                "36F3F07535864CBFB0DA32C22A2C704F4F209CF902F40C2050FCB169EF11D").toByteArray()))
    }
}