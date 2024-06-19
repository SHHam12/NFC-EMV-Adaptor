package com.github.shham12.nfc_emv_adaptor.iso7816emv.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.parser.SignedStaticApplicationDataDecoder
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.toByteArray
import org.junit.Assert
import org.junit.Test

class SignedStaticApplicationDataDecoderTest {
    @Test
    fun testRetrievalIssuerPublicKey() {
        // Sample data
        val emvRecord = EMVTransactionRecord()
        emvRecord.addEMVTagValue("90", ("191AB5AC03365D5E9515C398CCC5C744A728A4FCFDE194D0B88B0FA1673AEBDD8AAADF" +
                "0EDBBC12414E7107A9F2B02DFB3985167C0EE9CDF3CB78749BF6D0AAE60E4C979F7E2AE635A77451B0E2F2EB136AB02076" +
                "CBE1E70CC4EE5529434A9EC6").toByteArray())
        emvRecord.addEMVTagValue("92", "CFB8D4885D960967179F982D42CE54ECC2054683".toByteArray())
        emvRecord.addEMVTagValue("9F32", "03".toByteArray())
        emvRecord.addEMVTagValue("5A", "374245002751005F".toByteArray())
        emvRecord.addEMVTagValue("9F46", ("E114557C29B988766A39FBC88AEE7C85A40F66A700AF73E0D889199FDDAA3836516D8" +
                "587BD68EBCA5B99021E4175D3BA4BEB87B7D08C7B51C2B6F3E5CFB8D4885D960967179F982D42CE54ECC2054683").toByteArray())
        emvRecord.addEMVTagValue("9F47", "03".toByteArray())
        emvRecord.addEMVTagValue("9F32", "03".toByteArray())
        emvRecord.addEMVTagValue("9F37", "A25B09ED".toByteArray())
        emvRecord.addEMVTagValue("9F4A", "82".toByteArray())
        emvRecord.addEMVTagValue("82", "19C0".toByteArray())
        emvRecord.addEMVTagValue("93", ("110BB9DF2D21981906B29A301411F9FA60CF494DBABABF54B1797C9C4B5D99B5E" +
                "67AB73049E771FC5FDC23E58350B781005324D31DC87AD0FBF636733808056D66074632711E7CBF14073796E1B60D4D").toByteArray())

        val caPublicKey = CaPublicKey(
            rid = "A000000029",
            index = "97",
            exponent = "03",
            modulus = "AF0754EAED977043AB6F41D6312AB1E22A6809175BEB28E70D5F99B2DF18CAE73519341BBBD327D0B8BE9D4D0E15F07D36EA3E3A05C892F5B19A3E9D3413B0D97E7AD10A5F5DE8E38860C0AD004B1E06F4040C295ACB457A788551B6127C0B29"
        )

        // Execute
        SignedStaticApplicationDataDecoder.validate(emvRecord, caPublicKey)

        // Validate
        Assert.assertNotNull(emvRecord.getEMVTags()["9F45"])
        // Add more assertions as needed to validate the returned result
        Assert.assertTrue(emvRecord.getEMVTags()["9F45"].contentEquals("DAC5".toByteArray()))
    }
}