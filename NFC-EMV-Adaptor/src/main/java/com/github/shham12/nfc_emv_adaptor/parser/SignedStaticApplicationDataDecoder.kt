package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.Cryptogram
import java.security.MessageDigest

object SignedStaticApplicationDataDecoder {
    fun validate(pEMVRecord: EMVTransactionRecord, capk: CaPublicKey) {
        var isFailed = false

        val issuerPublicKeyModulus = IssuerPublicKeyDecoder.retrievalIssuerPublicKeyModulus(pEMVRecord, capk)

        val exponent = pEMVRecord.getIssuerPublicKeyExponent()
        if (exponent.isEmpty())
            throw IllegalArgumentException("Issuer Public Key Exponent not found in Card")

        val ssad = pEMVRecord.getSignedStaticApplicationData() ?: throw IllegalArgumentException("Signed Static Application Data not found in Card")

        //Step 1: ICC Public Key Certificate and Issuer Public Key Modulus have the same length
        if (ssad.size != issuerPublicKeyModulus.size)
            isFailed = true

        //Step 2: The Recovered Data Trailer is equal to 'BC'
        val decryptedSSAD = Cryptogram.performRSA(ssad, exponent, issuerPublicKeyModulus)
        if (decryptedSSAD[issuerPublicKeyModulus.size - 1] != 0xBC.toByte())
            isFailed = true

        //Step 3: The Recovered Data Header is equal to '6A'
        if (decryptedSSAD[0] != 0x6A.toByte())
            isFailed = true

        //Step 4: The Certificate Format is equal to '03'
        if (decryptedSSAD[1] != 0x03.toByte())
            isFailed = true

        // Step 5: Concatenation
        var list = decryptedSSAD.sliceArray(1 until decryptedSSAD.size - 21)
        val remainder = pEMVRecord.getICCPublicKeyRemainder()
        if (remainder != null)
            list += remainder
        val exp = pEMVRecord.getICCPublicKeyExponent() ?: throw IllegalArgumentException("ICC Public Key Exponent not found in Card")
        list += exp

        val sdaTagList = pEMVRecord.getStaticDataAuthenticationTagList()
        if (sdaTagList != null) {
            val tag = BytesUtils.bytesToString(sdaTagList)
            assert(tag == "82")
            val tagValue = pEMVRecord.getEMVTags()[tag]
            list = if (tagValue != null) list + tagValue else list
        }

        // Step 6: Generate hash from concatenation (SHA-1 hash)
        val hashConcat = MessageDigest.getInstance("SHA-1").digest(list)

        // Step 7: Compare recovered hash with generated hash
        val hashICC = decryptedSSAD.copyOfRange(decryptedSSAD.size - 21, decryptedSSAD.size - 1)

        //if (!hashConcat.contentEquals(hashICC))
//            isFailed = true

        val dataAuthenticationCode = decryptedSSAD.sliceArray(3 until  5)
        pEMVRecord.addEMVTagValue("9F45", dataAuthenticationCode)

        if (isFailed) {
            pEMVRecord.setSDAFailed()
        }
    }
}