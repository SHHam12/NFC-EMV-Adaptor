package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.Cryptogram
import java.security.MessageDigest

object ICCPublicKeyDecoder {
    fun retrievalICCPublicKeyModulus(pEMVRecord: EMVTransactionRecord, capk: CaPublicKey): ByteArray {
        var isFailed = false

        val issuerPublicKeyModulus = IssuerPublicKeyDecoder.retrievalIssuerPublicKeyModulus(pEMVRecord, capk)

        val exponent = pEMVRecord.getICCPublicKeyExponent() ?: throw IllegalArgumentException("ICC Public Key Exponent not found in Card")

        val certificate = pEMVRecord.getICCPublicKeyCertificate() ?: throw IllegalArgumentException("ICC Public Key Certificate not found in Card")

        //Step 1: ICC Public Key Certificate and Issuer Public Key Modulus have the same length
        if (certificate.size != issuerPublicKeyModulus.size)
            isFailed = true

        //Step 2: The Recovered Data Trailer is equal to 'BC'
        val decryptedICC = Cryptogram.performRSA(certificate, exponent, issuerPublicKeyModulus)
        if (decryptedICC[issuerPublicKeyModulus.size - 1] != 0xBC.toByte())
            isFailed = true

        //Step 3: The Recovered Data Header is equal to '6A'
        if (decryptedICC[0] != 0x6A.toByte())
            isFailed = true

        //Step 4: The Certificate Format is equal to '04'
        if (decryptedICC[1] != 0x04.toByte())
            isFailed = true

        // Step 5: Concatenation
        var list = decryptedICC.sliceArray(1 until decryptedICC.size - 21)
        val remainder = pEMVRecord.getICCPublicKeyRemainder()
        if (remainder != null)
            list += remainder
        list += exponent

        val sdaTagList = pEMVRecord.getStaticDataAuthenticationTagList()
        if (sdaTagList != null) {
            val tag = bytesToString(sdaTagList)
            assert(tag == "82")
            val tagValue = pEMVRecord.getEMVTags()[tag]
            list = if (tagValue != null) list + tagValue else list
        }

        // Step 6: Generate hash from concatenation (SHA-1 hash)
        val hashConcat = MessageDigest.getInstance("SHA-1").digest(list)

        // Step 7: Compare recovered hash with generated hash
        val hashICC = decryptedICC.copyOfRange(decryptedICC.size - 21, decryptedICC.size - 1)

//        if (!hashConcat.contentEquals(hashICC))
//            isFailed = true

        // Step 8: Verify that the Issuer Identifier matches the leftmost 3-8 PAN digits
        val pan = pEMVRecord.getPAN()
        if (pan != null) {
            var panStr = bytesToString(pan).uppercase()
            var panCert = bytesToString(decryptedICC.copyOfRange(2, 12)).uppercase()
            for (i in 0..19) {
                if (panCert[i] == 'F') {
                    panCert = panCert.substring(0, i)
                    panStr = panStr.substring(0, i)
                    break
                }
            }
            if (!panStr.contentEquals(panCert))
                isFailed = true
        }

        // Step 9: Verification of the Certification Expiration Date is not implemented here

        // Step 10: Check the ICC Public Key Algorithm Indicator
        val pkAlgorithmIndicator = decryptedICC[18]

        // Step 11: Concatenate the Leftmost Digits of the ICC Public Key
        //and the ICC Public Key Remainder (if present) to obtain the ICC Public Key Modulus
        val iccPubKeyLen = decryptedICC[19].toInt() and 0xFF
        var leftmostDigits = decryptedICC.sliceArray(21 until 21 + (issuerPublicKeyModulus.size - 42))
        if (leftmostDigits.size > iccPubKeyLen)
            leftmostDigits = leftmostDigits.sliceArray(0 until iccPubKeyLen)
        val iccPublicKeyModulus = if (remainder != null) leftmostDigits + remainder else leftmostDigits

        if (isFailed) {
            if (pEMVRecord.isCardSupportDDA() && !pEMVRecord.isCardSupportCDA())
                pEMVRecord.setDDAFailed()
            else if (pEMVRecord.isCardSupportCDA())
                pEMVRecord.setCDAFailed()
        }

        return iccPublicKeyModulus
    }
}