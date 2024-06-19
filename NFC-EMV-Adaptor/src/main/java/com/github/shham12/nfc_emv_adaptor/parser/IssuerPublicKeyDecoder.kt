package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.hexTobyte
import com.github.shham12.nfc_emv_adaptor.util.Cryptogram
import java.security.MessageDigest

object IssuerPublicKeyDecoder {
    fun retrievalIssuerPublicKeyModulus(pEMVRecord: EMVTransactionRecord, capk: CaPublicKey): ByteArray {
        var isFailed = false

        val modulus = hexTobyte(capk.modulus)
        val cert = decryptIssuerPKCertificate(pEMVRecord.getEMVTags(), capk)

        // Contactless transaction does not need to validate SDA is success of not.
        // Step 1: Issuer Public Key Certificate and Certification Authority Public Key Modulus have the same length
        if (cert.size != modulus.size)
            isFailed = true

        // Step 2: The Recovered Data Trailer is equal to 'BC'
        if (cert[modulus.size - 1] != 0xBC.toByte())
            isFailed = true

        // Step 3: The Recovered Data Header is equal to '6A'
        if (cert[0] != 0x6A.toByte())
            isFailed = true

        // Step 4: The Certificate Format is equal to '02'
        if (cert[1] != 0x02.toByte())
            isFailed = true

        // Step 5: Concatenation of Certificate Format through Issuer Public Key or Leftmost Digits of the Issuer Public Key,
        //         followed by the Issuer Public Key Remainder (if present), and the Issuer Public Key Exponent
        val list = cert.sliceArray(1 until 15 + (modulus.size - 36))
        val remainder = pEMVRecord.getIssuerPublicKeyRemainder()
        val exponent = pEMVRecord.getIssuerPublicKeyExponent()
        val remex = remainder + exponent
        val concatenatedList = list + remex

        // Step 6: Generate hash from concatenation
        val hashConcat = MessageDigest.getInstance("SHA-1").digest(concatenatedList)

        // Step 7: Compare the hash result with the recovered hash result. They have to be equal
        val hashCert = cert.sliceArray(15 + (modulus.size - 36) until 15 + (modulus.size - 36) + 20)
        if (!hashCert.contentEquals(hashConcat))
            isFailed = true

        // Step 8: Verify that the Issuer Identifier matches the lefmost 3-8 PAN digits
        val pan = pEMVRecord.getPAN() ?: throw IllegalArgumentException("PAN not found in Card")
        val panLeft = pan.sliceArray(0 until 4)
        val panCert = cert.sliceArray(2 until 6)
        val panCertHex = bytesToString(panCert)
        val panHex = bytesToString(panLeft)
        for (i in 0 until 8) {
            if (panCertHex[i] == 'F') {
                val panCertTrimmed = panCertHex.substring(0, i)
                val panTrimmed = panHex.substring(0, i)
                assert(panTrimmed == panCertTrimmed)
                break
            }
        }

        // Step 9: Verify that the last day of the month specified in the Certification Expiration Date is equal to or later than today's date.

        // Step 10: Optional step

        // Step 11: Check the Issuer Public Key Algorithm Indicator
        val pkAlgorithmIndicator = cert[12]

        // Step 12: Concatenate the Leftmost Digits of the Issuer Public Key and the Issuer Public Key Remainder (if present)
        //          to obtain the Issuer Public Key Modulus
        val issuerPubKeyLen = cert[13].toInt() and 0xFF
        var leftmostDigits = cert.sliceArray(15 until 15 + (modulus.size - 36))
        if (leftmostDigits.size > issuerPubKeyLen)
            leftmostDigits = leftmostDigits.sliceArray(0 until issuerPubKeyLen)
        val issuerPublicKeyModulus = leftmostDigits + remainder

        if (isFailed){
            if (pEMVRecord.isCardSupportDDA() && !pEMVRecord.isCardSupportCDA())
                pEMVRecord.setDDAFailed()
            else if (pEMVRecord.isCardSupportCDA())
                pEMVRecord.setCDAFailed()
        }

        return issuerPublicKeyModulus
    }

    private fun decryptIssuerPKCertificate(emvTags: MutableMap<String, ByteArray>, capk: CaPublicKey): ByteArray {
        val certificate = emvTags["90"] ?: throw IllegalArgumentException("Issuer Public Key Certificate not found in Card")
        return Cryptogram.performRSA(certificate, hexTobyte(capk.exponent), hexTobyte(capk.modulus))
    }
}