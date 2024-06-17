package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.hexTobyte
import java.math.BigInteger
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException



object IssuerPublicKeyDecoder {
    fun retrievalIssuerPublicKeyModulus(emvTags: MutableMap<String, ByteArray>, capk: CaPublicKey): ByteArray {
        val modulus = hexTobyte(capk.modulus)
        val cert = decryptIssuerPKCertificate(emvTags, capk)

        // Contactless transaction does not need to validate SDA is success of not.
        // Step 1: Issuer Public Key Certificate and Certification Authority Public Key Modulus have the same length
        assert(cert.size == modulus.size)

        // Step 2: The Recovered Data Trailer is equal to 'BC'
        assert(cert[modulus.size - 1] == 0xBC.toByte())

        // Step 3: The Recovered Data Header is equal to '6A'
        assert(cert[0] == 0x6A.toByte())

        // Step 4: The Certificate Format is equal to '02'
        assert(cert[1] == 0x02.toByte())

        // Step 5: Concatenation of Certificate Format through Issuer Public Key or Leftmost Digits of the Issuer Public Key,
        //         followed by the Issuer Public Key Remainder (if present), and the Issuer Public Key Exponent
        val list = cert.sliceArray(1 until 15 + (modulus.size - 36))
        val remainder = emvTags["92"] ?: byteArrayOf()
        val exponent = emvTags["9F32"] ?: byteArrayOf()
        val remex = remainder + exponent
        val concatenatedList = list + remex

        // Step 6: Generate hash from concatenation
        val hashConcat = MessageDigest.getInstance("SHA-1").digest(concatenatedList)

        // Step 7: Compare the hash result with the recovered hash result. They have to be equal
        val hashCert = cert.sliceArray(15 + (modulus.size - 36) until 15 + (modulus.size - 36) + 20)
        assert(hashCert.contentEquals(hashConcat))

        // Step 8: Verify that the Issuer Identifier matches the lefmost 3-8 PAN digits
        val pan = emvTags["5A"] ?: throw IllegalArgumentException("PAN not found in Card")
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
        val leftmostDigits = cert.sliceArray(15 until 15 + (modulus.size - 36))
        val issuerPublicKeyModulus = leftmostDigits + remainder
        return issuerPublicKeyModulus
    }

    private fun decryptIssuerPKCertificate(emvTags: MutableMap<String, ByteArray>, capk: CaPublicKey): ByteArray {
        val certificate = emvTags["90"] ?: throw IllegalArgumentException("Issuer Public Key Certificate not found in Card")
        return performRSA(certificate, hexTobyte(capk.exponent), hexTobyte(capk.modulus))
    }

    fun performRSA(dataBytes: ByteArray, expBytes: ByteArray, modBytes: ByteArray): ByteArray {
        var dataBytes = dataBytes
        var expBytes = expBytes
        var modBytes = modBytes
        val inBytesLength = dataBytes.size

        if (expBytes[0] >= 0x80.toByte()) {
            //Prepend 0x00 to modulus
            val tmp = ByteArray(expBytes.size + 1)
            tmp[0] = 0x00.toByte()
            System.arraycopy(expBytes, 0, tmp, 1, expBytes.size)
            expBytes = tmp
        }

        if (modBytes[0] >= 0x80.toByte()) {
            //Prepend 0x00 to modulus
            val tmp = ByteArray(modBytes.size + 1)
            tmp[0] = 0x00.toByte()
            System.arraycopy(modBytes, 0, tmp, 1, modBytes.size)
            modBytes = tmp
        }

        if (dataBytes[0] >= 0x80.toByte()) {
            //Prepend 0x00 to signed data to avoid that the most significant bit is interpreted as the "signed" bit
            val tmp = ByteArray(dataBytes.size + 1)
            tmp[0] = 0x00.toByte()
            System.arraycopy(dataBytes, 0, tmp, 1, dataBytes.size)
            dataBytes = tmp
        }

        val exp = BigInteger(expBytes)
        val mod = BigInteger(modBytes)
        val data = BigInteger(dataBytes)

        var result = data.modPow(exp, mod).toByteArray()

        if (result.size == (inBytesLength + 1) && result[0] == 0x00.toByte()) {
            //Remove 0x00 from beginning of array
            val tmp = ByteArray(inBytesLength)
            System.arraycopy(result, 1, tmp, 0, inBytesLength)
            result = tmp
        }

        return result
    }

}