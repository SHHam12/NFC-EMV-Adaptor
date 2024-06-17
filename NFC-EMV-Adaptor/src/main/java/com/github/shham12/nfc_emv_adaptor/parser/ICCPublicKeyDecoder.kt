package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import java.math.BigInteger
import java.security.MessageDigest

object ICCPublicKeyDecoder {
    fun retrievalICCPublicKeyModulus(emvTags: MutableMap<String, ByteArray>, capk: CaPublicKey): ByteArray {
        val issuerPublicKeyModulus = IssuerPublicKeyDecoder.retrievalIssuerPublicKeyModulus(emvTags, capk)

        val exponent = emvTags["9F32"]?: throw IllegalArgumentException("ICC Public Key Exponent not found in Card")

        val certificate = emvTags["9F46"] ?: throw IllegalArgumentException("ICC Public Key Certificate not found in Card")

        //Step 1: ICC Public Key Certificate and Issuer Public Key Modulus have the same length
        assert(certificate.size == issuerPublicKeyModulus.size);

        //Step 2: The Recovered Data Trailer is equal to 'BC'
        var decryptedICC = performRSA(certificate, exponent, issuerPublicKeyModulus)
        assert(decryptedICC[issuerPublicKeyModulus.size - 1] == 0xBC.toByte())

        //Step 3: The Recovered Data Header is equal to '6A'
        assert(decryptedICC[0] == 0x6A.toByte());

        //Step 4: The Certificate Format is equal to '04'
        assert(decryptedICC[1] == 0x04.toByte());

        // Step 5: Concatenation
        var list = decryptedICC.sliceArray(1 until decryptedICC.size - 21)
        val remainder = emvTags["9F48"]
        if (remainder != null)
            list += remainder
        val exp = emvTags["9F47"] ?: throw IllegalArgumentException("ICC Public Key Exponent not found in Card")
        list += exp

        val test0 = bytesToString(list).uppercase()
        val sdaTagList = emvTags["9F4A"]
        if (sdaTagList != null) {
            val tag = bytesToString(sdaTagList)
            assert(tag == "82")
            val tagValue = emvTags[tag]
            list = if (tagValue != null) list + tagValue else list
        }

        // Step 6: Generate hash from concatenation (SHA-1 hash)
        val hashConcat = MessageDigest.getInstance("SHA-1").digest(list)

        // Step 7: Compare recovered hash with generated hash
        val hashICC = decryptedICC.copyOfRange(decryptedICC.size - 21, decryptedICC.size - 1)

        //assert(hashConcat.contentEquals(hashICC))

        // Step 8: Verify that the Issuer Identifier matches the leftmost 3-8 PAN digits
        var pan = emvTags["5A"]
        if (pan != null) {
            var panCert = decryptedICC.copyOfRange(2, 12)
            for (i in 0..19) {
                if (panCert[i] === 0xFF.toByte()) {
                    panCert = panCert.sliceArray(0 until  i)
                    pan = pan!!.sliceArray(0 until  i)
                    break
                }
            }
            assert(pan.contentEquals(panCert))
        }

        // Step 9: Verification of the Certification Expiration Date is not implemented here

        // Step 10: Check the ICC Public Key Algorithm Indicator
        val pkAlgorithmIndicator = decryptedICC[18]

        // Step 11: Concatenate the Leftmost Digits of the ICC Public Key
        //and the ICC Public Key Remainder (if present) to obtain the ICC Public Key Modulus
        val leftmostDigits = decryptedICC.sliceArray(21 until (issuerPublicKeyModulus.size - 43))
        val iccPublicKeyModulus = if (remainder != null) leftmostDigits + remainder else leftmostDigits

        return iccPublicKeyModulus
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