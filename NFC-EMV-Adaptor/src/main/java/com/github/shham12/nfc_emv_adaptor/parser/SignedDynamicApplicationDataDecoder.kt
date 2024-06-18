package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.hexTobyte
import com.github.shham12.nfc_emv_adaptor.util.DOLParser
import com.github.shham12.nfc_emv_adaptor.util.TLVParser
import java.security.MessageDigest

object SignedDynamicApplicationDataDecoder {
    fun retrievalApplicationCryptogram(emvTags: MutableMap<String, ByteArray>, capk: CaPublicKey) {
        val iccPublicKeyModulus = ICCPublicKeyDecoder.retrievalICCPublicKeyModulus(emvTags, capk)

        val exponent = emvTags["9F47"]?: throw IllegalArgumentException("ICC Public Key Exponent not found in Card")

        val sdad = emvTags["9F4B"] ?: throw IllegalArgumentException("Signed Dynamic Application Data not found in Card")

        //Step 1: ICC Public Key Certificate and Issuer Public Key Modulus have the same length
        assert(sdad.size == iccPublicKeyModulus.size);

        //Step 2: The Recovered Data Trailer is equal to 'BC'
        var decryptedSDAD =
            ICCPublicKeyDecoder.performRSA(sdad, exponent, iccPublicKeyModulus)
        assert(decryptedSDAD[iccPublicKeyModulus.size - 1] == 0xBC.toByte())

        //Step 3: The Recovered Data Header is equal to '6A'
        assert(decryptedSDAD[0] == 0x6A.toByte());

        //Step 4: The Certificate Format is equal to '05'
        assert(decryptedSDAD[1] == 0x05.toByte());

        // Step 5: Concatenation
        var length = decryptedSDAD[3].toInt()
        var iccDynamicData = decryptedSDAD.sliceArray(4 until 4 + length)

        // Step 6: Check CID from ICC Dynamic Data & from Gen AC
        val iccDynamicNumLength = iccDynamicData[0].toInt()
        val iccDynamicNum = iccDynamicData.sliceArray(1 until 1 + iccDynamicNumLength)
        val CID = iccDynamicData.sliceArray(1 + iccDynamicNumLength until 2 + iccDynamicNumLength)

        assert(CID.contentEquals(emvTags["9F27"]))

        // Step 7: Concatenate from left to right the second to the sixth data elements in Table 22 (that
        //is, Signed Data Format through Pad Pattern), followed by the Unpredictable
        //Number.
        val list = decryptedSDAD.sliceArray(1 until (decryptedSDAD.size - 21))
        val unpredictableNumber = emvTags["9F37"] ?: throw IllegalArgumentException("Unpredictable Number is not generated")
        val concatenatedList = list + unpredictableNumber

        // Step 8: Generate hash from concatenation
        val hashConcat = MessageDigest.getInstance("SHA-1").digest(concatenatedList)

        // Step 9: Compare the hash result with the recovered hash result. They have to be equal
        val hashCert = decryptedSDAD.sliceArray((decryptedSDAD.size - 21) until (decryptedSDAD.size - 1))
        assert(hashCert.contentEquals(hashConcat))

        // Step 10: Concatenate from left to right the values of the following data elements
        // Only supports contactless => only care about CDOL1
        // - The values of the data elements specified by, and in the order they appear in
        //   the PDOL, and sent by the terminal in the GET PROCESSING OPTIONS
        //   command.
        // - The values of the data elements specified by, and in the order they appear in
        //   the CDOL1, and sent by the terminal in the first GENERATE AC command.
        // - The tags, lengths, and values of the data elements returned by the ICC in the
        //   response to the GENERATE AC command in the order they are returned,
        //   with the exception of the Signed Dynamic Application Data.
        val pDOL = DOLParser.generateDOLdata(DOLParser.parseDOL(emvTags["9F38"]!!), emvTags["4F"],false)
        val cDOL1 = DOLParser.generateDOLdata(DOLParser.parseDOL(emvTags["8C"]!!), null,false)
        val responseMessageTemp2 = TLVParser.parseEx(emvTags["77"]!!)
        responseMessageTemp2.removeByTag("9F4B")
        val concatlist = pDOL + cDOL1 + hexTobyte(responseMessageTemp2.generate(false, filteredTags = false).uppercase())

        // Step 11: Apply the indicated hash algorithm (derived from the Hash Algorithm Indicator) to
        // the result of the concatenation of the previous step to produce the Transaction Data
        // Hash Code.
        val hashConcatList = MessageDigest.getInstance("SHA-1").digest(concatlist)


        // Step 12: Compare the calculated Transaction Data Hash Code from the previous step with
        //the Transaction Data Hash Code retrieved from the ICC Dynamic Data in step 5. If
        //they are not the same, CDA has failed.
        assert(iccDynamicData.contentEquals(hashConcatList))

        emvTags["9F4C"] = iccDynamicData
        val appplicationCryptogram = iccDynamicData.sliceArray(2 + iccDynamicNumLength until iccDynamicData.size - 20)
        emvTags["9F26"] = appplicationCryptogram
    }
}