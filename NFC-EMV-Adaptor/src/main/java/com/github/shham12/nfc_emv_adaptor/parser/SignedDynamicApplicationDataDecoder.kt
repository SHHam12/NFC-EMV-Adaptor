package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.hexTobyte
import com.github.shham12.nfc_emv_adaptor.util.Cryptogram
import com.github.shham12.nfc_emv_adaptor.util.DOLParser
import com.github.shham12.nfc_emv_adaptor.util.TLVParser
import java.security.MessageDigest

object SignedDynamicApplicationDataDecoder {
    fun retrievalApplicationCryptogram(pEMVRecord: EMVTransactionRecord, capk: CaPublicKey) {
        var isFailed = false

        val iccPublicKeyModulus = ICCPublicKeyDecoder.retrievalICCPublicKeyModulus(pEMVRecord, capk)

        val exponent = pEMVRecord.getICCPublicKeyExponent() ?: throw IllegalArgumentException("ICC Public Key Exponent not found in Card")

        val sdad = pEMVRecord.getSignedDynamicApplicationData() ?: throw IllegalArgumentException("Signed Dynamic Application Data not found in Card")

        //Step 1: ICC Public Key Certificate and Issuer Public Key Modulus have the same length
        if (sdad.size != iccPublicKeyModulus.size)
            isFailed = true

        //Step 2: The Recovered Data Trailer is equal to 'BC'
        var decryptedSDAD = Cryptogram.performRSA(sdad, exponent, iccPublicKeyModulus)
        if (decryptedSDAD[iccPublicKeyModulus.size - 1] != 0xBC.toByte())
            isFailed = true

        //Step 3: The Recovered Data Header is equal to '6A'
        if (decryptedSDAD[0] != 0x6A.toByte())
            isFailed = true

        //Step 4: The Certificate Format is equal to '05'
        if (decryptedSDAD[1] != 0x05.toByte())
            isFailed = true

        // Step 5: Concatenation
        var length = decryptedSDAD[3].toInt() and 0xFF
        var iccDynamicData = decryptedSDAD.sliceArray(4 until 4 + length)

        // Step 6: Check CID from ICC Dynamic Data & from Gen AC
        val iccDynamicNumLength = iccDynamicData[0].toInt() and 0xFF
        val iccDynamicNum = iccDynamicData.sliceArray(1 until 1 + iccDynamicNumLength)
        val CID = iccDynamicData.sliceArray(1 + iccDynamicNumLength until 2 + iccDynamicNumLength)
        val appplicationCryptogram = iccDynamicData.sliceArray(2 + iccDynamicNumLength until iccDynamicData.size - 20)
        val transactionHashData = iccDynamicData.sliceArray(iccDynamicData.size - 20 until iccDynamicData.size)

        if (!CID.contentEquals(pEMVRecord.getCryptogramInformationData()))
            isFailed = true

        // Step 7: Concatenate from left to right the second to the sixth data elements in Table 22 (that
        //is, Signed Data Format through Pad Pattern), followed by the Unpredictable
        //Number.
        val list = decryptedSDAD.sliceArray(1 until (decryptedSDAD.size - 21))
        val unpredictableNumber = pEMVRecord.getUnpredictableNumber()
        val concatenatedList = list + unpredictableNumber

        // Step 8: Generate hash from concatenation
        val hashConcat = MessageDigest.getInstance("SHA-1").digest(concatenatedList)

        // Step 9: Compare the hash result with the recovered hash result. They have to be equal
        val hashCert = decryptedSDAD.sliceArray((decryptedSDAD.size - 21) until (decryptedSDAD.size - 1))
        if (!hashCert.contentEquals(hashConcat))
            isFailed = true

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
        val pDOL = DOLParser.generateDOLdata(DOLParser.parseDOL(pEMVRecord.getPDOL()), false, pEMVRecord)
        val cDOL1 = DOLParser.generateDOLdata(DOLParser.parseDOL(pEMVRecord.getCDOL1()), false, pEMVRecord)
        val responseMessageTemp2 = TLVParser.parseEx(pEMVRecord.getResponseMessageTemplate2())
        responseMessageTemp2.removeByTag("9F4B")
        val concatlist = pDOL + cDOL1 + hexTobyte(responseMessageTemp2.generate(false, filteredTags = false).uppercase())

        // Step 11: Apply the indicated hash algorithm (derived from the Hash Algorithm Indicator) to
        // the result of the concatenation of the previous step to produce the Transaction Data
        // Hash Code.
        val hashConcatList = MessageDigest.getInstance("SHA-1").digest(concatlist)

        // Step 12: Compare the calculated Transaction Data Hash Code from the previous step with
        //the Transaction Data Hash Code retrieved from the ICC Dynamic Data in step 5. If
        //they are not the same, CDA has failed.
        if (!transactionHashData.contentEquals(hashConcatList))
            isFailed = true

        pEMVRecord.addEMVTagValue("9F4C", iccDynamicData)
        pEMVRecord.addEMVTagValue("9F26", appplicationCryptogram)

        if (isFailed){
            if (pEMVRecord.isCardSupportDDA() && !pEMVRecord.isCardSupportCDA())
                pEMVRecord.setDDAFailed()
            else if (pEMVRecord.isCardSupportCDA())
                pEMVRecord.setCDAFailed()
        }
    }
}