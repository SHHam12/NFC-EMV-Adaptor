package com.github.shham12.nfc_emv_adaptor

import android.util.Log
import com.github.shham12.nfc_emv_adaptor.exception.TLVException
import com.github.shham12.nfc_emv_adaptor.iso7816emv.CaPublicKeyTable
import com.github.shham12.nfc_emv_adaptor.iso7816emv.TLV
import com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.APDUCommand
import com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.APDUResponse
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.AFL
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.DOL
import com.github.shham12.nfc_emv_adaptor.iso7816emv.enum.CommandEnum
import com.github.shham12.nfc_emv_adaptor.iso7816emv.impl.CaPublicKey
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.parser.IProvider
import com.github.shham12.nfc_emv_adaptor.parser.ResponseFormat1Parser
import com.github.shham12.nfc_emv_adaptor.parser.SignedDynamicApplicationDataDecoder
import com.github.shham12.nfc_emv_adaptor.parser.SignedStaticApplicationDataDecoder
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.containsSequence
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.matchBitByBitIndex
import com.github.shham12.nfc_emv_adaptor.util.DOLParser
import com.github.shham12.nfc_emv_adaptor.util.DOLParser.containsTag
import com.github.shham12.nfc_emv_adaptor.util.DOLParser.parseDOL
import com.github.shham12.nfc_emv_adaptor.util.DOLParser.updateDOLValue
import com.github.shham12.nfc_emv_adaptor.util.TLVList
import com.github.shham12.nfc_emv_adaptor.util.TLVParser
import kotlin.experimental.or


class EMVParser(pProvider: IProvider, pContactLess: Boolean = true, capkXML: String) {
    /**
     * Max record for SFI
     */
    private val MAX_RECORD_SFI: Int = 16
    /**
     * PPSE directory "2PAY.SYS.DDF01"
     */
    private val PPSE: ByteArray = "2PAY.SYS.DDF01".toByteArray()

    /**
     * PSE directory "1PAY.SYS.DDF01"
     */
    private val PSE: ByteArray = "1PAY.SYS.DDF01".toByteArray()

    /**
     * Provider
     */
    private var provider: IProvider? = pProvider

    /**
     * use contactless mode
     */
    private var contactLess = pContactLess

    private var CAPKTable: CaPublicKeyTable? = null

    private var emvTransactionRecord = EMVTransactionRecord()

    init {
        CAPKTable = CaPublicKeyTable(capkXML)
    }

    /**
     * Method used to read a EMV card
     *
     * provider to send command to the card
     * @return data read from card or null if any provider match the card type
     */
    fun readEmvCard(): MutableMap<String, ByteArray> {
        emvTransactionRecord.clear()

        var AFLData: ByteArray? = null
        var CDOL1: ByteArray? = null
        var CDOL2: ByteArray? = null

        // use PSE first
        var application: ByteArray? = selectPSE(contactLess)
        if (application != null) {
            // Parse application and populate to emvTags
            TLVParser.parseEx(application).getTLVList().forEach { tlv: TLV ->
                if (!tlv.tag.isConstructed())
                    emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
            }
        }
        // Select AID
        var pdol: ByteArray? = selectAID(emvTransactionRecord.getAID())
        // GPO
        var ResponseMessageTemplate: ByteArray? = gpo(pdol)
        // Extract data from Response Message Template

        if (ResponseMessageTemplate != null) {
            // Check data is Response Message Template 1
            var MsgTemplate: TLV? = TLVParser.parseEx(ResponseMessageTemplate).searchByTag("80")

            if (MsgTemplate != null) {
                var ParsedMsgTemp = ResponseFormat1Parser.parse(CommandEnum.GPO, MsgTemplate.value)
                ParsedMsgTemp.getTLVList().forEach { tlv: TLV ->
                    if (!tlv.tag.isConstructed())
                        emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                }
                AFLData = ParsedMsgTemp.searchByTag("94")!!.value
            } else {
                AFLData = TLVParser.parseEx(ResponseMessageTemplate).searchByTag("94")?.value
            }
        }

        // Read Record
        if (AFLData != null) {
            Log.d("AFLData", AFLData.joinToString("") { "%02x".format(it) })
            // Read Command
            val aflRecords: List<AFL> = extractAFL(AFLData)
            if (aflRecords.isEmpty()) {
                Log.d("NFC-EMV-Adaptor", "No AFL records found")
            } else {
                // Generate Read Record commands from AFL records
                val readRecordCommands: List<APDUCommand> =
                    generateReadRecordCommands(aflRecords)

                // Send Read Record commands and handle responses
                for (command in readRecordCommands) {
                    var response = APDUResponse(provider!!.transceive(command.toBytes())!!)
                    if (response.isSuccess()) {
                        TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv: TLV ->
                            if (!tlv.tag.isConstructed())
                                emvTransactionRecord.addEMVTagValue(
                                    tlv.tag.getTag().uppercase(),
                                    tlv.value
                                )
                        }
                        if (TLVParser.parseEx(response.getData()).searchByTag("8C") != null)
                            CDOL1 = TLVParser.parseEx(response.getData()).searchByTag("8C")?.value
                        if (TLVParser.parseEx(response.getData()).searchByTag("8D") != null)
                            CDOL2 = TLVParser.parseEx(response.getData()).searchByTag("8D")?.value
                    }
                }
                Log.d(
                    "NFC-EMV-Adaptor",
                    "CDOL1 " + CDOL1?.joinToString("") { "%02x".format(it) })
                Log.d(
                    "NFC-EMV-Adaptor",
                    "CDOL2 " + CDOL2?.joinToString("") { "%02x".format(it) })
            }
        }

        // GenAC
        if (CDOL1 != null) {
            var cdoldata = parseDOL(CDOL1)
            var CDOL1Data: ByteArray? = DOLParser.generateDOLdata(cdoldata, false, emvTransactionRecord)
            //Check 82 tag value whether it support CDA or not
            var p1Field = if(emvTransactionRecord.isCardSupportCDA()) 0x90 else 0x80
            var GenAC: ByteArray? = provider!!.transceive(APDUCommand(CommandEnum.GENAC, p1Field, 0x00, CDOL1Data, 0).toBytes())
            if (GenAC != null) {
                var response = APDUResponse(GenAC)
                if (response.isSuccess()) {
                    TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv: TLV ->
                        if (tlv.tag.getTag() == "77")
                            emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                        else if (tlv.tag.getTag() == "80") {
                            var ParsedMsgTemp = ResponseFormat1Parser.parse(CommandEnum.GENAC, tlv.value)
                            ParsedMsgTemp.getTLVList().forEach { tlv: TLV ->
                                if (!tlv.tag.isConstructed())
                                    emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                            }
                        }
                        else if (!tlv.tag.isConstructed())
                            emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                        // Check 9F36 tag is exist
                        if (!emvTransactionRecord.getEMVTags().containsKey("9F36"))
                            emvTransactionRecord.setICCDataMissing()
                    }
                    // Process Offline Data Authentication
                    if (emvTransactionRecord.isSupportODA()) {
                        val RID = bytesToString(
                            emvTransactionRecord.getAID().sliceArray(0 until 5)
                        ).uppercase()
                        val capkIndex =
                            bytesToString(emvTransactionRecord.getEMVTags()["8F"]!!).uppercase()
                        val capk: CaPublicKey? = CAPKTable!!.findPublicKey(RID, capkIndex)
                        if (capk != null) {
                            if (emvTransactionRecord.isCardSupportSDA() && !emvTransactionRecord.isCardSupportDDA() && !emvTransactionRecord.isCardSupportDDA()) {
                                // Need to check 8F, 90, 93, 92, 9F32 tag are exist
                                emvTransactionRecord.setSDASelected()
                                // If fail, set SDA Failed Bit in TVR to 1
                                SignedStaticApplicationDataDecoder.validate(emvTransactionRecord, capk)
                            } else if (emvTransactionRecord.isCardSupportDDA() && !emvTransactionRecord.isCardSupportCDA()) {
                                // Need to check 8F, 90, 93, 92, 9F32, 9F46, 9F47, 9F48, 9F49 tag are exist
                                // If fail, set DDA Failed Bit in TVR to 1
                                SignedDynamicApplicationDataDecoder.retrievalApplicationCryptogram(
                                    emvTransactionRecord,
                                    capk
                                )
                            } else if (emvTransactionRecord.isCardSupportCDA()) {
                                // Need to check 8F, 90, 93, 92, 9F32, 9F46, 9F47, 9F48, 9F49 tag are exist
                                // If fail, set CDA Failed Bit in TVR to 1
                                SignedDynamicApplicationDataDecoder.retrievalApplicationCryptogram(
                                    emvTransactionRecord,
                                    capk
                                )
                            }
                        } else {
                            throw TLVException("Not supported AID")
                        }
                    }
                    else
                        emvTransactionRecord.setODANotPerformed()
                    // Application Version Number check for TVR B2b8
                    emvTransactionRecord.checkAppVerNum()
                    // Check Application Usage Control
                    emvTransactionRecord.checkAUC()
                    // Check Effective Date & Expiration Date
                    emvTransactionRecord.checkEffectiveAndExpirationDate()
                }
            }

        }

        Log.d("TLVDATA", generateKeyValueString(emvTransactionRecord.getEMVTags()))

        return emvTransactionRecord.getEMVTags()
    }

    /**
     * Select AID with PSE directory
     *
     * @param pContactLess
     * boolean to indicate contact less mode
     * @return card read
     */
    private fun selectPSE(pContactLess: Boolean): ByteArray? {
        Log.d("APDUCommand", "SELECT PSE")
        var application: TLV? = null
        // Select the PPSE or PSE directory
        var data = provider!!.transceive(APDUCommand(CommandEnum.SELECT, if (pContactLess) PPSE else PSE, 0).toBytes())
        var response = APDUResponse(data!!)
        if (response.isSuccess()) {
            if (contactLess) {
                // Parse PPSE data
                // Extract PCI Proprietary Template
                var tlvData : TLV? = TLVParser.parseEx(response.getData()).searchByTag("BF0C");

                if (tlvData != null) {
                    // Parse File Control Information (FCI) Issuer Discretionary Data
                    var appTemplates: TLVList? =  TLVParser.parseEx(tlvData.value);

                    if (appTemplates != null) {
                        application = appTemplates.getTLVList()[0]
                        // if application Template is more than 2, select high priority AID
                        if (appTemplates.getTLVList().size > 1) {
                            appTemplates.getTLVList().forEach { tlv ->
                                if (TLVParser.parseEx(tlv.value).searchByTag("87")?.value?.contains(0x01.toByte()) == true) // 87 Application Priority Indicator with length 1
                                    application = tlv
                            }
                        }
                    }
                }
            }
        }

        return application?.value
    }

    /**
     * Select AID with PSE directory
     *
     * @param pAID
     * boolean to indicate contact less mode
     * @return card read
     */
    private fun selectAID(pAID: ByteArray?): ByteArray? {
        Log.d("APDUCommand", "SELECT AID")
        var pdol : TLV? = null
        if (pAID == null)
            throw TLVException("AID not exist")
        var data = provider!!.transceive(APDUCommand(CommandEnum.SELECT, pAID, 0).toBytes())
        var response = APDUResponse(data!!)
        if (response.isSuccess()) {
            pdol = TLVParser.parseEx(response.getData()).searchByTag("9F38");
            TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv: TLV ->
                if (!tlv.tag.isConstructed())
                    emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
            }
        }

        return pdol?.value
    }

    /**
     * Get Processing Options
     *
     * @param pPDOL
     * boolean to indicate contact less mode
     * @return card read
     */
    private fun gpo(pPDOL: ByteArray?): ByteArray? {
        Log.d("APDUCommand", "GPO")
        var pdoldata: List<DOL>? = null
        if (pPDOL != null) {
            pdoldata = DOLParser.parseDOL(pPDOL)
        }
        var data = provider!!.transceive(APDUCommand(CommandEnum.GPO, DOLParser.generateDOLdata(pdoldata, true, emvTransactionRecord), 0).toBytes())
        var response = APDUResponse(data!!)
        if (response.isSuccess()) {
            TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv: TLV ->
                if (!tlv.tag.isConstructed())
                    emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
            }
            Log.d("NFC-EMV-Adaptor", response.getData().joinToString("") { "%02x".format(it) })
        }

        return response.getData()
    }

    private fun generateReadRecordCommands(aflRecords: List<AFL?>): List<APDUCommand> {
        val apduCommands: MutableList<APDUCommand> = ArrayList()

        for (record in aflRecords) {
            if (record != null) {
                for (i in record.startRecord..record.endRecord) {
                    val apdu = APDUCommand(CommandEnum.READ_RECORD, i , ((record.sfi shl 3) or 0x04), 0x00)
//                    val apdu = APDUCommand(CommandEnum.READ_RECORD, i , ((record.sfi shl 3) or 0x04))
                    apduCommands.add(apdu)
                }
            }
        }

        return apduCommands
    }

    /**
     * Extract list of application file locator from Afl response
     *
     * @param pAFL
     *            AFL data
     * @return list of AFL
     */
    private fun extractAFL(pAFL: ByteArray): List<AFL> {
        val aflRecords = mutableListOf<AFL>()
        // Extract AFL data (ignoring status bytes at the end)
        var index = 0 // Typically the data starts after the first four bytes
        while (index < pAFL.size - 2) {
            val record : AFL =
                AFL(
                    (pAFL.get(index).toInt() shr 3) and 0x1F,
                    pAFL.get(index + 1).toInt() and 0xFF,
                    pAFL.get(index + 2).toInt() and 0xFF,
                    pAFL.get(index + 3).toInt() and 0xFF
                )
            Log.d(
                "AFLRecord",
                record.sfi.toString() + " " + record.startRecord + " " + record.endRecord + " " + record.offlineRecords
            )
            aflRecords.add(record)
            index += 4 // Move to the next AFL entry
        }
        return aflRecords
    }

    private fun generateKeyValueString(byteArrayDict: Map<String, ByteArray>): String {
        val result = StringBuilder()
        byteArrayDict.forEach { (key, value) ->
            // Skip this entry if the key is "90"
            if (key.uppercase() == "90") return@forEach
            if (key.uppercase() == "9F46") return@forEach
            if (key.uppercase() == "9F4B") return@forEach
            if (key.uppercase() == "77") return@forEach

            val temp = value.joinToString("") { byte ->
                "%02X".format(byte)
            }
            val length = value.size.toString(16).uppercase().padStart(2, '0') // Get length in two-digit hexadecimal format
            result.append("$key$length$temp")
        }
        return result.toString()
    }

}