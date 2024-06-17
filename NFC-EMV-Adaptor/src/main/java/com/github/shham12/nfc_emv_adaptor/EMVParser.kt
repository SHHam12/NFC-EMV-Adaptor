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
import com.github.shham12.nfc_emv_adaptor.parser.IProvider
import com.github.shham12.nfc_emv_adaptor.parser.ResponseFormat1Parser
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

    private var emvTags = mutableMapOf<String, ByteArray>()

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
        emvTags.clear()

        var AFLData: ByteArray? = null
        var CDOL1: ByteArray? = null
        var CDOL2: ByteArray? = null

        // use PSE first
        var application: ByteArray? = selectPSE(contactLess)
        if (application != null) {
            // Parse application and populate to emvTags
            TLVParser.parseEx(application).getTLVList().forEach { tlv: TLV ->
                if (!tlv.tag.isConstructed())
                    emvTags[tlv.tag.getTag().uppercase()] = tlv.value
            }
        }
        // Select AID
        var pdol: ByteArray? = selectAID(emvTags["4F"])
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
                        emvTags[tlv.tag.getTag()] = tlv.value
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
                    TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv: TLV ->
                        if (!tlv.tag.isConstructed())
                            emvTags[tlv.tag.getTag()] = tlv.value
                    }
                    if (TLVParser.parseEx(response.getData()).searchByTag("8C") != null)
                        CDOL1 = TLVParser.parseEx(response.getData()).searchByTag("8C")?.value
                    if (TLVParser.parseEx(response.getData()).searchByTag("8D") != null)
                        CDOL2 = TLVParser.parseEx(response.getData()).searchByTag("8D")?.value
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
        if (CDOL1 != null){
            var cdoldata = parseDOL(CDOL1)
            var CDOL1Data: ByteArray? = DOLParser.generateDOLdata(cdoldata, false)
            //Check 82 tag value whether it support CDA or not
            var p1Field = if(matchBitByBitIndex(emvTags["82"]!!.get(0), 0)) 0x90 else 0x80
//            var GenAC: ByteArray? = provider!!.transceive(APDUCommand(CommandEnum.GENAC, p1Field, 0x00, CDOL1Data, 0).toBytes())
            var GenAC: ByteArray? = provider!!.transceive(APDUCommand(CommandEnum.GENAC, 0x80, 0x00, CDOL1Data, 0).toBytes())
            if (GenAC != null) {
                TLVParser.parseEx(GenAC).getTLVList().forEach { tlv: TLV ->
                    if (tlv.tag.isConstructed() == false)
                        emvTags[tlv.tag.getTag()] = tlv.value
                }
            }
        }

        Log.d("TLVDATA", generateKeyValueString(emvTags))

        return emvTags
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

                if (tlvData != null){
                    // Parse File Control Information (FCI) Issuer Discretionary Data
                    var appTemplates: TLVList? =  TLVParser.parseEx(tlvData.value);

                    if (appTemplates != null){
                        application = appTemplates.getTLVList()[0]
                        // if application Template is more than 2, select high priority AID
                        if (appTemplates.getTLVList().size > 1){
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
                    emvTags[tlv.tag.getTag()] = tlv.value
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
            // Check AID is AMEX and 9F6E tag is exist from PDOL. If not exist it needs to update 9F35 tag value with (9F35 & 9F6D) operation for GPO
            val amex = byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x25.toByte())
            if (emvTags["4F"]!!.containsSequence(amex) && !containsTag(pdoldata, "9F6E")) {
                // TODO Need to set 9F6D value according to CVM Required limit logic
                var ctlsReaderCapability = 0XC8 // CVM Required 0XC8 CVM Not Required 0XC0
                updateDOLValue(pdoldata,"9F35", byteArrayOf(0x22.toByte() or ctlsReaderCapability.toByte()))
            }
        }
        var data = provider!!.transceive(APDUCommand(CommandEnum.GPO, DOLParser.generateDOLdata(pdoldata, true), 0).toBytes())
        var response = APDUResponse(data!!)
        if (response.isSuccess()) {
            TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv: TLV ->
                if (!tlv.tag.isConstructed())
                    emvTags[tlv.tag.getTag()] = tlv.value
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

            val temp = value.joinToString("") { byte ->
                "%02X".format(byte)
            }
            val length = value.size.toString(16).uppercase().padStart(2, '0') // Get length in two-digit hexadecimal format
            result.append("$key$length$temp")
        }
        return result.toString()
    }

}