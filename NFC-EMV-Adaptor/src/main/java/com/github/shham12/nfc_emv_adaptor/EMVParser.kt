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
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.EMVTransactionRecord
import com.github.shham12.nfc_emv_adaptor.parser.IProvider
import com.github.shham12.nfc_emv_adaptor.parser.ResponseFormat1Parser
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.DOLParser
import com.github.shham12.nfc_emv_adaptor.util.DOLParser.parseDOL
import com.github.shham12.nfc_emv_adaptor.util.TLVParser


class EMVParser(pProvider: IProvider, pContactLess: Boolean = true, pCapkXML: String) {
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

    private var capkTable: CaPublicKeyTable? = null

    private var emvTransactionRecord = EMVTransactionRecord()

    init {
        capkTable = CaPublicKeyTable(pCapkXML)
    }

    /**
     * Method used to read a EMV card
     *
     * provider to send command to the card
     * @return data read from card or null if any provider match the card type
     */
    fun readEmvCard(): MutableMap<String, ByteArray> {
        emvTransactionRecord.clear()

        // use PSE first
        selectPSE(contactLess)
        // Select AID
        var pdol: ByteArray? = selectAID(emvTransactionRecord.getAID())
        // GPO
        var aflData: ByteArray? = gpo(pdol)
        // Read Record
        var cdol1: ByteArray? = readRecord(aflData)

        // Processing Restriction
        emvTransactionRecord.processRestriction()

        // Cardholder Verification
        emvTransactionRecord.processCVM()

        // Process Terminal Risk Management
        emvTransactionRecord.processTermRiskManagement()

        // Process Terminal Action Analysis
        val p1Field = emvTransactionRecord.processTermActionAnalysis()

        // GenAC
        generateAC(cdol1, p1Field)

        // Need to notify Card Read Successfully

        // Process Offline Data Authentication
        emvTransactionRecord.processODA(capkTable)

        Log.d("TLVDATA", generateKeyValueString(emvTransactionRecord.getEMVTags()))

        return emvTransactionRecord.getEMVTags()
    }

    /**
     * Select AID with PSE directory
     *
     * @param pContactLess
     * boolean to indicate contact less mode
     */
    private fun selectPSE(pContactLess: Boolean) {
        Log.d("APDUCommand", "SELECT PSE")

        val selectCommand = APDUCommand(CommandEnum.SELECT, if (pContactLess) PPSE else PSE, 0).toBytes()
        val response = APDUResponse(provider!!.transceive(selectCommand)!!)

        if (response.isSuccess()) {
            if (pContactLess) {
                // Parse PPSE data
                TLVParser.parseEx(response.getData()).searchByTag("BF0C")?.let { tlvData ->
                    // Parse File Control Information (FCI) Issuer Discretionary Data
                    TLVParser.parseEx(tlvData.value).getTLVList().let { appTemplates ->
                        var application = appTemplates.firstOrNull()

                        // If application Template is more than 2, select high priority AID
                        if (appTemplates.size > 1) {
                            appTemplates.forEach { tlv ->
                                val priorityIndicator = TLVParser.parseEx(tlv.value).searchByTag("87")?.value
                                if (priorityIndicator?.contains(0x01.toByte()) == true) {
                                    application = tlv
                                }
                            }
                        }

                        application?.let{tlv ->
                            tlv.value?.let{app ->
                                // Parse application and populate to emvTags
                                TLVParser.parseEx(app).getTLVList().forEach { tlv: TLV ->
                                    if (!tlv.tag.isConstructed())
                                        emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Select AID with PSE directory
     *
     * @param pAID
     *          AID data
     * @return PDOL data
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
     *          PDOL data
     * @return AFL Data
     */
    private fun gpo(pPDOL: ByteArray?): ByteArray? {
        Log.d("APDUCommand", "GPO")
        val pdolData: List<DOL>? = pPDOL?.let { parseDOL(it) }
        val gpoData = APDUCommand(CommandEnum.GPO, DOLParser.generateDOLdata(pdolData, true, emvTransactionRecord), 0).toBytes()
        val response = APDUResponse(provider!!.transceive(gpoData)!!)

        if (response.isSuccess()) {
            TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv ->
                if (!tlv.tag.isConstructed()) {
                    emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                }
            }

            Log.d("NFC-EMV-Adaptor", response.getData().joinToString("") { "%02x".format(it) })

            // Extract data from Response Message Template
            val data = response.getData()
            val msgTemplate = TLVParser.parseEx(data).searchByTag("80")

            val aflData = msgTemplate?.let {
                ResponseFormat1Parser.parse(CommandEnum.GPO, it.value).apply {
                    getTLVList().forEach { tlv ->
                        if (!tlv.tag.isConstructed()) {
                            emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                        }
                    }
                }.searchByTag("94")?.value
            } ?: TLVParser.parseEx(data).searchByTag("94")?.value

            return aflData
        } else if (response.isInvalidated()) {
            throw TLVException("Try another interface")
        } else
            throw TLVException(bytesToString(response.toBytes()).uppercase())

        return null
    }

    /**
     * Read Record
     *
     * @param pAFL
     *          AFL Data
     * @return CDOL1 data
     */
    private fun readRecord(pAFL: ByteArray?): ByteArray? {
        var cdol1: ByteArray? = null
        pAFL?.let { data ->
            Log.d("AFLData", data.joinToString("") { "%02x".format(it) })

            // Read Command
            val aflRecords: List<AFL> = extractAFL(data)
            if (aflRecords.isEmpty()) {
                Log.d("NFC-EMV-Adaptor", "No AFL records found")
            } else {
                // Generate Read Record commands from AFL records
                val readRecordCommands: List<APDUCommand> = generateReadRecordCommands(aflRecords)

                // Send Read Record commands and handle responses
                for (command in readRecordCommands) {
                    val response = APDUResponse(provider!!.transceive(command.toBytes())!!)
                    if (response.isSuccess()) {
                        TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv ->
                            if (!tlv.tag.isConstructed()) {
                                emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                            }
                        }
                        TLVParser.parseEx(response.getData()).searchByTag("8C")?.value?.let { value ->
                            cdol1 = value
                            Log.d("NFC-EMV-Adaptor", "CDOL1 ${cdol1?.joinToString("") { "%02x".format(it) }}")
                        }
                        TLVParser.parseEx(response.getData()).searchByTag("8D")?.value?.let { value ->
                            Log.d("NFC-EMV-Adaptor", "CDOL2 ${value?.joinToString("") { "%02x".format(it) }}")
                        }
                    }
                }

            }
        }
        return cdol1
    }

    private fun generateReadRecordCommands(pAFLRecords: List<AFL?>): List<APDUCommand> {
        val apduCommands: MutableList<APDUCommand> = ArrayList()

        for (record in pAFLRecords) {
            record?.let { rec ->
                for (i in rec.startRecord..rec.endRecord) {
                    val apdu = APDUCommand(CommandEnum.READ_RECORD, i, (rec.sfi shl 3) or 0x04, 0x00)
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
        var index = 0 // Typically the data starts after the first four bytes

        while (index < pAFL.size - 2) {
            val sfi = (pAFL[index].toInt() shr 3) and 0x1F
            val startRecord = pAFL[index + 1].toInt() and 0xFF
            val endRecord = pAFL[index + 2].toInt() and 0xFF
            val offlineRecords = pAFL[index + 3].toInt() and 0xFF

            val record = AFL(sfi, startRecord, endRecord, offlineRecords)

            Log.d("AFLRecord", "$sfi $startRecord $endRecord $offlineRecords")
            aflRecords.add(record)
            index += 4 // Move to the next AFL entry
        }

        return aflRecords
    }

    /**
     * Generate Application Cryptogram
     *
     * @param pCDOL1
     *            CDOL1 data
     * @param pP1Field
     *            p1 for APDU Command
     * @return list of AFL
     */
    private fun generateAC(pCDOL1: ByteArray?, pP1Field: Int) {
        pCDOL1?.let { cdol1 ->
            val cdolData = parseDOL(cdol1)
            val cdol1Data = DOLParser.generateDOLdata(cdolData, false, emvTransactionRecord)

            val genACResponse = provider!!.transceive(APDUCommand(CommandEnum.GENAC, pP1Field, 0x00, cdol1Data, 0).toBytes())?.let { APDUResponse(it) }

            genACResponse?.takeIf { it.isSuccess() }?.let { response ->
                TLVParser.parseEx(response.getData()).getTLVList().forEach { tlv ->
                    when (tlv.tag.getTag()) {
                        "77" -> emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                        "80" -> {
                            ResponseFormat1Parser.parse(CommandEnum.GENAC, tlv.value).getTLVList().forEach { innerTlv ->
                                if (!innerTlv.tag.isConstructed()) {
                                    emvTransactionRecord.addEMVTagValue(innerTlv.tag.getTag().uppercase(), innerTlv.value)
                                }
                            }
                        }
                        else -> {
                            if (!tlv.tag.isConstructed()) {
                                emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                            }
                        }
                    }
                }
            }
        }
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