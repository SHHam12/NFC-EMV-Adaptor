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
import com.github.shham12.nfc_emv_adaptor.util.AFLUtils
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils.bytesToString
import com.github.shham12.nfc_emv_adaptor.util.DOLParser
import com.github.shham12.nfc_emv_adaptor.util.DOLParser.parseDOL
import com.github.shham12.nfc_emv_adaptor.util.TLVParser


class EMVParser(pProvider: IProvider, pContactLess: Boolean = true, pCapkXML: String) {
    /**
     * Max record for SFI
     */
    private val maxRecordSFI: Int = 16
    /**
     * PPSE directory "2PAY.SYS.DDF01"
     */
    private val ppse: ByteArray = "2PAY.SYS.DDF01".toByteArray()

    /**
     * PSE directory "1PAY.SYS.DDF01"
     */
    private val pse: ByteArray = "1PAY.SYS.DDF01".toByteArray()

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

    private var applicationCandidate: List<TLV>? = null

    init {
        capkTable = CaPublicKeyTable(pCapkXML)
    }

    /**
     * Method used to read a EMV card
     *
     * provider to send command to the card
     * @return data read from card or null if any provider match the card type
     */
    fun readEmvCard(pAmount: String): MutableMap<String, ByteArray> {
        emvTransactionRecord.clear()

        // use PSE first
        selectPSE(contactLess, pAmount)
        // Select AID
        val pdol: ByteArray? = selectAID(emvTransactionRecord.getAID())
        // GPO
        val aflData: ByteArray? = gpo(pdol, pAmount)
        // Read Record
        val cdol1: ByteArray? = readRecord(aflData)

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
    private fun selectPSE(pContactLess: Boolean, pAmount: String) {
        Log.d("APDUCommand", "SELECT PSE")

        val selectCommand = APDUCommand(CommandEnum.SELECT, if (pContactLess) ppse else pse, 0).toBytes()
        val response = APDUResponse(provider!!.transceive(selectCommand)!!)

        if (response.isSuccess()) {
            if (pContactLess) {
                // Parse PPSE data
                TLVParser.parseEx(response.getData()).searchByTag("BF0C")?.let { tlvData ->
                    // Parse File Control Information (FCI) Issuer Discretionary Data
                    TLVParser.parseEx(tlvData.value).getTLVList().let { appTemplates ->
                        var application = appTemplates.firstOrNull()
                        // If application Template is more than 2, select high priority AID and save other AIDs
                        val candidateTemplates = appTemplates.filter { it.tag.getTag() == "61" }
                        if (candidateTemplates.size > 1) {
                            applicationCandidate = candidateTemplates
                            application = selectHigherPriorityApplication(candidateTemplates)
                        }
                        setApplicationWithAmount(application, pAmount)
                    }
                }
            }
        }
    }

    private fun selectHigherPriorityApplication(pCandidateTemplates: List<TLV>): TLV? {
        // Find the TLV with the higher priorityIndicator
        val applicationWithHigherPriority = pCandidateTemplates.minByOrNull { tlv ->
            // Extract the priorityIndicator as a byte array
            val priorityIndicator = TLVParser.parseEx(tlv.value).searchByTag("87")?.value
            // Convert the first byte of priorityIndicator to an integer for comparison
            priorityIndicator?.firstOrNull()?.toInt()
                ?: Int.MAX_VALUE // Default to MAX_VALUE if priorityIndicator is null
        }
        // If we found an application with minimum priority
        applicationWithHigherPriority?.let { highPriorityTlv ->
            applicationCandidate = pCandidateTemplates.filter { it != highPriorityTlv }
        }
        return applicationWithHigherPriority
    }

    private fun setApplicationWithAmount(pApplication: TLV?, pAmount: String
    ) {
        pApplication?.let { tlv ->
            tlv.value.let { app ->
                // Parse application and populate to emvTags
                TLVParser.parseEx(app).getTLVList().forEach { tlv: TLV ->
                    if (!tlv.tag.isConstructed())
                        emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                }
            }
            // Assume AID is inserted
            emvTransactionRecord.loadAID(emvTransactionRecord.getAID())
            emvTransactionRecord.setAmount1(pAmount)
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
        val data = provider!!.transceive(APDUCommand(CommandEnum.SELECT, pAID, 0).toBytes())
        val response = APDUResponse(data!!)
        if (response.isSuccess()) {
            pdol = TLVParser.parseEx(response.getData()).searchByTag("9F38")
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
    private fun gpo(pPDOL: ByteArray?, pAmount: String): ByteArray? {
        Log.d("APDUCommand", "GPO")
        val pdolData: List<DOL>? = pPDOL?.let { parseDOL(it) }
        val gpoData = APDUCommand(CommandEnum.GPO, DOLParser.generateDOLdata(pdolData, true, emvTransactionRecord), 0).toBytes()
        val response = APDUResponse(provider!!.transceive(gpoData)!!)

        return if (response.isSuccess()) {
            processGpoSuccess(response.getData())
        } else {
            handleGpoFailure(response, pAmount)
        }
    }

    private fun processGpoSuccess(data: ByteArray): ByteArray? {
        TLVParser.parseEx(data).getTLVList().forEach { tlv ->
            if (!tlv.tag.isConstructed()) emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
        }

        Log.d("NFC-EMV-Adaptor", data.joinToString("") { "%02x".format(it) })
        val msgTemplate = TLVParser.parseEx(data).searchByTag("80")

        return msgTemplate?.let {
            ResponseFormat1Parser.parse(CommandEnum.GPO, it.value).apply {
                getTLVList().forEach { tlv ->
                    if (!tlv.tag.isConstructed()) emvTransactionRecord.addEMVTagValue(tlv.tag.getTag().uppercase(), tlv.value)
                }
            }.searchByTag("94")?.value
        } ?: TLVParser.parseEx(data).searchByTag("94")?.value
    }

    private fun handleGpoFailure(response: APDUResponse, pAmount: String): ByteArray? {
        return if (response.isConditionNotSatisfied() && applicationCandidate != null) {
            emvTransactionRecord.clear()
            val candidate = selectHigherPriorityApplication(applicationCandidate!!)
            setApplicationWithAmount(candidate, pAmount)
            val pdol = selectAID(emvTransactionRecord.getAID())
            gpo(pdol, pAmount) // Call gpo again with the same PDOL
        } else if (response.isInvalidated()) {
            throw TLVException("Try another interface")
        } else {
            throw TLVException(bytesToString(response.toBytes()).uppercase())
        }
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
            val aflRecords: List<AFL> = AFLUtils.extractAFL(data)
            if (aflRecords.isEmpty()) {
                Log.d("NFC-EMV-Adaptor", "No AFL records found")
            } else {
                // Generate Read Record commands from AFL records
                val readRecordCommands: List<APDUCommand> = AFLUtils.generateReadRecordCommands(aflRecords)

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
                            Log.d("NFC-EMV-Adaptor", "CDOL2 ${value.joinToString("") { "%02x".format(it) }}")
                        }
                    }
                }

            }
        }
        return cdol1
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