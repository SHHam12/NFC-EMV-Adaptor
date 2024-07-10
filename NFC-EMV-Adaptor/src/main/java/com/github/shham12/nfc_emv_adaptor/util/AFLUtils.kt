package com.github.shham12.nfc_emv_adaptor.util

import android.util.Log
import com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu.APDUCommand
import com.github.shham12.nfc_emv_adaptor.iso7816emv.enum.CommandEnum
import com.github.shham12.nfc_emv_adaptor.iso7816emv.model.AFL

class AFLUtils {
    companion object {
        fun generateReadRecordCommands(pAFLRecords: List<AFL?>): List<APDUCommand> {
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
         * @param pAFL AFL data
         * @return list of AFL
         */
        fun extractAFL(pAFL: ByteArray): List<AFL> {
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
    }
}