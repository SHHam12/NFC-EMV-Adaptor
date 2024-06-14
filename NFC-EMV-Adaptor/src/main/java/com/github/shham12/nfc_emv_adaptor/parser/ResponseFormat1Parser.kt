package com.github.shham12.nfc_emv_adaptor.parser

import com.github.shham12.nfc_emv_adaptor.iso7816emv.TLV
import com.github.shham12.nfc_emv_adaptor.iso7816emv.enum.CommandEnum
import com.github.shham12.nfc_emv_adaptor.util.TLVList

object ResponseFormat1Parser {
    fun parse(cmd: CommandEnum, data: ByteArray) : TLVList {
        val tlvList = TLVList()
        if (cmd == CommandEnum.GPO) {
            tlvList.add(TLV("82", 2, data.slice(0 until 2).toByteArray()))
            tlvList.add(TLV("94", data.slice(2 until data.size).size / 2, data.slice(2 until data.size).toByteArray()))
        }
        else if (cmd == CommandEnum.GENAC) {
            tlvList.add(TLV("9F27", 1, data.slice(0 until 2).toByteArray()))
            tlvList.add(TLV("9F36", 2, data.slice(2 until 6).toByteArray()))
            tlvList.add(TLV("9F26", 8, data.slice(6 until 22).toByteArray()))
            tlvList.add(TLV("9F36", data.slice(22 until data.size).size / 2, data.slice(22 until data.size).toByteArray()))
        }
        return tlvList
    }

}