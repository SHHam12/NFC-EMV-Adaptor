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
            tlvList.add(TLV("9F27", 1, data.slice(0 until 1).toByteArray()))
            tlvList.add(TLV("9F36", 2, data.slice(1 until 3).toByteArray()))
            tlvList.add(TLV("9F26", 8, data.slice(3 until 11).toByteArray()))
            tlvList.add(TLV("9F10", data.size - 11, data.slice(11 until data.size).toByteArray()))
        }
        return tlvList
    }

}