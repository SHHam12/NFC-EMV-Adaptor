package com.github.shham12.nfc_emv_adaptor.iso7816emv.model

data class AFL(val sfi: Int, val startRecord: Int, val endRecord: Int, val offlineRecords: Int) {
    override fun toString(): String {
        return "SFI: $sfi, Start: $startRecord, End: $endRecord"
    }
}
