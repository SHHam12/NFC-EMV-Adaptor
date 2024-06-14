package com.github.shham12.nfc_emv_adaptor.parser.impl

import android.nfc.tech.IsoDep
import android.util.Log
import com.github.shham12.nfc_emv_adaptor.exception.CommunicationException
import com.github.shham12.nfc_emv_adaptor.parser.IProvider
import com.github.shham12.nfc_emv_adaptor.util.BytesUtils
import java.io.IOException


class Provider(isoDep: IsoDep) : IProvider {
    private var mTagCom: IsoDep? = isoDep

    @Throws(CommunicationException::class)
    override fun transceive(pCommand: ByteArray): ByteArray? {

        Log.d("APDUCommand", "send: " + BytesUtils.bytesToString(pCommand))

        val response: ByteArray
        try {
            // send command to emv card
            response = mTagCom!!.transceive(pCommand)
        } catch (e: IOException) {
            throw CommunicationException(e.message!!)
        }

        Log.d("APDUResponse", "receive: " + BytesUtils.bytesToString(response))

        return response
    }
}