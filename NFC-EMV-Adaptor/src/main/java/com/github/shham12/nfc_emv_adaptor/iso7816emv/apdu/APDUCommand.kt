package com.github.shham12.nfc_emv_adaptor.iso7816emv.apdu

import com.github.shham12.nfc_emv_adaptor.iso7816emv.enum.CommandEnum

class APDUCommand(
        private val mCla: Int,
        private val mIns: Int,
        private val mP1: Int = 0x00,
        private val mP2: Int = 0x00,
        private val mLc: Int = 0x00,
        private val mData: ByteArray? = null,
        private val mLe: Int = 0x00,
        private val mLeUsed: Boolean = false
) {

    constructor(pEnum: CommandEnum, data: ByteArray?, le: Int) : this(
            mCla = pEnum.cla,
            mIns = pEnum.ins,
            mP1 = pEnum.p1,
            mP2 = pEnum.p2,
            mLc = data?.size ?: 0,
            mData = data ?: ByteArray(0),
            mLe = le,
            mLeUsed = true
    )

    constructor(pEnum: CommandEnum, p1: Int, p2: Int, le: Int) : this(
            mCla = pEnum.cla,
            mIns = pEnum.ins,
            mP1 = p1,
            mP2 = p2,
            mLe = le,
            mLeUsed = true
    )

    constructor(pEnum: CommandEnum, p1: Int, p2: Int) : this(
            mCla = pEnum.cla,
            mIns = pEnum.ins,
            mP1 = p1,
            mP2 = p2,
            mLeUsed = false
    )

    constructor(pEnum: CommandEnum, p1: Int, p2: Int, data: ByteArray?, le: Int) : this(
            mCla = pEnum.cla,
            mIns = pEnum.ins,
            mP1 = p1,
            mP2 = p2,
            mLc = data?.size ?: 0,
            mData = data ?: ByteArray(0),
            mLe = le,
            mLeUsed = true
    )

    fun toBytes(): ByteArray {
        val header = byteArrayOf(mCla.toByte(), mIns.toByte(), mP1.toByte(), mP2.toByte())
        return when {
            mData != null && mLeUsed ->
                header +
                        mLc.toByte() +
                        mData +
                        mLe.toByte() // When Data is exist send: CLS INS P1 P2
            mData != null && !mLeUsed ->
                    header +
                        mLc.toByte() +
                        mData // When Data is exist send: CLS INS P1 P2
            mLeUsed -> header + mLe.toByte()
            // Lc Data Le
            else -> header // If Data is not exist: CLS INS P1 P2 Le
        }
    }
}








