package com.github.shham12.nfc_emv_adaptor.iso7816emv.enum

enum class CommandEnum(val cla: Int, val ins: Int, val p1: Int, val p2: Int) {

    /**
     * Select command
     */
    SELECT(0x00, 0xA4, 0x04, 0x00),

    /**
     * Read record command
     */
    READ_RECORD(0x00, 0xB2, 0x00, 0x00),

    /**
     * GPO Command
     */
    GPO(0x80, 0xA8, 0x00, 0x00),

    /**
     * GENERATE APPLICATION CRYPTOGRAM
     */
    GENAC(0x80, 0xAE, 0x00, 0x00);
}
