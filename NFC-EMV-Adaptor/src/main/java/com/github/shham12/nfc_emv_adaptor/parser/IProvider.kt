package com.github.shham12.nfc_emv_adaptor.parser

interface IProvider {
    /**
     * Method used to transmit and receive card response
     *
     * @param pCommand
     * command to send to card
     * @return byte array returned by card
     */
    fun transceive(pCommand: ByteArray): ByteArray?
}