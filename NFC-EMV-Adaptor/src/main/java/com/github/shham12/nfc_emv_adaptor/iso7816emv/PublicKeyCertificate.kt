package com.github.shham12.nfc_emv_adaptor.iso7816emv

/**
 * Crypto public key. Covers the chain from Scheme (CA) to Issuer (Bank) and then ICC (chip).
 */
interface PublicKeyCertificate {
    val exponent: String?
    val modulus: String
    val name: String
    val modulusLength: Int
        get() = modulus.length / 2
}