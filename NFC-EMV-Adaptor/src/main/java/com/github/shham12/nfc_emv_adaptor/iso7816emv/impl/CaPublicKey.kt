package com.github.shham12.nfc_emv_adaptor.iso7816emv.impl

import com.github.shham12.nfc_emv_adaptor.iso7816emv.PublicKeyCertificate

data class CaPublicKey(
    var rid: String,
    var index: String,
    override var exponent: String,
    override var modulus: String) : PublicKeyCertificate {
    override var name: String = "CA public key ($rid,$index)"
}