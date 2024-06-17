package com.github.shham12.nfc_emv_adaptor.iso7816emv.impl

import com.github.shham12.nfc_emv_adaptor.iso7816emv.PublicKeyCertificate

data class ICCPublicKey(
    override var exponent: String,
    override var modulus: String,
    var remainder: String) : PublicKeyCertificate {
    override var name: String = "ICC public key ($exponent,$modulus,$remainder)"
    }
