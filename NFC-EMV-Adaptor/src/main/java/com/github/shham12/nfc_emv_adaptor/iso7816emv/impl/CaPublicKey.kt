package com.github.shham12.nfc_emv_adaptor.iso7816emv.impl

import com.github.shham12.nfc_emv_adaptor.iso7816emv.PublicKeyCertificate
import com.google.gson.annotations.SerializedName

data class CaPublicKey(
    @SerializedName("RID")
    var rid: String,

    @SerializedName("PKIndex")
    var index: String,

    @SerializedName("Exponent")
    override var exponent: String,

    @SerializedName("Modulus")
    override var modulus: String
) : PublicKeyCertificate {

    override var name: String = "CA public key ($rid,$index)"
}