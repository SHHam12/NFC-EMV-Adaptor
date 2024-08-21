package com.github.shham12.nfc_emv_adaptor.iso7816emv.impl

import com.github.shham12.nfc_emv_adaptor.iso7816emv.PublicKeyCertificate
import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName

data class CaPublicKey(
    @Expose @SerializedName("RID")
    var rid: String,

    @Expose @SerializedName("PKIndex")
    var index: String,

    @Expose @SerializedName("Exponent")
    override var exponent: String,

    @Expose @SerializedName("Modulus")
    override var modulus: String
) : PublicKeyCertificate {

    override var name: String = "CA public key ($rid,$index)"
}