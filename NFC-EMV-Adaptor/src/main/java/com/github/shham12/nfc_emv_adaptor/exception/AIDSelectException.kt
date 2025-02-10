package com.github.shham12.nfc_emv_adaptor.exception

class AIDSelectException(message: String, cause: Throwable, aidList: List<String>, existingAIDs: List<String>)
    : Exception(message, cause) {

    init {
        val additionalTrace = StackTraceElement(
            "AIDSelection",
            "ErrorDetails",
            "AidList=${aidList}, ExistingAIDs=${existingAIDs}, SelectedApplication=${cause.message}",
            -1
        )

        stackTrace = arrayOf(additionalTrace) + cause.stackTrace
    }
}
