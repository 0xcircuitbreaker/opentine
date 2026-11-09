package dev.opentine.ide.core

import com.google.gson.JsonObject

/** What `tine why FILE:LINE --json` says about one line. */
data class Provenance(val path: String, val line: Int, val commit: String, val run: String, val steps: Int, val model: String) {
    companion object {
        fun parse(document: JsonObject): Provenance {
            fun str(name: String) = document.get(name)?.takeIf { it.isJsonPrimitive }?.asString ?: ""
            val attribution = document.get("attribution")?.takeIf { it.isJsonObject }?.asJsonObject
            return Provenance(
                str("path"),
                document.get("line")?.takeIf { it.isJsonPrimitive }?.asInt ?: 0,
                str("commit"),
                str("run"),
                document.get("slice")?.takeIf { it.isJsonArray }?.asJsonArray?.size() ?: 0,
                attribution?.get("model")?.takeIf { it.isJsonPrimitive }?.asString ?: "",
            )
        }
    }
}

/** The verifier's verdict from `tine verify RUN --offline --json`, reported as it is. */
data class Verdict(val ok: Boolean, val verdict: String, val reason: String) {
    companion object {
        fun parse(document: JsonObject): Verdict {
            val verdict = document.get("verdict")?.takeIf { it.isJsonPrimitive }?.asString
                ?: if (document.get("ok")?.takeIf { it.isJsonPrimitive }?.asBoolean == true) "pass" else "fail"
            val failed = document.get("checks")?.takeIf { it.isJsonArray }?.asJsonArray
                ?.map { it.asJsonObject }
                ?.firstOrNull { it.get("outcome")?.asString == "fail" }
            return Verdict(verdict == "pass", verdict, failed?.get("reason")?.asString ?: "")
        }
    }
}

object Explain {
    /** One sentence for a notification; a line with no run is never called verified. */
    fun line(provenance: Provenance, verdict: Verdict?): String {
        val where = "${provenance.path}:${provenance.line}"
        if (provenance.run.isEmpty()) return "$where: no agent run is linked to this line (human-written, or not attributed)."
        val by = if (provenance.model.isEmpty()) "" else " by ${provenance.model}"
        val head = "$where: written$by in run ${provenance.run} (commit ${provenance.commit.take(12).ifEmpty { "-" }}, " +
            "${provenance.steps} step(s) in its causal slice)"
        return when {
            verdict == null -> "$head; the run is not held here, so it was not verified."
            verdict.ok -> "$head; verified offline: ${verdict.verdict}."
            else -> "$head; verification FAILED" + (if (verdict.reason.isEmpty()) "" else " (${verdict.reason})") + "."
        }
    }
}
