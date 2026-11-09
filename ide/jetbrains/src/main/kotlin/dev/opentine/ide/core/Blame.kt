package dev.opentine.ide.core

import com.google.gson.JsonElement
import com.google.gson.JsonObject

/** The run (and step and model) that wrote one line, from the attribution notes. */
data class AiAttribution(val run: String, val seq: Int?, val model: String)

data class BlameLine(val line: Int, val commit: String, val author: String, val summary: String, val ai: AiAttribution?)

/** The per-line `tine-blame/1` record of `tine blame FILE --lines --json`. */
data class BlameRecord(val path: String, val totalLines: Int, val aiLines: Int, val lines: List<BlameLine>) {
    /** "12 of 40 lines AI-written (30%)". */
    fun aiShare(): String {
        val percent = if (totalLines == 0) 0 else Math.round(100.0 * aiLines / totalLines).toInt()
        return "$aiLines of $totalLines lines AI-written ($percent%)"
    }

    /** The gutter text for a 0-based [index], or null for a human-written line. */
    fun gutterLabel(index: Int): String? {
        val ai = lines.firstOrNull { it.line == index + 1 }?.ai ?: return null
        return "AI ${ai.model.ifEmpty { "agent" }} ${shortRun(ai.run)}"
    }

    fun tooltip(index: Int): String? {
        val row = lines.firstOrNull { it.line == index + 1 } ?: return null
        val ai = row.ai ?: return null
        val step = ai.seq?.let { " step $it" } ?: ""
        return "AI-written by ${ai.model.ifEmpty { "an agent" }}\nrun ${ai.run}$step\n" +
            "commit ${row.commit.take(12)} by ${row.author}: ${row.summary}"
    }

    companion object {
        private fun str(e: JsonElement?): String = if (e != null && e.isJsonPrimitive) e.asString else ""

        private fun int(e: JsonElement?): Int? =
            if (e != null && e.isJsonPrimitive && e.asJsonPrimitive.isNumber) e.asInt else null

        fun parse(document: JsonObject): BlameRecord {
            val lines = document.get("lines")
            require(str(document.get("schema")) == "tine-blame/1" && lines != null && lines.isJsonArray) {
                "not a `tine blame --lines --json` record (tine-blame/1)"
            }
            val rows = lines.asJsonArray.mapNotNull { raw ->
                if (!raw.isJsonObject) return@mapNotNull null
                val row = raw.asJsonObject
                val line = int(row.get("line")) ?: return@mapNotNull null
                val ai = row.get("ai")?.takeIf { it.isJsonObject }?.asJsonObject?.let {
                    AiAttribution(str(it.get("run")), int(it.get("seq")), str(it.get("model")))
                }
                BlameLine(line, str(row.get("commit")), str(row.get("author")), str(row.get("summary")), ai)
            }
            return BlameRecord(
                str(document.get("path")),
                int(document.get("total_lines")) ?: rows.size,
                int(document.get("ai_lines")) ?: rows.count { it.ai != null },
                rows,
            )
        }

        /** A run id shortened to its digest's first 12 hex digits. */
        fun shortRun(run: String): String {
            val at = run.indexOf(":sha256:")
            return (if (at >= 0) run.substring(at + 8) else run).take(12)
        }
    }
}
