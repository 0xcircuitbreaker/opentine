package dev.opentine.ide.core

import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Path

/** The IDE-independent core, against the same fixture the VS Code extension uses. */
class CoreTest {
    private val fixture = File("../vscode/test/fixtures/blame-lines.json").readText()

    @Test
    fun onlyAiLinesGetAGutterLabel() {
        val record = BlameRecord.parse(JsonParser.parseString(fixture).asJsonObject)
        assertNull(record.gutterLabel(0))
        assertEquals("AI claude-sonnet-4-5 be292c795e4d", record.gutterLabel(1))
        assertEquals("2 of 3 lines AI-written (67%)", record.aiShare())
    }

    @Test
    fun argumentListsArePosixAndNeverOptions() {
        assertEquals(listOf("why", "src/app.py:2", "--json"), TineCli.whyArgs("src/app.py", 2))
        assertEquals("src/app.py", TineCli.repoRelative(Path.of("w"), Path.of("w", "src", "app.py")))
        assertTrue(runCatching { TineCli.verifyArgs("--help") }.isFailure)
    }

    @Test
    fun verdictsAreWordedApart() {
        val why = Provenance("a.py", 3, "c".repeat(40), "run:sha256:" + "be".repeat(32), 2, "m")
        val failed = Verdict.parse(JsonParser.parseString(
            """{"verdict":"fail","checks":[{"outcome":"fail","reason":"integrity.mismatch"}]}""").asJsonObject)
        assertFalse(failed.ok)
        assertTrue(Explain.line(why, failed).contains("FAILED (integrity.mismatch)"))
        assertTrue(Explain.line(why, null).contains("not verified"))
        assertTrue(Explain.line(why.copy(run = ""), null).contains("no agent run"))
    }
}
