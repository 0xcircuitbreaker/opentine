package dev.opentine.ide.core

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.nio.file.Path
import java.util.concurrent.TimeUnit

/** One finished `tine` call. */
data class TineResult(val code: Int, val stdout: String, val stderr: String)

/**
 * Runs `tine` as an argument list (never through a shell) in the repository's
 * work tree, with a timeout. Paths handed to it are repository-relative and
 * POSIX, so `tine blame` and `tine why` see the name git does on every platform.
 */
class TineCli(private val command: List<String>, private val timeoutSeconds: Long = 60) {
    fun run(args: List<String>, workTree: File): TineResult {
        require(command.isNotEmpty()) { "no tine executable configured" }
        val process = ProcessBuilder(command + args).directory(workTree).start()
        val out = process.inputStream.bufferedReader(Charsets.UTF_8)
        val err = process.errorStream.bufferedReader(Charsets.UTF_8)
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val readers = listOf(
            Thread { stdout.append(out.readText()) },
            Thread { stderr.append(err.readText()) },
        )
        readers.forEach { it.start() }
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            throw IllegalStateException("tine did not finish in $timeoutSeconds s")
        }
        readers.forEach { it.join() }
        return TineResult(process.exitValue(), stdout.toString(), stderr.toString())
    }

    fun json(args: List<String>, workTree: File): JsonObject = parseJson(run(args, workTree))

    companion object {
        /** The JSON object a `--json` call printed; an error envelope becomes an exception. */
        fun parseJson(result: TineResult): JsonObject {
            val value = try {
                JsonParser.parseString(result.stdout.trim())
            } catch (e: Exception) {
                throw IllegalStateException(result.stderr.trim().ifEmpty { "tine printed no JSON (exit ${result.code})" })
            }
            if (!value.isJsonObject) throw IllegalStateException("tine printed a JSON value that is not an object")
            val document = value.asJsonObject
            val error = document.get("error")
            if (error != null && error.isJsonObject) {
                val message = error.asJsonObject.get("message")
                throw IllegalStateException(message?.takeIf { it.isJsonPrimitive }?.asString ?: "tine failed (exit ${result.code})")
            }
            return document
        }

        /** [file] relative to [root] with `/` separators; refuses a file outside [root]. */
        fun repoRelative(root: Path, file: Path): String {
            val rel = root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize())
            val text = rel.joinToString("/") { it.toString() }
            require(text.isNotEmpty() && !text.startsWith("..")) { "$file is not inside $root" }
            return text
        }

        fun blameArgs(path: String) = listOf("blame", path, "--lines", "--json")

        fun whyArgs(path: String, line: Int): List<String> {
            require(line >= 1) { "lines start at 1" }
            return listOf("why", "$path:$line", "--json")
        }

        fun verifyArgs(run: String): List<String> {
            require(!run.startsWith("-")) { "a run id never starts with '-'" }
            return listOf("verify", run, "--offline", "--json")
        }
    }
}
