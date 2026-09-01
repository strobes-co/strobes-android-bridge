package co.strobes.bridge

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * File I/O for the Android bridge — the on-device analog of
 * strobes_shell_agent/executor.py's read_file/write_file/list_files/
 * upload_file/download_file, same command names and response shapes, so
 * backend agent tools that already speak this protocol to the desktop
 * bridge work against this one unmodified.
 *
 * This is what lets an agent install an APK (file_upload the bytes, then
 * shell_execute("pm install ...") — or for split APKs, pm install-create /
 * install-write per split / install-commit) and pull back UI-automation
 * artifacts (screencap PNGs, uiautomator dump XML) that must NOT go through
 * shell_execute's UTF-8 text decoding, since that would corrupt binary data.
 *
 * Every operation shells out through `su -c` directly (bypassing libsu's
 * text-oriented Shell.Result) so bytes move as raw process stdin/stdout —
 * safe for arbitrary binary content, and works the same whether root comes
 * from a Magisk daemon or a bare AOSP su binary.
 */
object FileTransfer {

    // Mirrors the desktop daemon's RAW_LIMIT: base64 inflates ~33%, and the
    // platform's WS frame cap is 10MB — stay well under it either direction.
    private const val MAX_TRANSFER_BYTES = 7_500_000

    private fun quote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    /** Mirrors read_file(path) -> {success, content, size, truncated?} (TEXT). */
    suspend fun readFile(path: String): JSONObject = withContext(Dispatchers.IO) {
        val raw = readBytes(path) ?: return@withContext JSONObject().apply {
            put("success", false)
            put("error", "File not found or unreadable: $path")
        }
        val text = if (raw.size > MAX_TRANSFER_BYTES) {
            String(raw, 0, MAX_TRANSFER_BYTES, Charsets.UTF_8)
        } else {
            String(raw, Charsets.UTF_8)
        }
        JSONObject().apply {
            put("success", true)
            put("content", text)
            put("size", raw.size)
            if (raw.size > MAX_TRANSFER_BYTES) put("truncated", true)
        }
    }

    /** Mirrors write_file(path, content, mode) -> {success, path, size} (TEXT). */
    suspend fun writeFile(path: String, content: String, mode: String): JSONObject =
        withContext(Dispatchers.IO) {
            val bytes = content.toByteArray(Charsets.UTF_8)
            val append = mode == "append"
            writeBytes(path, bytes, append)
        }

    /** Mirrors upload_file(path, content_b64) -> {success, path, size} (BINARY). */
    suspend fun uploadFile(path: String, contentB64: String): JSONObject = withContext(Dispatchers.IO) {
        val bytes = try {
            Base64.decode(contentB64, Base64.DEFAULT)
        } catch (e: Exception) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Invalid base64: ${e.message}")
            }
        }
        writeBytes(path, bytes, append = false)
    }

    /** Mirrors download_file(path) -> {success, content_b64, size} (BINARY). */
    suspend fun downloadFile(path: String): JSONObject = withContext(Dispatchers.IO) {
        val raw = readBytes(path) ?: return@withContext JSONObject().apply {
            put("success", false)
            put("error", "File not found or unreadable: $path")
        }
        if (raw.size > MAX_TRANSFER_BYTES) {
            return@withContext JSONObject().apply {
                put("success", false)
                put(
                    "error",
                    "File too large: ${raw.size} bytes (max $MAX_TRANSFER_BYTES bytes). " +
                        "For large files (big APKs, video captures), have the device fetch it " +
                        "directly instead: shell_execute(\"curl -o '$path' <url>\")."
                )
            }
        }
        JSONObject().apply {
            put("success", true)
            put("content_b64", Base64.encodeToString(raw, Base64.NO_WRAP))
            put("size", raw.size)
        }
    }

    /** Mirrors list_files(directory, pattern, recursive) -> {success, directory, files[]}. */
    suspend fun listFiles(directory: String, recursive: Boolean): JSONObject = withContext(Dispatchers.IO) {
        if (!RootShellExecutor.checkRoot().available) {
            // No non-root way to browse an arbitrary real directory — this app
            // can only see its own sandbox, and VirtualFs's hashed filenames
            // don't preserve the original directory structure to list by. Be
            // honest about that rather than pretending to browse `directory`.
            return@withContext JSONObject().apply {
                put("success", false)
                put(
                    "error",
                    "Root is unavailable — arbitrary directory listing isn't possible without it. " +
                        "Use file_download on a specific known path instead (works via the virtual-fs " +
                        "fallback for paths this bridge itself wrote, e.g. a screencap/uiautomator-dump output).",
                )
            }
        }
        // `find -maxdepth 1` for a flat listing, or a real recursive find — both
        // text-safe, so this can reuse the ordinary root shell exec path.
        val findArgs = if (recursive) "" else "-maxdepth 1 -mindepth 1"
        val cmd = "find ${quote(directory)} $findArgs -printf '%y\\t%s\\t%P\\n' 2>&1"
        val result = RootShellExecutor.executeShellCommand(cmd, 30)
        if (!result.optBoolean("success", false)) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Directory not found or unreadable: $directory")
            }
        }
        val files = JSONArray()
        result.optString("stdout", "").lineSequence().forEach { line ->
            if (line.isBlank()) return@forEach
            val parts = line.split("\t", limit = 3)
            if (parts.size == 3) {
                files.put(JSONObject().apply {
                    put("name", parts[2])
                    put("type", if (parts[0] == "d") "dir" else "file")
                    put("size", parts[1].toLongOrNull() ?: 0L)
                })
            }
        }
        JSONObject().apply {
            put("success", true)
            put("directory", directory)
            put("files", files)
        }
    }

    // -------------------------------------------------------------------
    // Byte I/O — root path bypasses libsu's text Shell.Result for raw bytes;
    // non-root path reads/writes the VirtualFs sandbox mapping instead.
    // -------------------------------------------------------------------

    private fun readBytes(path: String): ByteArray? =
        if (RootShellExecutor.checkRoot().available) catBytes(path) else VirtualFs.read(path)

    private fun writeBytes(path: String, bytes: ByteArray, append: Boolean): JSONObject =
        if (RootShellExecutor.checkRoot().available) {
            writeBytesAsRoot(path, bytes, append)
        } else {
            try {
                if (append) {
                    val existing = VirtualFs.read(path) ?: ByteArray(0)
                    VirtualFs.write(path, existing + bytes)
                } else {
                    VirtualFs.write(path, bytes)
                }
                JSONObject().apply { put("success", true); put("path", path); put("size", bytes.size) }
            } catch (e: Exception) {
                JSONObject().apply { put("success", false); put("error", e.message ?: "write failed") }
            }
        }

    private fun catBytes(path: String): ByteArray? {
        return try {
            val proc = ProcessBuilder("su", "-c", "cat ${quote(path)}").start()
            val bytes = proc.inputStream.readBytes()
            val exit = proc.waitFor()
            if (exit != 0) null else bytes
        } catch (e: Exception) {
            null
        }
    }

    private fun writeBytesAsRoot(path: String, bytes: ByteArray, append: Boolean): JSONObject {
        return try {
            val redirect = if (append) ">>" else ">"
            val dir = File(path).parent ?: "/"
            val cmd = "mkdir -p ${quote(dir)} && cat $redirect ${quote(path)}"
            val proc = ProcessBuilder("su", "-c", cmd).start()
            proc.outputStream.use { it.write(bytes); it.flush() }
            val err = proc.errorStream.bufferedReader().readText()
            val exit = proc.waitFor()
            if (exit == 0) {
                JSONObject().apply {
                    put("success", true)
                    put("path", path)
                    put("size", bytes.size)
                }
            } else {
                JSONObject().apply {
                    put("success", false)
                    put("error", err.ifBlank { "write failed (exit $exit)" })
                }
            }
        } catch (e: Exception) {
            JSONObject().apply {
                put("success", false)
                put("error", e.message ?: "write failed")
            }
        }
    }
}
