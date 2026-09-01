package co.strobes.bridge

import java.io.File
import java.security.MessageDigest

/**
 * Non-root stand-in for the arbitrary-absolute-path filesystem access
 * FileTransfer normally gets via `su`. Without root, this app can only read/
 * write inside its own sandbox (getExternalFilesDir), not literal paths like
 * `/sdcard/foo.png` or `/data/local/tmp/foo` — but the backend tool layer
 * (AndroidScreenshotTool etc.) is unaware of that distinction: it writes
 * somewhere via shell_execute (ShellCommandRouter, e.g. `screencap -p
 * /sdcard/x.png`) then reads the SAME literal path back via file_download.
 *
 * Fix: deterministically map every requested path to one sandbox file keyed
 * by the path itself (hashed, to dodge illegal-filename characters and
 * length limits) — the same nominal path always resolves to the same real
 * file, so that write-then-read round trip keeps working unmodified on a
 * non-root device.
 */
object VirtualFs {

    private fun keyFor(path: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(path.toByteArray(Charsets.UTF_8))
        val hex = digest.joinToString("") { "%02x".format(it) }.take(16)
        val base = File(path).name.ifBlank { "file" }.filter { it.isLetterOrDigit() || it in "._-" }.take(60)
        return "${hex}_$base"
    }

    fun resolve(path: String): File {
        val dir = File(DeviceContext.require().getExternalFilesDir(null), "virtualfs")
        dir.mkdirs()
        return File(dir, keyFor(path))
    }

    fun write(path: String, bytes: ByteArray) {
        resolve(path).writeBytes(bytes)
    }

    fun read(path: String): ByteArray? {
        val f = resolve(path)
        return if (f.exists()) f.readBytes() else null
    }

    fun exists(path: String): Boolean = resolve(path).exists()

    fun delete(path: String): Boolean = resolve(path).delete()
}
