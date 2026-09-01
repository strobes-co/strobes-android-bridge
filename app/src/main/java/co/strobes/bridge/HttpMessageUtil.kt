package co.strobes.bridge

import java.io.InputStream
import java.io.OutputStream

/**
 * Minimal HTTP/1.1 message reader/writer for the embedded MITM proxy.
 * Deliberately reconstructs messages rather than byte-for-byte passthrough
 * — simpler to reason about, and fine for a traffic-capture tool (this is
 * effectively what mitmproxy itself does too).
 */
object HttpMessageUtil {

    class ParsedMessage(
        val startLine: String,
        val headers: List<Pair<String, String>>,
        val body: ByteArray,
        val bodyTruncated: Boolean,
    )

    /** Caps how much of a single body we keep in memory / history — a capture
     * tool doesn't need to buffer a multi-MB file upload/download in full. */
    private const val MAX_BODY_BYTES = 256 * 1024

    fun header(headers: List<Pair<String, String>>, name: String): String? =
        headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    /** Reads one HTTP message (request or response) from [input]. Returns
     * null on clean EOF before any bytes of a new message arrive (the
     * normal way a keep-alive connection ends). */
    fun readMessage(input: InputStream): ParsedMessage? {
        // Tolerate stray blank lines between keep-alive messages (a bounded
        // loop, not recursion — a pathological all-blank-lines stream must
        // not be able to blow the stack).
        var startLine: String
        var blankGuard = 0
        while (true) {
            startLine = readLine(input) ?: return null
            if (startLine.isNotBlank() || ++blankGuard > 20) break
        }
        if (startLine.isBlank()) return null

        val headers = mutableListOf<Pair<String, String>>()
        while (true) {
            val line = readLine(input) ?: break
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            headers.add(line.substring(0, idx).trim() to line.substring(idx + 1).trim())
        }

        val transferEncoding = header(headers, "Transfer-Encoding")
        val contentLength = header(headers, "Content-Length")?.toLongOrNull()

        val (body, truncated) = when {
            transferEncoding?.contains("chunked", ignoreCase = true) == true -> readChunkedBody(input)
            contentLength != null && contentLength > 0 -> readFixedBody(input, contentLength)
            else -> ByteArray(0) to false
        }

        return ParsedMessage(startLine, headers, body, truncated)
    }

    fun writeMessage(output: OutputStream, startLine: String, headers: List<Pair<String, String>>, body: ByteArray) {
        val sb = StringBuilder()
        sb.append(startLine).append("\r\n")
        for ((k, v) in headers) sb.append(k).append(": ").append(v).append("\r\n")
        sb.append("\r\n")
        output.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        if (body.isNotEmpty()) output.write(body)
        output.flush()
    }

    /** Rebuilds a header list with Content-Length set correctly and any
     * Transfer-Encoding/Connection framing headers stripped — we already
     * fully buffered the body, so chunked framing no longer applies, and we
     * don't keep the upstream connection alive across requests. */
    fun framingHeadersFor(headers: List<Pair<String, String>>, bodyLength: Int): List<Pair<String, String>> {
        val filtered = headers.filterNot {
            it.first.equals("Transfer-Encoding", ignoreCase = true) ||
                it.first.equals("Content-Length", ignoreCase = true)
        }
        return filtered + ("Content-Length" to bodyLength.toString())
    }

    private fun readLine(input: InputStream): String? {
        val buf = StringBuilder()
        var sawAny = false
        while (true) {
            val b = input.read()
            if (b == -1) return if (sawAny) buf.toString() else null
            sawAny = true
            if (b == '\n'.code) {
                if (buf.isNotEmpty() && buf.last() == '\r') buf.deleteCharAt(buf.length - 1)
                return buf.toString()
            }
            buf.append(b.toChar())
        }
    }

    private fun readFixedBody(input: InputStream, length: Long): Pair<ByteArray, Boolean> {
        val cap = minOf(length, MAX_BODY_BYTES.toLong()).toInt()
        val buf = ByteArray(cap)
        var read = 0
        while (read < cap) {
            val n = input.read(buf, read, cap - read)
            if (n == -1) break
            read += n
        }
        var remaining = length - read
        // Drain (without storing) anything past our capture cap so the
        // stream stays in sync for the next message on this connection.
        val drain = ByteArray(8192)
        while (remaining > 0) {
            val n = input.read(drain, 0, minOf(remaining, drain.size.toLong()).toInt())
            if (n == -1) break
            remaining -= n
        }
        return buf.copyOf(read) to (length > cap)
    }

    private fun readChunkedBody(input: InputStream): Pair<ByteArray, Boolean> {
        val out = java.io.ByteArrayOutputStream()
        var truncated = false
        while (true) {
            val sizeLine = readLine(input) ?: break
            val size = sizeLine.trim().split(";")[0].toIntOrNull(16) ?: break
            if (size == 0) {
                // Trailing headers (rare) then the terminating blank line.
                while (true) {
                    val l = readLine(input) ?: break
                    if (l.isEmpty()) break
                }
                break
            }
            var remaining = size
            val chunk = ByteArray(8192)
            while (remaining > 0) {
                val n = input.read(chunk, 0, minOf(remaining, chunk.size))
                if (n == -1) break
                if (out.size() < MAX_BODY_BYTES) {
                    out.write(chunk, 0, minOf(n, MAX_BODY_BYTES - out.size()))
                } else {
                    truncated = true
                }
                remaining -= n
            }
            readLine(input) // trailing CRLF after each chunk's data
        }
        return out.toByteArray() to truncated
    }
}
