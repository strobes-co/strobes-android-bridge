package co.strobes.bridge

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

/** One captured request/response exchange, sent back to Strobes as JSON. */
data class CapturedExchange(
    val id: Long,
    val timestampMs: Long,
    val scheme: String,
    val host: String,
    val method: String,
    val path: String,
    val requestHeaders: List<Pair<String, String>>,
    val requestBody: ByteArray,
    val requestBodyTruncated: Boolean,
    val status: Int,
    val statusText: String,
    val responseHeaders: List<Pair<String, String>>,
    val responseBody: ByteArray,
    val responseBodyTruncated: Boolean,
    val durationMs: Long,
    val error: String? = null,
) {
    fun toJson(includeBodies: Boolean): JSONObject {
        val o = JSONObject()
        o.put("id", id)
        o.put("timestamp_ms", timestampMs)
        o.put("scheme", scheme)
        o.put("host", host)
        o.put("method", method)
        o.put("path", path)
        o.put("url", "$scheme://$host$path")
        o.put("request_headers", headersToJson(requestHeaders))
        o.put("status", status)
        o.put("status_text", statusText)
        o.put("response_headers", headersToJson(responseHeaders))
        o.put("duration_ms", durationMs)
        o.put("request_body_size", requestBody.size)
        o.put("request_body_truncated", requestBodyTruncated)
        o.put("response_body_size", responseBody.size)
        o.put("response_body_truncated", responseBodyTruncated)
        if (error != null) o.put("error", error)
        if (includeBodies) {
            if (requestBody.isNotEmpty()) {
                o.put("request_body_b64", Base64.encodeToString(requestBody, Base64.NO_WRAP))
            }
            if (responseBody.isNotEmpty()) {
                o.put("response_body_b64", Base64.encodeToString(responseBody, Base64.NO_WRAP))
            }
        }
        return o
    }

    private fun headersToJson(headers: List<Pair<String, String>>): JSONArray {
        val arr = JSONArray()
        for ((k, v) in headers) {
            val h = JSONObject()
            h.put("name", k)
            h.put("value", v)
            arr.put(h)
        }
        return arr
    }
}

/**
 * Bounded in-memory capture buffer. In-memory (not persisted) is a
 * deliberate scope choice — a pentest session is bounded, and this mirrors
 * android_logcat's own line-cap approach elsewhere in this bridge: cap it,
 * evict the oldest, never grow unbounded.
 */
object ProxyHistoryStore {
    private const val MAX_ENTRIES = 1000

    private val idCounter = AtomicLong(0)
    private val entries = ArrayDeque<CapturedExchange>()
    private val lock = Any()

    fun nextId(): Long = idCounter.incrementAndGet()

    fun add(exchange: CapturedExchange) {
        synchronized(lock) {
            entries.addLast(exchange)
            while (entries.size > MAX_ENTRIES) entries.removeFirst()
        }
    }

    /** [sinceId] = only entries with id greater than this (for incremental polling). */
    fun list(sinceId: Long, limit: Int, hostFilter: String?): List<CapturedExchange> {
        synchronized(lock) {
            return entries.asSequence()
                .filter { it.id > sinceId }
                .filter { hostFilter.isNullOrBlank() || it.host.contains(hostFilter, ignoreCase = true) }
                .toList()
                .takeLast(limit.coerceAtMost(MAX_ENTRIES))
        }
    }

    fun count(): Int = synchronized(lock) { entries.size }

    fun clear() = synchronized(lock) { entries.clear() }
}
