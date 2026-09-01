package co.strobes.bridge

import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Third level of the Traffic tab drill-down — a dedicated request/response
 * screen for one exchange, replacing the previous AlertDialog. Fetches with
 * includeBodies=true on demand (see MainActivity's old showTrafficDetail
 * comment for why the list poll never carries bodies).
 */
class TrafficDetailActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_ENTRY_ID = "entry_id"
        private const val MAX_BODY_DISPLAY_CHARS = 8_000
    }

    private lateinit var titleView: TextView
    private lateinit var bodyView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_traffic_detail)

        titleView = findViewById(R.id.detail_title)
        bodyView = findViewById(R.id.detail_body)
        findViewById<View>(R.id.btn_back).setOnClickListener { finish() }

        ProxyController.init(applicationContext)

        val id = intent.getLongExtra(EXTRA_ENTRY_ID, -1L)
        lifecycleScope.launch {
            val history = withContext(Dispatchers.IO) {
                ProxyController.history(sinceId = id - 1, limit = 1, hostFilter = null, includeBodies = true)
            }
            val entries = history.optJSONArray("entries")
            val entry = if (entries != null && entries.length() > 0) entries.getJSONObject(0) else null
            if (entry == null) {
                titleView.text = getString(R.string.traffic_hosts_empty)
                return@launch
            }
            render(entry)
        }
    }

    private fun render(entry: JSONObject) {
        titleView.text = entry.optString("host") + entry.optString("path")

        val sb = StringBuilder()
        sb.append(entry.optString("method")).append(' ').append(entry.optString("url")).append('\n')
        val status = entry.optInt("status", 0)
        if (status > 0) sb.append("Status: ").append(status).append(' ').append(entry.optString("status_text")).append('\n')
        entry.optString("error").let { if (it.isNotBlank()) sb.append("Error: ").append(it).append('\n') }
        sb.append("Duration: ").append(entry.optLong("duration_ms")).append("ms\n\n")

        sb.append("— ").append(getString(R.string.traffic_detail_request)).append(" —\n")
        appendHeaders(sb, entry.optJSONArray("request_headers"))
        appendBody(
            sb, entry.optString("request_body_b64"), entry.optBoolean("request_body_truncated"),
            isGzip(entry.optJSONArray("request_headers")),
        )

        sb.append("\n— ").append(getString(R.string.traffic_detail_response)).append(" —\n")
        appendHeaders(sb, entry.optJSONArray("response_headers"))
        appendBody(
            sb, entry.optString("response_body_b64"), entry.optBoolean("response_body_truncated"),
            isGzip(entry.optJSONArray("response_headers")),
        )

        bodyView.text = sb.toString()
    }

    private fun appendHeaders(sb: StringBuilder, headers: JSONArray?) {
        sb.append(getString(R.string.traffic_detail_headers)).append(":\n")
        if (headers == null || headers.length() == 0) {
            sb.append("  (none)\n")
            return
        }
        for (i in 0 until headers.length()) {
            val h = headers.getJSONObject(i)
            sb.append("  ").append(h.optString("name")).append(": ").append(h.optString("value")).append('\n')
        }
    }

    private fun isGzip(headers: JSONArray?): Boolean {
        if (headers == null) return false
        for (i in 0 until headers.length()) {
            val h = headers.getJSONObject(i)
            if (h.optString("name").equals("Content-Encoding", ignoreCase = true) &&
                h.optString("value").contains("gzip", ignoreCase = true)
            ) {
                return true
            }
        }
        return false
    }

    private fun appendBody(sb: StringBuilder, bodyB64: String, truncated: Boolean, gzip: Boolean) {
        sb.append(getString(R.string.traffic_detail_body)).append(":\n")
        if (bodyB64.isBlank()) {
            sb.append(getString(R.string.traffic_detail_body_empty)).append('\n')
            return
        }
        val raw = Base64.decode(bodyB64, Base64.NO_WRAP)
        val text = try {
            val bytes = if (gzip) {
                java.util.zip.GZIPInputStream(raw.inputStream()).use { it.readBytes() }
            } else {
                raw
            }
            String(bytes, Charsets.UTF_8)
        } catch (e: Exception) {
            "(binary, ${raw.size} bytes)"
        }
        sb.append(text.take(MAX_BODY_DISPLAY_CHARS))
        if (truncated || text.length > MAX_BODY_DISPLAY_CHARS) {
            sb.append(getString(R.string.traffic_detail_body_truncated))
        }
        sb.append('\n')
    }
}
