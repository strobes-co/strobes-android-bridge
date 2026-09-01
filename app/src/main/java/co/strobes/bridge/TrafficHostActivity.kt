package co.strobes.bridge

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Second level of the Traffic tab's host → requests → detail drill-down —
 * the request list for one host, filtered server-side (well, in-process) via
 * ProxyController.history(hostFilter=...) rather than re-filtering the full
 * capture list client-side.
 */
class TrafficHostActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_HOST = "host"
        private const val POLL_MS = 3_000L
        private const val LIST_LIMIT = 200
    }

    private lateinit var host: String
    private lateinit var list: RecyclerView
    private lateinit var empty: TextView
    private lateinit var adapter: TrafficAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_traffic_host)

        host = intent.getStringExtra(EXTRA_HOST).orEmpty()
        findViewById<TextView>(R.id.host_title).text = host
        findViewById<View>(R.id.btn_back).setOnClickListener { finish() }

        empty = findViewById(R.id.host_empty)
        list = findViewById(R.id.host_entry_list)
        adapter = TrafficAdapter { entry ->
            startActivity(
                Intent(this, TrafficDetailActivity::class.java)
                    .putExtra(TrafficDetailActivity.EXTRA_ENTRY_ID, entry.optLong("id")),
            )
        }
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

        ProxyController.init(applicationContext)

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    val history = withContext(Dispatchers.IO) {
                        ProxyController.history(sinceId = 0, limit = LIST_LIMIT, hostFilter = host, includeBodies = false)
                    }
                    val entries = history.optJSONArray("entries")
                    val rows = mutableListOf<org.json.JSONObject>()
                    if (entries != null) for (i in 0 until entries.length()) rows.add(entries.getJSONObject(i))
                    adapter.submit(rows)
                    empty.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
                    list.visibility = if (rows.isEmpty()) View.GONE else View.VISIBLE
                    delay(POLL_MS)
                }
            }
        }
    }
}
