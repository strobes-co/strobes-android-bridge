package co.strobes.bridge

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.json.JSONObject

/**
 * Groups the flat capture list (ProxyController.history()) by host for the
 * Traffic tab's top-level view — tapping a row drills into TrafficHostActivity
 * for that host's individual exchanges, mirroring how a proxy tool like
 * Burp/mitmproxy groups its own history by target.
 */
class HostAdapter(
    private val onHostClick: (String) -> Unit,
) : RecyclerView.Adapter<HostAdapter.ViewHolder>() {

    data class HostEntry(val host: String, val count: Int, val lastTimestampMs: Long)

    private var hosts: List<HostEntry> = emptyList()

    /** [entries] arrives oldest-first from ProxyHistoryStore, host+count
     * unaffected by order — sorted here by most-recently-active host first. */
    fun submit(entries: List<JSONObject>) {
        val grouped = entries.groupBy { it.optString("host") }
        hosts = grouped.map { (host, list) ->
            HostEntry(host, list.size, list.maxOf { it.optLong("timestamp_ms") })
        }.sortedByDescending { it.lastTimestampMs }
        notifyDataSetChanged()
    }

    class ViewHolder(view: android.view.View) : RecyclerView.ViewHolder(view) {
        val name: TextView = view.findViewById(R.id.host_name)
        val count: TextView = view.findViewById(R.id.host_count)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_host_entry, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val h = hosts[position]
        holder.name.text = h.host
        holder.count.text = "${h.count} exchange${if (h.count == 1) "" else "s"}"
        holder.itemView.setOnClickListener { onHostClick(h.host) }
    }

    override fun getItemCount(): Int = hosts.size
}
