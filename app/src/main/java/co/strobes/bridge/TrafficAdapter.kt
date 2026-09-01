package co.strobes.bridge

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import java.text.SimpleDateFormat
import java.util.Locale
import org.json.JSONObject

/**
 * Renders the live capture list on the Traffic tab. Backed directly by
 * ProxyController.history()'s JSON entries (see MainActivity's poll loop) —
 * no separate view-model, this is a lab tool showing an in-memory buffer
 * that's already cheap to re-fetch in full every poll tick.
 */
class TrafficAdapter(
    private val onEntryClick: (JSONObject) -> Unit,
) : RecyclerView.Adapter<TrafficAdapter.ViewHolder>() {

    private var entries: List<JSONObject> = emptyList()

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    /** Newest-first — [newEntries] arrives oldest-first from ProxyHistoryStore. */
    fun submit(newEntries: List<JSONObject>) {
        entries = newEntries.asReversed()
        notifyDataSetChanged()
    }

    class ViewHolder(view: android.view.View) : RecyclerView.ViewHolder(view) {
        val method: TextView = view.findViewById(R.id.entry_method)
        val hostPath: TextView = view.findViewById(R.id.entry_host_path)
        val status: TextView = view.findViewById(R.id.entry_status)
        val meta: TextView = view.findViewById(R.id.entry_meta)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_traffic_entry, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val e = entries[position]
        val context = holder.itemView.context

        holder.method.text = e.optString("method")
        holder.hostPath.text = e.optString("host") + e.optString("path")

        val error = e.optString("error")
        val status = e.optInt("status", 0)
        when {
            error.isNotBlank() -> {
                holder.status.text = "ERR"
                holder.status.setTextColor(ContextCompat.getColor(context, R.color.cds_support_error))
            }
            status == 0 -> {
                holder.status.text = "…"
                holder.status.setTextColor(ContextCompat.getColor(context, R.color.cds_support_neutral))
            }
            else -> {
                holder.status.text = status.toString()
                holder.status.setTextColor(
                    ContextCompat.getColor(
                        context,
                        when {
                            status < 300 -> R.color.cds_support_success
                            status < 400 -> R.color.cds_support_info
                            status < 500 -> R.color.cds_support_warning
                            else -> R.color.cds_support_error
                        },
                    ),
                )
            }
        }

        val time = timeFormat.format(e.optLong("timestamp_ms"))
        val duration = e.optLong("duration_ms")
        holder.meta.text = "$time · ${duration}ms"

        holder.itemView.setOnClickListener { onEntryClick(e) }
    }

    override fun getItemCount(): Int = entries.size
}
