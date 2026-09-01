package co.strobes.bridge

import android.Manifest
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.tabs.TabLayout
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var statusDot: View
    private lateinit var statusText: TextView
    private lateinit var inputServerUrl: EditText
    private lateinit var inputOrgId: EditText
    private lateinit var inputApiKey: EditText
    private lateinit var inputShellName: EditText
    private lateinit var btnToggleBridge: android.widget.Button

    private lateinit var tabLayout: TabLayout
    private lateinit var statusContent: ScrollView
    private lateinit var trafficContent: View
    private lateinit var trafficList: RecyclerView
    private lateinit var trafficEmpty: TextView
    private lateinit var hostAdapter: HostAdapter

    // Last-seen BridgeForegroundService state — read by the single toggle
    // button's click handler (see renderStatus/onToggleBridgeClicked) so one
    // button can flip start<->stop instead of two separate buttons.
    private var lastBridgeConnected = false
    private var statusDotBlink: ObjectAnimator? = null

    companion object {
        private const val TRAFFIC_POLL_MS = 3_000L
        private const val TRAFFIC_LIST_LIMIT = 200
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusDot = findViewById(R.id.status_dot)
        statusText = findViewById(R.id.status_text)
        inputServerUrl = findViewById(R.id.input_server_url)
        inputOrgId = findViewById(R.id.input_org_id)
        inputApiKey = findViewById(R.id.input_api_key)
        inputShellName = findViewById(R.id.input_shell_name)
        btnToggleBridge = findViewById(R.id.btn_toggle_bridge)

        tabLayout = findViewById(R.id.tab_layout)
        statusContent = findViewById(R.id.status_content)
        trafficContent = findViewById(R.id.traffic_content)
        trafficList = findViewById(R.id.traffic_list)
        trafficEmpty = findViewById(R.id.traffic_empty)
        setupTabs()

        prefillFromPrefs()
        handlePairingDeepLink(intent)
        requestNotificationPermissionIfNeeded()

        // The proxy auto-starts with the bridge itself (see
        // BridgeForegroundService#startBridge) and can also be toggled
        // remotely (an agent's android_proxy_* tool calls, or the REST
        // API), or from DeviceStatusActivity — all paths share this one
        // ProxyController. init() must run regardless of which of those has
        // happened, so status can be reported (including "stopped") even on
        // a fresh install where the service has never started yet.
        ProxyController.init(applicationContext)
        DeviceContext.init(applicationContext)

        btnToggleBridge.setOnClickListener { onToggleBridgeClicked() }
        findViewById<View>(R.id.btn_setup_guide).setOnClickListener {
            startActivity(Intent(this, OnboardingActivity::class.java))
        }
        findViewById<View>(R.id.btn_capability_table).setOnClickListener {
            startActivity(Intent(this, CapabilityTableActivity::class.java))
        }
        findViewById<View>(R.id.row_device_status).setOnClickListener {
            startActivity(Intent(this, DeviceStatusActivity::class.java))
        }

        lifecycleScope.launch {
            BridgeForegroundService.status.collect { s -> renderStatus(s) }
        }

        // Same poll cadence DeviceStatusActivity uses for its own rows,
        // separate loop here: ProxyController.history() is an in-process,
        // in-memory read (no bridge/network round trip), so re-fetching the
        // whole recent window every tick is cheap — this is the same data
        // an agent's android_proxy_history tool reads, just rendered for a
        // human instead. includeBodies=false here: the list row never shows
        // body content, so there's no reason to base64-encode every
        // captured body on every 3s tick just to throw it away — see
        // TrafficDetailActivity for the on-demand body fetch.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    val history = withContext(Dispatchers.IO) {
                        ProxyController.history(sinceId = 0, limit = TRAFFIC_LIST_LIMIT, hostFilter = null, includeBodies = false)
                    }
                    renderTraffic(history)
                    delay(TRAFFIC_POLL_MS)
                }
            }
        }
    }

    private fun setupTabs() {
        tabLayout.addTab(tabLayout.newTab().setText(R.string.tab_status))
        tabLayout.addTab(tabLayout.newTab().setText(R.string.tab_traffic))
        tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                val showTraffic = tab.position == 1
                statusContent.visibility = if (showTraffic) View.GONE else View.VISIBLE
                trafficContent.visibility = if (showTraffic) View.VISIBLE else View.GONE
            }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })

        hostAdapter = HostAdapter { host ->
            startActivity(Intent(this, TrafficHostActivity::class.java).putExtra(TrafficHostActivity.EXTRA_HOST, host))
        }
        trafficList.layoutManager = LinearLayoutManager(this)
        trafficList.adapter = hostAdapter
    }

    /** Groups the flat capture list into per-host rows (see HostAdapter) —
     * tapping a host drills into TrafficHostActivity, then a request into
     * TrafficDetailActivity, replacing the old flat-list + AlertDialog view. */
    private fun renderTraffic(history: JSONObject) {
        val entries = history.optJSONArray("entries")
        val list = mutableListOf<JSONObject>()
        if (entries != null) {
            for (i in 0 until entries.length()) list.add(entries.getJSONObject(i))
        }
        hostAdapter.submit(list)
        trafficEmpty.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
        trafficList.visibility = if (list.isEmpty()) View.GONE else View.VISIBLE
    }

    /** Maps the raw service state string to a label + status-dot color —
     * the same red/yellow/green vocabulary the web platform's connection
     * tags use, so "connected" always reads the same regardless of surface. */
    private fun renderStatus(state: String) {
        val (label, colorRes) = when {
            state == "connected" -> "Connected" to R.color.cds_support_success
            state.startsWith("disconnected") -> "Disconnected" to R.color.cds_support_error
            state == "not paired" -> "Not paired" to R.color.cds_support_neutral
            state == "stopped" -> "Stopped" to R.color.cds_support_neutral
            else -> state to R.color.cds_support_warning
        }
        statusText.text = label
        statusDot.background.mutate().setTint(ContextCompat.getColor(this, colorRes))
        // A live "connected" state pulses — anything static (stopped,
        // disconnected, not paired) holds a solid dot, so blinking itself
        // reads as "actively live" without needing to read the label.
        if (state == "connected") startBlink(statusDot) else stopBlink(statusDot)

        // Only "stopped"/"not paired" count as fully off — anything else
        // (connecting, connected, disconnected-but-retrying) means the
        // service is already running, so the single toggle button's next
        // tap should stop it, not start a second instance.
        lastBridgeConnected = state != "stopped" && state != "not paired"
        btnToggleBridge.text = getString(if (lastBridgeConnected) R.string.action_stop else R.string.action_start)
        // Stop reads as a destructive/attention action (red), Start as a
        // go-ahead action (green) — color follows what tapping it DOES,
        // not the current state, so it never contradicts the status dot.
        btnToggleBridge.backgroundTintList = ColorStateList.valueOf(
            ContextCompat.getColor(this, if (lastBridgeConnected) R.color.cds_support_error else R.color.cds_support_success),
        )
    }

    private fun startBlink(view: View) {
        if (statusDotBlink != null) return
        statusDotBlink = ObjectAnimator.ofFloat(view, View.ALPHA, 1f, 0.25f).apply {
            duration = 700
            repeatMode = ValueAnimator.REVERSE
            repeatCount = ValueAnimator.INFINITE
            start()
        }
    }

    private fun stopBlink(view: View) {
        statusDotBlink?.cancel()
        statusDotBlink = null
        view.alpha = 1f
    }

    override fun onDestroy() {
        statusDotBlink?.cancel()
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handlePairingDeepLink(intent)
    }

    private fun prefillFromPrefs() {
        inputServerUrl.setText(Prefs.serverUrl(this))
        inputOrgId.setText(Prefs.orgId(this))
        inputApiKey.setText(Prefs.apiKey(this))
        inputShellName.setText(
            Prefs.shellName(this).ifBlank { Build.MODEL },
        )
    }

    /** Parses strobesbridge://pair?server=...&org_id=...&api_key=...&name=... */
    private fun handlePairingDeepLink(intent: Intent?) {
        val uri: Uri = intent?.data ?: return
        if (uri.scheme != "strobesbridge" || uri.host != "pair") return

        uri.getQueryParameter("server")?.let { inputServerUrl.setText(it) }
        uri.getQueryParameter("org_id")?.let { inputOrgId.setText(it) }
        uri.getQueryParameter("api_key")?.let { inputApiKey.setText(it) }
        uri.getQueryParameter("name")?.let { inputShellName.setText(it) }
        // Pin to the Shell row the platform already created for this pairing,
        // instead of this app's own self-generated bridge_id — otherwise the
        // Shell's "connected" status would never reflect this connection.
        uri.getQueryParameter("bridge_id")?.let { Prefs.setBridgeId(this, it) }

        Toast.makeText(this, "Pairing details loaded — review and tap Start", Toast.LENGTH_LONG).show()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001,
                )
            }
        }
    }

    /** Single toggle: flips to whichever action `lastBridgeConnected` (kept
     * live by renderStatus, driven by BridgeForegroundService.status) says
     * is next — replaces the previous separate Start/Stop buttons. */
    private fun onToggleBridgeClicked() {
        if (lastBridgeConnected) onStopClicked() else onStartClicked()
    }

    private fun onStartClicked() {
        val serverUrl = inputServerUrl.text.toString().trim()
        val orgId = inputOrgId.text.toString().trim()
        val apiKey = inputApiKey.text.toString().trim()
        val shellName = inputShellName.text.toString().trim()

        if (serverUrl.isBlank() || orgId.isBlank() || apiKey.isBlank()) {
            Toast.makeText(this, "Server URL, Organization ID and API key are required", Toast.LENGTH_LONG).show()
            return
        }

        Prefs.save(this, serverUrl, orgId, apiKey, shellName)

        val serviceIntent = Intent(this, BridgeForegroundService::class.java)
            .setAction(BridgeForegroundService.ACTION_START)
        startForegroundService(serviceIntent)
        Toast.makeText(this, "Bridge starting…", Toast.LENGTH_SHORT).show()
    }

    private fun onStopClicked() {
        val serviceIntent = Intent(this, BridgeForegroundService::class.java)
            .setAction(BridgeForegroundService.ACTION_STOP)
        startService(serviceIntent)
    }
}
