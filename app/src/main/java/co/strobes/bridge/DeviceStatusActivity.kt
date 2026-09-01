package co.strobes.bridge

import android.app.AlertDialog
import android.content.Intent
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Everything about THIS device's capability posture that isn't "am I paired
 * and talking to the platform" (that stays on MainActivity, alongside the
 * pairing fields and the single start/stop toggle) — root, the non-root
 * Accessibility fallback, the embedded MITM proxy, CA trust, capture count,
 * and the optional reboot-required system trust store. Split out from
 * MainActivity so the main screen reads as "bridge details + start bridge,"
 * not a wall of unrelated status rows.
 */
class DeviceStatusActivity : AppCompatActivity() {

    private lateinit var rootStatusText: TextView
    private lateinit var automationStatusDot: View
    private lateinit var automationStatusText: TextView
    private lateinit var btnOpenAccessibilitySettings: android.widget.Button
    private lateinit var proxyStatusDot: View
    private lateinit var proxyStatusText: TextView
    private lateinit var btnToggleProxy: android.widget.Button
    private lateinit var caStatusText: TextView
    private lateinit var btnToggleCa: android.widget.Button
    private lateinit var capturedCountText: TextView
    private lateinit var rootCaStatusDot: View
    private lateinit var rootCaStatusText: TextView
    private lateinit var btnRootCaAction: android.widget.Button
    private lateinit var fridaStatusDot: View
    private lateinit var fridaStatusText: TextView
    private lateinit var btnToggleFrida: android.widget.Button

    private var lastRootAvailable = false
    private var lastCaInstalled = false
    private var lastProxyRunning = false
    private var lastRootCaStaged = false
    private var lastRootCaActive = false
    private var lastFridaEnabled = false
    private var fridaEnabling = false

    companion object {
        private const val POLL_MS = 3_000L
    }

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_device_status)
        findViewById<View>(R.id.btn_back).setOnClickListener { finish() }

        rootStatusText = findViewById(R.id.root_status_text)
        automationStatusDot = findViewById(R.id.automation_status_dot)
        automationStatusText = findViewById(R.id.automation_status_text)
        btnOpenAccessibilitySettings = findViewById(R.id.btn_open_accessibility_settings)
        proxyStatusDot = findViewById(R.id.proxy_status_dot)
        proxyStatusText = findViewById(R.id.proxy_status_text)
        btnToggleProxy = findViewById(R.id.btn_toggle_proxy)
        caStatusText = findViewById(R.id.ca_status_text)
        btnToggleCa = findViewById(R.id.btn_toggle_ca)
        capturedCountText = findViewById(R.id.captured_count_text)
        rootCaStatusDot = findViewById(R.id.root_ca_status_dot)
        rootCaStatusText = findViewById(R.id.root_ca_status_text)
        btnRootCaAction = findViewById(R.id.btn_root_ca_action)
        fridaStatusDot = findViewById(R.id.frida_status_dot)
        fridaStatusText = findViewById(R.id.frida_status_text)
        btnToggleFrida = findViewById(R.id.btn_toggle_frida)

        ProxyController.init(applicationContext)
        DeviceContext.init(applicationContext)

        btnToggleCa.setOnClickListener { onToggleCaClicked() }
        btnToggleProxy.setOnClickListener { onToggleProxyClicked() }
        btnRootCaAction.setOnClickListener { onRootCaActionClicked() }
        btnToggleFrida.setOnClickListener { onToggleFridaClicked() }
        btnOpenAccessibilitySettings.setOnClickListener {
            startActivity(Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }

        lifecycleScope.launch {
            val root = withContext(Dispatchers.IO) { RootShellExecutor.checkRoot() }
            lastRootAvailable = root.available
            if (root.available) {
                rootStatusText.text = "Available (${root.via})"
                rootStatusText.setTextColor(ContextCompat.getColor(this@DeviceStatusActivity, R.color.cds_support_success))
            } else {
                rootStatusText.text = "Unavailable — ${root.detail}"
                rootStatusText.setTextColor(ContextCompat.getColor(this@DeviceStatusActivity, R.color.cds_support_warning))
            }
            renderAutomationStatus()
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    renderAutomationStatus()
                    delay(POLL_MS)
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    val status = withContext(Dispatchers.IO) { ProxyController.status() }
                    renderProxyStatus(status)
                    delay(POLL_MS)
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    val enabled = withContext(Dispatchers.IO) { FridaController.isEnabled(applicationContext) }
                    if (!fridaEnabling) renderFridaStatus(enabled)
                    delay(POLL_MS)
                }
            }
        }
    }

    private fun renderFridaStatus(enabled: Boolean) {
        lastFridaEnabled = enabled
        fridaStatusText.text = getString(if (enabled) R.string.frida_enabled else R.string.frida_not_enabled)
        fridaStatusText.setTextColor(
            ContextCompat.getColor(this, if (enabled) R.color.cds_support_success else R.color.cds_text_secondary),
        )
        fridaStatusDot.background.mutate().setTint(
            ContextCompat.getColor(this, if (enabled) R.color.cds_support_success else R.color.cds_support_neutral),
        )
        btnToggleFrida.text = getString(if (enabled) R.string.action_frida_enabled else R.string.action_enable_frida)
        btnToggleFrida.isEnabled = !enabled
    }

    private fun onToggleFridaClicked() {
        if (lastFridaEnabled || fridaEnabling) return
        fridaEnabling = true
        btnToggleFrida.isEnabled = false
        fridaStatusText.text = getString(R.string.frida_downloading)
        lifecycleScope.launch {
            val result = try {
                withContext(Dispatchers.IO) { FridaController.enable() }
            } catch (e: Exception) {
                JSONObject().apply { put("success", false); put("error", e.message ?: "failed") }
            }
            if (!result.optBoolean("success")) {
                Toast.makeText(
                    this@DeviceStatusActivity,
                    "Enable Frida failed: ${result.optString("error").ifBlank { "unknown error" }}",
                    Toast.LENGTH_LONG,
                ).show()
            }
            fridaEnabling = false
            val enabled = withContext(Dispatchers.IO) { FridaController.isEnabled(applicationContext) }
            renderFridaStatus(enabled)
        }
    }

    private fun renderAutomationStatus() {
        val accessibilityOn = StrobesAccessibilityService.isRunning()
        when {
            lastRootAvailable -> {
                automationStatusText.text = getString(R.string.automation_root_available)
                automationStatusText.setTextColor(ContextCompat.getColor(this, R.color.cds_text_secondary))
                automationStatusDot.background.mutate().setTint(ContextCompat.getColor(this, R.color.cds_support_success))
                btnOpenAccessibilitySettings.visibility = View.GONE
            }
            accessibilityOn -> {
                automationStatusText.text = getString(R.string.automation_accessibility_enabled)
                automationStatusText.setTextColor(ContextCompat.getColor(this, R.color.cds_text_primary))
                automationStatusDot.background.mutate().setTint(ContextCompat.getColor(this, R.color.cds_support_success))
                btnOpenAccessibilitySettings.visibility = View.GONE
            }
            else -> {
                automationStatusText.text = getString(R.string.automation_accessibility_disabled)
                automationStatusText.setTextColor(ContextCompat.getColor(this, R.color.cds_text_primary))
                automationStatusDot.background.mutate().setTint(ContextCompat.getColor(this, R.color.cds_support_warning))
                btnOpenAccessibilitySettings.visibility = View.VISIBLE
            }
        }
    }

    private fun renderProxyStatus(status: JSONObject) {
        val rootAvailable = status.optBoolean("root_available", true)

        val running = status.optBoolean("running")
        lastProxyRunning = running
        proxyStatusText.text = when {
            !rootAvailable -> "Requires root (not available on this device)"
            running -> "Running (port ${status.optInt("port")})"
            else -> getString(R.string.proxy_stopped)
        }
        proxyStatusDot.background.mutate().setTint(
            ContextCompat.getColor(
                this,
                if (!rootAvailable) R.color.cds_support_warning else if (running) R.color.cds_support_success else R.color.cds_support_neutral,
            ),
        )
        btnToggleProxy.text = getString(if (running) R.string.action_disable_proxy else R.string.action_enable_proxy)
        btnToggleProxy.isEnabled = rootAvailable

        val caInstalled = status.optBoolean("ca_installed")
        lastCaInstalled = caInstalled
        caStatusText.text = getString(if (caInstalled) R.string.ca_installed else R.string.ca_not_installed)
        caStatusText.setTextColor(
            ContextCompat.getColor(this, if (caInstalled) R.color.cds_support_success else R.color.cds_text_secondary),
        )
        btnToggleCa.text = getString(if (caInstalled) R.string.action_remove_ca else R.string.action_install_ca)
        btnToggleCa.isEnabled = rootAvailable

        val count = status.optInt("captured_count")
        capturedCountText.text = "$count exchange${if (count == 1) "" else "s"}"

        val rootCaStaged = status.optBoolean("root_ca_module_staged")
        val rootCaActive = status.optBoolean("root_ca_active")
        lastRootCaStaged = rootCaStaged
        lastRootCaActive = rootCaActive
        when {
            rootCaActive -> {
                rootCaStatusText.text = getString(R.string.root_ca_active)
                rootCaStatusText.setTextColor(ContextCompat.getColor(this, R.color.cds_support_success))
                rootCaStatusDot.background.mutate().setTint(ContextCompat.getColor(this, R.color.cds_support_success))
                btnRootCaAction.text = getString(R.string.action_remove_root_ca)
            }
            rootCaStaged -> {
                rootCaStatusText.text = getString(R.string.root_ca_staged)
                rootCaStatusText.setTextColor(ContextCompat.getColor(this, R.color.cds_support_warning))
                rootCaStatusDot.background.mutate().setTint(ContextCompat.getColor(this, R.color.cds_support_warning))
                btnRootCaAction.text = getString(R.string.action_reboot_now)
            }
            else -> {
                rootCaStatusText.text = getString(R.string.root_ca_not_installed)
                rootCaStatusText.setTextColor(ContextCompat.getColor(this, R.color.cds_text_secondary))
                rootCaStatusDot.background.mutate().setTint(ContextCompat.getColor(this, R.color.cds_support_neutral))
                btnRootCaAction.text = getString(R.string.action_install_root_ca)
            }
        }
    }

    private fun runProxyAction(actionName: String, action: suspend () -> JSONObject) {
        setActionButtonsEnabled(false)
        lifecycleScope.launch {
            val result = try {
                withContext(Dispatchers.IO) { action() }
            } catch (e: Exception) {
                JSONObject().apply { put("success", false); put("error", e.message ?: "failed") }
            }
            if (!result.optBoolean("success")) {
                val detail = result.optString("error").ifBlank { result.optString("stderr").ifBlank { "unknown error" } }
                Toast.makeText(this@DeviceStatusActivity, "$actionName failed: $detail", Toast.LENGTH_LONG).show()
            }
            val fresh = withContext(Dispatchers.IO) { ProxyController.status() }
            renderProxyStatus(fresh)
            setActionButtonsEnabled(true)
        }
    }

    private fun setActionButtonsEnabled(enabled: Boolean) {
        btnToggleCa.isEnabled = enabled
        btnToggleProxy.isEnabled = enabled
        btnRootCaAction.isEnabled = enabled
    }

    private fun onRootCaActionClicked() {
        when {
            lastRootCaActive -> {
                runProxyActionThen("Remove root CA", { ProxyController.uninstallRootCaModule() }) {
                    showRebootDialog(isInstall = false)
                }
            }
            lastRootCaStaged -> showRebootDialog(isInstall = true)
            else -> {
                runProxyActionThen("Install root CA", { ProxyController.installRootCaModule() }) {
                    showRebootDialog(isInstall = true)
                }
            }
        }
    }

    private fun runProxyActionThen(
        actionName: String,
        action: suspend () -> JSONObject,
        onSuccess: () -> Unit,
    ) {
        setActionButtonsEnabled(false)
        lifecycleScope.launch {
            val result = try {
                withContext(Dispatchers.IO) { action() }
            } catch (e: Exception) {
                JSONObject().apply { put("success", false); put("error", e.message ?: "failed") }
            }
            val fresh = withContext(Dispatchers.IO) { ProxyController.status() }
            renderProxyStatus(fresh)
            setActionButtonsEnabled(true)
            if (result.optBoolean("success")) {
                onSuccess()
            } else {
                val detail = result.optString("error").ifBlank { result.optString("stderr").ifBlank { "unknown error" } }
                Toast.makeText(this@DeviceStatusActivity, "$actionName failed: $detail", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun showRebootDialog(isInstall: Boolean) {
        AlertDialog.Builder(this)
            .setTitle(if (isInstall) R.string.reboot_dialog_title_install else R.string.reboot_dialog_title_remove)
            .setMessage(if (isInstall) R.string.reboot_dialog_message_install else R.string.reboot_dialog_message_remove)
            .setPositiveButton(R.string.action_reboot) { _, _ ->
                Toast.makeText(this, "Rebooting…", Toast.LENGTH_SHORT).show()
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) { ProxyController.rebootForRootCa() }
                }
            }
            .setNegativeButton(R.string.action_later, null)
            .show()
    }

    private fun onToggleCaClicked() {
        if (lastCaInstalled) {
            runProxyAction("Remove CA cert") { ProxyController.uninstallCaOnly() }
        } else {
            runProxyAction("Install CA cert") { ProxyController.installCaOnly() }
        }
    }

    private fun onToggleProxyClicked() {
        if (lastProxyRunning) {
            runProxyAction("Disable proxy") { ProxyController.stop() }
        } else {
            runProxyAction("Enable proxy") { ProxyController.start() }
        }
    }
}
