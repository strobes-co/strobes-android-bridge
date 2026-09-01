package co.strobes.bridge

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.CheckBox
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Guided setup wizard: test-device warning ack, root check, non-root
 * permission grants, Accessibility automation, CA trust, a capability
 * summary, then done. Each capability step reads/writes the exact same
 * controllers the main screen and remote agent commands use (ProxyController,
 * StrobesAccessibilityService) — this is a guided front door to the same
 * state, not a separate parallel setup path.
 */
class OnboardingActivity : AppCompatActivity() {

    private val steps = listOf(
        R.id.step_warning, R.id.step_root, R.id.step_permissions,
        R.id.step_accessibility, R.id.step_ca, R.id.step_capability, R.id.step_done,
    )
    private var current = 0
    private var rootAvailable = false

    private lateinit var progress: TextView
    private lateinit var warningCheckbox: CheckBox
    private lateinit var rootBody: TextView
    private lateinit var permissionsStatus: TextView
    private lateinit var accessibilityStatus: TextView
    private lateinit var caBody: TextView
    private lateinit var caStatus: TextView
    private lateinit var btnCaAction: android.widget.Button
    private lateinit var caManualGroup: View
    private lateinit var btnDownloadCert: android.widget.Button
    private lateinit var caDownloadStatus: TextView
    private lateinit var btnInstallDownloadedCert: android.widget.Button
    private lateinit var btnOpenSecuritySettings: android.widget.Button
    private var downloadedCertUri: android.net.Uri? = null
    private lateinit var btnBack: android.widget.Button
    private lateinit var btnNext: android.widget.Button

    private val nonRootPermissions = arrayOf(
        Manifest.permission.READ_SMS,
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.READ_MEDIA_IMAGES,
        Manifest.permission.READ_MEDIA_VIDEO,
        Manifest.permission.READ_MEDIA_AUDIO,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
    )

    private val requestPermissions = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { renderPermissionsStatus() }

    // A plain startActivity() leaves CertInstaller's getCallingPackage()
    // null, so its "This certificate from ___ must be installed" dialog
    // shows "from null" instead of this app's name — routing through
    // startActivityForResult (what this launcher does under the hood) is
    // what gives the OS a real caller record to attribute.
    private val installCertLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { renderCaStatus() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_onboarding)

        progress = findViewById(R.id.wizard_progress)
        warningCheckbox = findViewById(R.id.warning_checkbox)
        rootBody = findViewById(R.id.root_body)
        permissionsStatus = findViewById(R.id.permissions_status)
        accessibilityStatus = findViewById(R.id.accessibility_status)
        caBody = findViewById(R.id.ca_body)
        caStatus = findViewById(R.id.ca_status)
        btnCaAction = findViewById(R.id.btn_ca_action)
        caManualGroup = findViewById(R.id.ca_manual_group)
        btnDownloadCert = findViewById(R.id.btn_download_cert)
        caDownloadStatus = findViewById(R.id.ca_download_status)
        btnInstallDownloadedCert = findViewById(R.id.btn_install_downloaded_cert)
        btnOpenSecuritySettings = findViewById(R.id.btn_open_security_settings)
        btnBack = findViewById(R.id.btn_wizard_back)
        btnNext = findViewById(R.id.btn_wizard_next)

        ProxyController.init(applicationContext)
        DeviceContext.init(applicationContext)

        warningCheckbox.setOnCheckedChangeListener { _, _ -> renderNav() }
        findViewById<View>(R.id.btn_grant_permissions).setOnClickListener {
            requestPermissions.launch(nonRootPermissions)
        }
        findViewById<View>(R.id.btn_open_accessibility).setOnClickListener {
            startActivity(Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
        findViewById<View>(R.id.btn_view_capability_table).setOnClickListener {
            startActivity(Intent(this, CapabilityTableActivity::class.java))
        }
        btnCaAction.setOnClickListener { onCaActionClicked() }
        btnDownloadCert.setOnClickListener { onDownloadCertClicked() }
        btnInstallDownloadedCert.setOnClickListener { onInstallDownloadedCertClicked() }
        btnOpenSecuritySettings.setOnClickListener { openSecuritySettings() }
        btnBack.setOnClickListener { if (current > 0) { current--; renderStep() } else finish() }
        btnNext.setOnClickListener {
            if (current < steps.size - 1) { current++; renderStep() } else finish()
        }

        lifecycleScope.launch {
            val root = withContext(Dispatchers.IO) { RootShellExecutor.checkRoot() }
            rootAvailable = root.available
            rootBody.text = if (root.available) {
                getString(R.string.onboarding_step_root_body_available)
            } else {
                getString(R.string.onboarding_step_root_body_unavailable)
            }
            caBody.text = if (rootAvailable) {
                getString(R.string.onboarding_step_ca_body_root)
            } else {
                getString(R.string.onboarding_step_ca_body_nonroot)
            }
            renderCaStatus()
        }

        renderStep()
    }

    override fun onResume() {
        super.onResume()
        renderPermissionsStatus()
        renderAccessibilityStatus()
        renderCaStatus()
    }

    private fun renderStep() {
        steps.forEachIndexed { i, id -> findViewById<View>(id).visibility = if (i == current) View.VISIBLE else View.GONE }
        progress.text = "Step ${current + 1} of ${steps.size}"
        renderNav()
        when (steps[current]) {
            R.id.step_permissions -> renderPermissionsStatus()
            R.id.step_accessibility -> renderAccessibilityStatus()
            R.id.step_ca -> renderCaStatus()
        }
    }

    private fun renderNav() {
        btnBack.text = getString(R.string.action_back)
        btnNext.text = if (current == steps.size - 1) getString(R.string.action_finish) else getString(R.string.action_next)
        // The warning step is a hard gate — nothing past it proceeds until
        // the device-provisioning acknowledgment is explicit, not implied by
        // just tapping through.
        btnNext.isEnabled = steps[current] != R.id.step_warning || warningCheckbox.isChecked
    }

    private fun renderPermissionsStatus() {
        val granted = nonRootPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) == android.content.pm.PackageManager.PERMISSION_GRANTED
        }
        permissionsStatus.text = "${granted.size} of ${nonRootPermissions.size} granted"
    }

    private fun renderAccessibilityStatus() {
        accessibilityStatus.text = if (StrobesAccessibilityService.isRunning()) {
            getString(R.string.automation_accessibility_enabled)
        } else {
            getString(R.string.automation_accessibility_disabled)
        }
    }

    private fun renderCaStatus() {
        val trusted = ProxyController.isCaTrusted()
        caStatus.text = if (trusted) getString(R.string.cert_trusted) else getString(R.string.cert_not_trusted)
        caStatus.setTextColor(
            ContextCompat.getColor(this, if (trusted) R.color.cds_support_success else R.color.cds_text_helper),
        )
        // Root gets the one-tap button; non-root gets the download +
        // manual-Settings-install flow — Android doesn't let a third-party
        // app finish a CA install itself (see ProxyTools.saveCaCertToDownloads).
        btnCaAction.visibility = if (rootAvailable) View.VISIBLE else View.GONE
        caManualGroup.visibility = if (rootAvailable) View.GONE else View.VISIBLE
        btnCaAction.text = getString(R.string.action_install_ca)
        btnCaAction.isEnabled = !trusted
    }

    private fun onCaActionClicked() {
        btnCaAction.isEnabled = false
        lifecycleScope.launch {
            withContext(Dispatchers.IO) { ProxyController.installCaOnly() }
            renderCaStatus()
        }
    }

    private fun onDownloadCertClicked() {
        btnDownloadCert.isEnabled = false
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { ProxyController.saveCaCertToDownloads(applicationContext) }
            if (result.optBoolean("success")) {
                caDownloadStatus.text = "Saved to Downloads/${result.optString("file_name")}"
                downloadedCertUri = android.net.Uri.parse(result.optString("uri"))
                btnInstallDownloadedCert.visibility = View.VISIBLE
                // Jump straight into the install flow — the whole point of
                // downloading is to install it, no reason to make the user
                // tap twice.
                onInstallDownloadedCertClicked()
            } else {
                caDownloadStatus.text = "Couldn't save the certificate: ${result.optString("error")}"
            }
            btnDownloadCert.isEnabled = true
        }
    }

    /** Opening the saved cert with its real MIME type is what actually
     * triggers Android's system certificate installer — this is the
     * "prompt to install" step, not just a file sitting in Downloads. */
    private fun onInstallDownloadedCertClicked() {
        val uri = downloadedCertUri ?: return
        try {
            installCertLauncher.launch(
                Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, "application/x-x509-ca-cert")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                },
            )
        } catch (e: Exception) {
            android.widget.Toast.makeText(
                this, "No app handled the certificate file — use Open Settings below instead.", android.widget.Toast.LENGTH_LONG,
            ).show()
        }
    }

    /** No single intent reliably jumps straight to "Install a certificate"
     * across OEM Settings apps — ACTION_SECURITY_SETTINGS is the most
     * broadly supported entry point close to it; the manual steps text
     * covers the rest of the tap path from there. */
    private fun openSecuritySettings() {
        try {
            startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
        } catch (e: Exception) {
            startActivity(Intent(android.provider.Settings.ACTION_SETTINGS))
        }
    }
}
