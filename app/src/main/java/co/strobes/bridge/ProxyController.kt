package co.strobes.bridge

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Process-wide owner of the embedded MITM proxy's lifecycle — deliberately
 * NOT scoped to one BridgeWebSocketClient instance, since the WS control
 * channel reconnects periodically (network blips, server restarts) and an
 * in-progress interception session must survive that, not restart every
 * time. [init] is called once from BridgeForegroundService.onCreate();
 * every command handler below just calls into this singleton.
 */
object ProxyController {

    @Volatile private var appContext: Context? = null

    private val certAuthority: MitmCertAuthority by lazy {
        MitmCertAuthority(requireContext())
    }
    private val server: MitmProxyServer by lazy { MitmProxyServer(certAuthority) }

    fun init(context: Context) {
        if (appContext == null) appContext = context.applicationContext
    }

    private fun requireContext(): Context =
        appContext ?: error("ProxyController.init() was never called")

    suspend fun start(): JSONObject {
        val port = server.start()
        val caResult = ProxyTools.installCaCert(
            requireContext(), certAuthority.caCertPem(), certAuthority.subjectHashOldFileName(),
        )
        val proxyResult = ProxyTools.setSystemProxy(port)
        val caOk = caResult.optBoolean("success")
        val proxyOk = proxyResult.optBoolean("success")
        return JSONObject().apply {
            put("success", caOk && proxyOk)
            put("port", port)
            put("ca_installed", caOk)
            put(
                "ca_scope",
                "user cert store only — trusted by apps whose network security config opts into " +
                    "user certs; a hardened app targeting a modern SDK without that opt-in will " +
                    "reject this CA and its traffic won't appear in history (see ProxyTools doc).",
            )
            put("system_proxy_set", proxyOk)
            if (!caOk) put("ca_install_error", caResult.optString("stderr").ifBlank { "unknown error" })
            if (!proxyOk) put("proxy_set_error", proxyResult.optString("stderr").ifBlank { "unknown error" })
        }
    }

    /** [uninstallCa] = also remove the CA from the user cert store (a clean
     * teardown at the end of an engagement) — left installed by default so a
     * still-open interception session in a capture-review tool doesn't
     * suddenly see cert errors on the next request. */
    suspend fun stop(uninstallCa: Boolean = false): JSONObject {
        server.stop()
        val proxyResult = ProxyTools.clearSystemProxy()
        val caResult = if (uninstallCa) {
            ProxyTools.uninstallCaCert(certAuthority.subjectHashOldFileName())
        } else {
            null
        }
        return JSONObject().apply {
            put("success", true)
            put("system_proxy_cleared", proxyResult.optBoolean("success"))
            if (caResult != null) put("ca_uninstalled", caResult.optBoolean("success"))
        }
    }

    /** Installs the CA without touching the proxy server or system proxy
     * setting — lets a human pre-trust the CA from the app's own UI before
     * deciding to actually start capturing, independent of the combined
     * proxy_start flow used remotely. */
    suspend fun installCaOnly(): JSONObject {
        return ProxyTools.installCaCert(
            requireContext(), certAuthority.caCertPem(), certAuthority.subjectHashOldFileName(),
        )
    }

    suspend fun uninstallCaOnly(): JSONObject {
        return ProxyTools.uninstallCaCert(certAuthority.subjectHashOldFileName())
    }

    /** The install intent for the non-root path (KeyChain's system "Install
     * certificate" dialog) — must be launched from an Activity, so exposed
     * here rather than handled inside this Service-friendly singleton.
     * Kept for reference/other callers, but OnboardingActivity's CA step no
     * longer uses it as the primary flow — see saveCaCertToDownloads's doc
     * comment for why. */
    fun caInstallIntent(): android.content.Intent = ProxyTools.createCaInstallIntent(certAuthority.caCert)

    /** Saves the CA cert to the public Downloads folder — the actual
     * working non-root install path (see ProxyTools.saveCaCertToDownloads). */
    fun saveCaCertToDownloads(context: Context): JSONObject =
        ProxyTools.saveCaCertToDownloads(context, certAuthority.caCertPem(), "strobes-bridge-ca")

    /** Exposes this install's actual CA cert + live proxy port to
     * FridaController, so the injected unpinning bundle trusts the SAME CA
     * this proxy already presents — not a second, unrelated one. */
    fun caCertPemForFrida(): String = certAuthority.caCertPem().trim()
    fun currentProxyPort(): Int = server.port

    /** Reads what the platform actually trusts right now (AndroidCAStore) —
     * true regardless of whether the cert got there via root's direct file
     * write or the KeyChain dialog, so this is the one accurate "is it
     * installed" check callers (status() below, the onboarding wizard)
     * should use instead of the root-only file-existence check. */
    fun isCaTrusted(): Boolean = ProxyTools.isCaTrusted(certAuthority.caCert)

    suspend fun status(): JSONObject {
        return JSONObject().apply {
            put("success", true)
            put("running", server.isRunning())
            put("port", server.port)
            put("captured_count", ProxyHistoryStore.count())
            put("ca_installed", isCaTrusted())
            put("root_ca_module_staged", RootCaModuleInstaller.isModuleStaged())
            put("root_ca_active", RootCaModuleInstaller.isActiveInSystemStore(certAuthority.subjectHashOldFileName()))
            // Traffic interception (CA install + the system-wide proxy setting
            // both need root — see ProxyTools's doc comment) is the one piece
            // of this bridge with no non-root fallback in this pass (would
            // need a VpnService-based local interceptor instead of the system
            // proxy setting). Surfaced explicitly so the UI can say so plainly
            // instead of just showing a perpetually-stuck "not installed".
            put("root_available", RootShellExecutor.checkRoot().available)
        }
    }

    /** Stages the root-manager module (Magisk/KernelSU/APatch) — see RootCaModuleInstaller's doc comment
     * for why this is deliberately separate from the user-cert-store path
     * and never reboots on its own. */
    suspend fun installRootCaModule(): JSONObject {
        return RootCaModuleInstaller.install(
            requireContext(), certAuthority.caCertPem(), certAuthority.subjectHashOldFileName(),
        )
    }

    suspend fun uninstallRootCaModule(): JSONObject = RootCaModuleInstaller.uninstall()

    /** The one call in this whole feature that reboots the device. Callers
     * (both the in-app button and any remote command) must treat this as a
     * distinct, explicitly-confirmed action — never chained automatically
     * after installRootCaModule(). */
    suspend fun rebootForRootCa(): JSONObject = RootCaModuleInstaller.rebootNow()

    fun history(sinceId: Long, limit: Int, hostFilter: String?, includeBodies: Boolean): JSONObject {
        val entries = ProxyHistoryStore.list(sinceId, limit, hostFilter)
        val arr = JSONArray()
        for (e in entries) arr.put(e.toJson(includeBodies))
        return JSONObject().apply {
            put("success", true)
            put("entries", arr)
            put("count", entries.size)
            put("total_captured", ProxyHistoryStore.count())
        }
    }

    fun clearHistory(): JSONObject {
        ProxyHistoryStore.clear()
        return JSONObject().apply { put("success", true) }
    }
}
