package co.strobes.bridge

import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import org.tukaani.xz.XZInputStream
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Runtime certificate-pinning / SSL-pinning bypass, using Frida — the piece
 * <test_device_dynamic_testing> in the mobile_pentest_agent prompt used to
 * document as "no Frida injection capability exists on the bridge". It does
 * now, via `frida-inject` (a standalone on-device binary — no frida-server +
 * remote client split needed, so this reuses the exact same root-shell
 * channel as every other on-device action here, no new WebSocket tunnel).
 *
 * Architecture:
 *  1. Detect the device's real ABI at runtime (`Build.SUPPORTED_ABIS`) and
 *     download the matching `frida-inject` release on first use, cached
 *     under this app's files dir keyed by version+arch. Bundling one
 *     prebuilt arch in the APK would either bloat it with every arch or
 *     silently fail on whatever wasn't bundled — fetching the one that
 *     actually matches this device is both smaller and more correct.
 *  2. The default unpinning payload — every technique from
 *     https://github.com/httptoolkit/frida-interception-and-unpinning
 *     (native BoringSSL hooking, HTTP/3 blocking so apps fall back to a
 *     version our proxy can see, ~20 known Java pinning libraries, root
 *     detection bypass) — ships as a prebuilt APK asset
 *     (frida_unpin_bundle.js, compiled via frida-compile so the modern
 *     Frida 17.x `frida-java-bridge` import actually resolves — Frida
 *     dropped the old auto-global `Java`, so an uncompiled copy of these
 *     scripts throws "Java is not defined" on this Frida version). Custom,
 *     agent-supplied scripts (see [runScript]) can't go through this same
 *     on-device compile step (no Node/esbuild on the device), so they're
 *     limited to Frida's native-level APIs (Interceptor/Module/Memory/
 *     Process/File/console) — no `Java.*` unless the script is small enough
 *     to not need frida-java-bridge at all.
 *  3. This app's actual CA cert + live proxy port (only known at runtime,
 *     generated fresh per install — see MitmCertAuthority) are written to a
 *     plain JSON file on device; the compiled bundle reads it itself at its
 *     own runtime via Frida's `File` API (see [writeConfigFile] for why —
 *     the compiled asset's bytes are never touched).
 *  4. Every injection — the bundle or a custom script — runs as a
 *     *backgrounded, non-eternalized* `frida-inject` process
 *     (`nohup ... > logfile 2>&1 &`), tracked by its own PID in [sessions].
 *     This is deliberate, not a downgrade from the old `-e`/eternalize
 *     design: killing that PID reliably tears the script (and its hooks)
 *     back down — confirmed empirically (a setInterval-based heartbeat
 *     script stopped ticking immediately once its injector PID was killed,
 *     with no further ticks after) — which is what makes [stopScript]
 *     possible at all. Eternalized hooks can't be un-hooked short of
 *     force-stopping the target app. The same backgrounding also solves
 *     log visibility for free: redirecting frida-inject's own stdout to a
 *     file captures every console.log the script ever makes, live, for as
 *     long as the session runs — script-side attempts to write logs to a
 *     file themselves (via Frida's `File` API, from inside the target
 *     app's own process) fail with "Permission denied": the target app's
 *     SELinux domain blocks writes outside its own sandbox even though the
 *     injection itself is root. The injector process runs outside that
 *     sandbox, so redirecting *its* stdout sidesteps the restriction
 *     entirely.
 */
object FridaController {

    private const val FRIDA_VERSION = "17.15.3"
    private const val ASSET_NAME = "frida_unpin_bundle.js"
    private const val CONFIG_FILE_NAME = "strobes_frida_config.json"
    private const val CONFIG_DEVICE_PATH = "/data/local/tmp/$CONFIG_FILE_NAME"
    private const val SELF_PACKAGE = "co.strobes.bridge"

    data class FridaSession(
        val sessionId: String,
        val injectorPid: Int,
        val targetPackage: String,
        val targetPid: Int,
        val scriptLabel: String,
        val logPath: String,
    )

    private val sessions = ConcurrentHashMap<String, FridaSession>()

    private fun fridaArchName(abi: String): String? = when (abi) {
        "arm64-v8a" -> "android-arm64"
        "armeabi-v7a", "armeabi" -> "android-arm"
        "x86_64" -> "android-x86_64"
        "x86" -> "android-x86"
        else -> null
    }

    private fun deviceAbi(): String = Build.SUPPORTED_ABIS.firstOrNull()
        ?: error("Build.SUPPORTED_ABIS was empty")

    // Explicit Proxy.NO_PROXY is load-bearing, not cosmetic: ProxyController
    // .start() sets the system-wide `http_proxy` setting, which applies to
    // THIS app's own process too. Without this override, the frida-inject
    // download gets routed through our own MITM proxy and rejected —
    // correctly — by TLS validation for presenting our self-signed leaf
    // cert for github.com instead of GitHub's real one ("Trust anchor for
    // certification path not found"). Fetching our own tooling should never
    // go through our own interception layer.
    private val downloadClient by lazy {
        OkHttpClient.Builder()
            .proxy(java.net.Proxy.NO_PROXY)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }

    private fun injectorFile(context: android.content.Context): File {
        val arch = fridaArchName(deviceAbi()) ?: "unknown"
        return File(context.filesDir, "frida-inject-$FRIDA_VERSION-$arch")
    }

    /** True once a human has tapped "Enable Frida" in this app and it
     * completed successfully — the one thing [bypassPinning]/[runScript]
     * themselves check before doing anything, since staging (downloading a
     * 50MB+ binary onto the device) is deliberately NOT something a remote
     * agent command can trigger on its own. */
    suspend fun isEnabled(context: android.content.Context): Boolean = withContext(Dispatchers.IO) {
        val arch = fridaArchName(deviceAbi()) ?: return@withContext false
        if (!injectorFile(context).exists()) return@withContext false
        val destPath = "/data/local/tmp/frida-inject-$FRIDA_VERSION-$arch"
        val check = RootShellExecutor.executeShellCommand("test -x '$destPath' && echo OK", 5)
        check.optString("stdout").trim() == "OK"
    }

    suspend fun status(): JSONObject = withContext(Dispatchers.IO) {
        val ctx = DeviceContext.require()
        val abi = deviceAbi()
        val arch = fridaArchName(abi)
        JSONObject().apply {
            put("success", true)
            put("device_abi", abi)
            put("frida_arch_supported", arch != null)
            put("frida_version", FRIDA_VERSION)
            put("enabled", isEnabled(ctx))
            put("root_available", RootShellExecutor.checkRoot().available)
            put("active_sessions", sessions.size)
        }
    }

    /**
     * The ONE entrypoint meant to be called from this app's own UI (see
     * DeviceStatusActivity) — never from a remote WebSocket command. Does
     * the one-time-per-device work: download frida-inject for this device's
     * real ABI, stage it at an executable path. Idempotent — safe to call
     * again if it previously failed partway (e.g. no network).
     */
    suspend fun enable(): JSONObject = withContext(Dispatchers.IO) {
        val root = RootShellExecutor.checkRoot()
        if (!root.available) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Frida needs root (${root.detail}) — no non-root equivalent exists for this.")
            }
        }
        val ctx = DeviceContext.require()
        try {
            stageInjectorForExec(ctx)
            JSONObject().apply { put("success", true) }
        } catch (e: Exception) {
            JSONObject().apply { put("success", false); put("error", e.message ?: "enable failed") }
        }
    }

    /**
     * Ensures `frida-inject` for this device's real ABI is present in this
     * app's private files dir, downloading it from Frida's GitHub releases
     * on first use only. Returns the local file, or throws with a clear
     * message if this ABI has no Frida build (32-bit x86 has historically
     * been dropped from some releases) or the download fails.
     */
    private suspend fun ensureInjector(context: android.content.Context): File = withContext(Dispatchers.IO) {
        val abi = deviceAbi()
        val arch = fridaArchName(abi)
            ?: error("No frida-inject build exists for this device's ABI ($abi)")
        val dest = injectorFile(context)
        if (dest.exists() && dest.length() > 0) return@withContext dest

        val url = "https://github.com/frida/frida/releases/download/" +
            "$FRIDA_VERSION/frida-inject-$FRIDA_VERSION-$arch.xz"
        val tmp = File(context.filesDir, "${dest.name}.downloading")
        val request = Request.Builder().url(url).build()
        downloadClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                error("Downloading frida-inject failed: HTTP ${response.code} for $url")
            }
            val body = response.body ?: error("Empty response body downloading frida-inject")
            XZInputStream(body.byteStream()).use { xz ->
                tmp.outputStream().use { out -> xz.copyTo(out) }
            }
        }
        if (!tmp.renameTo(dest)) error("Could not finalize downloaded frida-inject")
        dest
    }

    /** Pushes the (already-downloaded) injector to a world-executable path —
     * app-private files dir is fine for root to read, but root's own shell
     * exec needs the file to actually be marked executable, and some
     * devices' app-data mount is `noexec`; /data/local/tmp matches every
     * other root-shell convention already used elsewhere in this app. */
    private suspend fun stageInjectorForExec(context: android.content.Context): String {
        val src = ensureInjector(context)
        val destPath = "/data/local/tmp/${src.name}"
        val check = RootShellExecutor.executeShellCommand("test -x '$destPath' && echo OK", 5)
        if (check.optString("stdout").trim() == "OK") return destPath

        val copyResult = RootShellExecutor.executeShellCommand(
            "cp '${src.absolutePath}' '$destPath' && chmod 755 '$destPath'", 15,
        )
        if (!copyResult.optBoolean("success")) {
            error("Could not stage frida-inject on device: ${copyResult.optString("stderr")}")
        }
        return destPath
    }

    /**
     * The bundled asset (frida_unpin_bundle.js) is NEVER modified at
     * runtime — it stays byte-identical to what frida-compile produced.
     * frida-compile's output isn't plain JS on its own: it's Frida's own
     * length-prefixed bundle format (`📦\n<byte-count> /entry.js\n<that many
     * bytes of content>`, used so stack traces resolve back to the right
     * source file). Two earlier approaches to getting this install's own
     * CA cert/port into that asset both broke it: text-substituting a
     * placeholder INSIDE the compiled asset changed its byte length without
     * updating the declared count ("Unexpected end of input" / "Malformed
     * package"); loading the values via a second `-s` script that set
     * `globalThis.__STROBES_CONFIG__` before the bundle's script ran turned
     * out not to work either — `frida-inject` gives each `-s` script its own
     * isolated realm, not a shared one, so the setter's assignment (and even
     * its own console.log) never became visible to the next script at all.
     *
     * The actual fix: write the config as a plain JSON *file* on disk, and
     * have config.js (baked into the compiled asset) read it at its own
     * runtime via Frida's built-in `File` API
     * (`new File(path, "r").readText()`) — this crosses no script/realm
     * boundary and needs no bundle byte ever touched.
     */
    private fun writeConfigFile(context: android.content.Context): File {
        val config = JSONObject().apply {
            put("certPem", ProxyController.caCertPemForFrida())
            put("proxyPort", ProxyController.currentProxyPort())
            put("debugMode", true)
        }
        val file = File(context.filesDir, CONFIG_FILE_NAME)
        file.writeText(config.toString())
        return file
    }

    /** Copies the static, byte-identical-to-shipped bundle asset to
     * /data/local/tmp once; a size match on subsequent calls skips the
     * re-copy. Never rewritten with runtime values — see the doc comment
     * on [writeConfigFile] for why that used to be fragile. */
    private suspend fun stageBundleAsset(context: android.content.Context): String {
        val devicePath = "/data/local/tmp/$ASSET_NAME"
        val assetBytes = context.assets.open(ASSET_NAME).use { it.readBytes() }
        val sizeCheck = RootShellExecutor.executeShellCommand(
            "wc -c < '$devicePath' 2>/dev/null || echo 0", 5,
        )
        if (sizeCheck.optString("stdout").trim().toLongOrNull() == assetBytes.size.toLong()) {
            return devicePath
        }
        val local = File(context.filesDir, ASSET_NAME)
        local.writeBytes(assetBytes)
        val copyResult = RootShellExecutor.executeShellCommand(
            "cp '${local.absolutePath}' '$devicePath'", 15,
        )
        if (!copyResult.optBoolean("success")) {
            error("Could not stage $ASSET_NAME on device: ${copyResult.optString("stderr")}")
        }
        return devicePath
    }

    private fun sanitizeForFilename(s: String): String = s.replace(Regex("[^A-Za-z0-9_.]"), "_")

    private suspend fun resolvePid(packageName: String): Int? {
        val pidResult = RootShellExecutor.executeShellCommand("pidof '$packageName'", 10)
        return pidResult.optString("stdout").trim().split(Regex("\\s+")).firstOrNull()?.toIntOrNull()
    }

    /** Every currently running app's *main* process (package name without a
     * `:remote`/`:background`-style suffix), excluding this app itself —
     * the enumeration behind package_name "all". `ps -A` alone isn't
     * enough to tell an app from a native process: plenty of system HAL
     * daemons (e.g. `android.hardware.thermal@2.0-service.mock`) also have
     * dots in their names, and injecting Frida into one of those risks
     * crashing a core system service instead of an app. Cross-referencing
     * against `pm list packages` (actual installed Android application
     * package names only — no native daemon ever appears there) filters
     * those out; `ps -A` is still what tells us which of them are actually
     * running right now (Frida attaches to a live process; a
     * merely-installed-but-not-running package has nothing to inject into). */
    private suspend fun listRunningAppPids(): List<Pair<String, Int>> {
        val packagesResult = RootShellExecutor.executeShellCommand("pm list packages", 10)
        if (!packagesResult.optBoolean("success")) return emptyList()
        val installedPackages = packagesResult.optString("stdout").lineSequence()
            .mapNotNull { it.trim().removePrefix("package:").ifBlank { null } }
            .toHashSet()

        val psResult = RootShellExecutor.executeShellCommand("ps -A -o PID,NAME", 10)
        if (!psResult.optBoolean("success")) return emptyList()
        return psResult.optString("stdout").lineSequence()
            .drop(1)
            .mapNotNull { line ->
                val parts = line.trim().split(Regex("\\s+"), limit = 2)
                if (parts.size != 2) return@mapNotNull null
                val pid = parts[0].toIntOrNull() ?: return@mapNotNull null
                val name = parts[1]
                if (name.contains(':')) return@mapNotNull null
                if (name == SELF_PACKAGE || name !in installedPackages) return@mapNotNull null
                name to pid
            }
            .distinctBy { it.first }
            .toList()
    }

    private suspend fun isPidAlive(pid: Int): Boolean {
        val r = RootShellExecutor.executeShellCommand("kill -0 $pid 2>/dev/null && echo ALIVE || echo DEAD", 5)
        return r.optString("stdout").trim() == "ALIVE"
    }

    /**
     * The shared low-level "attach frida-inject to one already-running
     * process, load one script, keep it running in the background" step
     * used by both [bypassPinning] and [runScript]. Non-eternalized and
     * backgrounded (see the class doc comment for why): returns almost
     * immediately with a session_id the caller can later pass to
     * [readLogs] or [stopScript], after a short grace period to catch
     * scripts that fail immediately (bad syntax, "Process not found", a
     * thrown error before the first `console.log`) and report that as a
     * failure instead of a phantom "success".
     */
    private suspend fun startSession(
        targetPackage: String,
        targetPid: Int,
        scriptDevicePath: String,
        scriptLabel: String,
    ): JSONObject {
        val injectorPath = "/data/local/tmp/frida-inject-$FRIDA_VERSION-${fridaArchName(deviceAbi())}"
        val logPath = "/data/local/tmp/frida_log_${sanitizeForFilename(targetPackage)}_$targetPid.log"

        val startCmd = "rm -f '$logPath'; nohup '$injectorPath' -p $targetPid -s '$scriptDevicePath' " +
            "-R qjs > '$logPath' 2>&1 < /dev/null & echo \$!"
        val startResult = RootShellExecutor.executeShellCommand(startCmd, 10)
        val injectorPid = startResult.optString("stdout").trim().toIntOrNull()
        if (injectorPid == null) {
            return JSONObject().apply {
                put("success", false)
                put("target_package", targetPackage)
                put("error", "Could not start frida-inject: ${startResult.optString("stderr")}")
            }
        }

        delay(1500)
        val alive = isPidAlive(injectorPid)
        val log = RootShellExecutor.executeShellCommand("cat '$logPath' 2>/dev/null", 5).optString("stdout")

        return if (alive) {
            val sessionId = "frida_${sanitizeForFilename(targetPackage)}_$injectorPid"
            sessions[sessionId] = FridaSession(sessionId, injectorPid, targetPackage, targetPid, scriptLabel, logPath)
            JSONObject().apply {
                put("success", true)
                put("session_id", sessionId)
                put("target_package", targetPackage)
                put("target_pid", targetPid)
                put("log", log)
                put(
                    "note",
                    "Running in the background (not eternalized) — call frida_stop_script with this " +
                        "session_id to stop it, or frida_read_logs to see ongoing output.",
                )
            }
        } else {
            JSONObject().apply {
                put("success", false)
                put("target_package", targetPackage)
                put("target_pid", targetPid)
                put("log", log)
                put("error", "frida-inject exited immediately — see 'log' for the script's own error output.")
            }
        }
    }

    /**
     * Injects the full httptoolkit unpinning bundle into [packageName],
     * which must already be running (this attaches by PID resolved from
     * the package name — it does not spawn the app itself; launch it first
     * via a normal am start/monkey command, then call this). Pass `null`,
     * blank, or `"all"` to target every currently-running app on the device
     * *except the Strobes Bridge app itself* — useful for a blanket sweep
     * instead of naming one app at a time.
     */
    suspend fun bypassPinning(packageName: String?, timeoutSeconds: Int = 60): JSONObject = withContext(Dispatchers.IO) {
        val root = RootShellExecutor.checkRoot()
        if (!root.available) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Frida injection needs root (${root.detail}) — no non-root equivalent exists for this.")
            }
        }

        val ctx = DeviceContext.require()
        if (!isEnabled(ctx)) {
            return@withContext JSONObject().apply {
                put("success", false)
                put(
                    "error",
                    "Frida hasn't been enabled on this device yet. Ask the person at the device to " +
                        "open the Strobes Bridge app, go to Device status, and tap \"Enable Frida\" — " +
                        "this is a deliberate one-time human step, not something this command can do " +
                        "on its own.",
                )
            }
        }

        val targets: List<Pair<String, Int>> = if (packageName.isNullOrBlank() || packageName == "all") {
            listRunningAppPids()
        } else {
            val pid = resolvePid(packageName)
            if (pid == null) {
                return@withContext JSONObject().apply {
                    put("success", false)
                    put("error", "$packageName doesn't appear to be running (pidof found nothing) — launch it first, then retry.")
                }
            }
            listOf(packageName to pid)
        }
        if (targets.isEmpty()) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "No eligible running apps found to target (excluding $SELF_PACKAGE).")
            }
        }

        val configFile = writeConfigFile(ctx)
        val pushConfig = RootShellExecutor.executeShellCommand(
            "cp '${configFile.absolutePath}' '$CONFIG_DEVICE_PATH'", 10,
        )
        if (!pushConfig.optBoolean("success")) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Could not stage the Frida config file on device: ${pushConfig.optString("stderr")}")
            }
        }

        val bundleDevicePath = try {
            stageBundleAsset(ctx)
        } catch (e: Exception) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Could not stage the unpinning bundle on device: ${e.message}")
            }
        }

        // config.js (inside the compiled bundle) reads CONFIG_DEVICE_PATH
        // itself via Frida's File API at its own runtime — no second `-s`
        // script, no shared-realm assumption needed.
        val results = coroutineScope {
            targets.map { (pkg, pid) ->
                async { startSession(pkg, pid, bundleDevicePath, "bypass_pinning") }
            }.map { it.await() }
        }

        JSONObject().apply {
            put("success", results.any { it.optBoolean("success") })
            put("target_count", targets.size)
            put("results", JSONArray(results))
        }
    }

    /**
     * Runs an arbitrary, agent-supplied Frida script against [packageName]
     * (must already be running). Unlike [bypassPinning], this is NOT
     * frida-compiled first (no build toolchain on-device) — the script must
     * be plain JS using Frida's native APIs directly (Interceptor, Module,
     * Memory, Process, File, console); it will fail with "Java is not
     * defined" if it tries to use `Java.*` without importing
     * frida-java-bridge itself, which a raw on-device script has no way to
     * do. Same enable-gate as [bypassPinning] — a human must have enabled
     * Frida in this app's own UI first.
     */
    suspend fun runScript(packageName: String, scriptSource: String, scriptLabel: String = "custom"): JSONObject =
        withContext(Dispatchers.IO) {
            val root = RootShellExecutor.checkRoot()
            if (!root.available) {
                return@withContext JSONObject().apply {
                    put("success", false)
                    put("error", "Frida injection needs root (${root.detail}) — no non-root equivalent exists for this.")
                }
            }
            val ctx = DeviceContext.require()
            if (!isEnabled(ctx)) {
                return@withContext JSONObject().apply {
                    put("success", false)
                    put(
                        "error",
                        "Frida hasn't been enabled on this device yet. Ask the person at the device to " +
                            "open the Strobes Bridge app, go to Device status, and tap \"Enable Frida\".",
                    )
                }
            }
            val pid = resolvePid(packageName)
            if (pid == null) {
                return@withContext JSONObject().apply {
                    put("success", false)
                    put("error", "$packageName doesn't appear to be running (pidof found nothing) — launch it first, then retry.")
                }
            }

            val local = File(ctx.filesDir, "frida_custom_${sanitizeForFilename(packageName)}_$pid.js")
            local.writeText(scriptSource)
            val devicePath = "/data/local/tmp/${local.name}"
            val push = RootShellExecutor.executeShellCommand("cp '${local.absolutePath}' '$devicePath'", 10)
            if (!push.optBoolean("success")) {
                return@withContext JSONObject().apply {
                    put("success", false)
                    put("error", "Could not stage the custom script on device: ${push.optString("stderr")}")
                }
            }

            startSession(packageName, pid, devicePath, scriptLabel)
        }

    /** Reads the log file for an active or already-stopped session — the
     * log file itself isn't deleted by [stopScript], only the in-memory
     * session entry, so logs remain readable after stopping. */
    suspend fun readLogs(sessionId: String, tailLines: Int = 200): JSONObject = withContext(Dispatchers.IO) {
        val session = sessions[sessionId]
        if (session == null) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Unknown session_id '$sessionId' — call frida_list_sessions to see active ones.")
            }
        }
        val result = RootShellExecutor.executeShellCommand("tail -n $tailLines '${session.logPath}' 2>&1", 10)
        JSONObject().apply {
            put("success", true)
            put("session_id", sessionId)
            put("target_package", session.targetPackage)
            put("running", isPidAlive(session.injectorPid))
            put("log", result.optString("stdout"))
        }
    }

    /** Kills the tracked frida-inject PID for this session — confirmed
     * (empirically, not just assumed) to actually tear the script and its
     * hooks back down, not just stop log output; see the class doc
     * comment. Falls back to SIGKILL if SIGTERM doesn't land within 2s. */
    suspend fun stopScript(sessionId: String): JSONObject = withContext(Dispatchers.IO) {
        val session = sessions[sessionId]
        if (session == null) {
            return@withContext JSONObject().apply {
                put("success", false)
                put("error", "Unknown session_id '$sessionId' — call frida_list_sessions to see active ones.")
            }
        }
        RootShellExecutor.executeShellCommand("kill -15 ${session.injectorPid} 2>/dev/null", 5)
        delay(2000)
        if (isPidAlive(session.injectorPid)) {
            RootShellExecutor.executeShellCommand("kill -9 ${session.injectorPid} 2>/dev/null", 5)
            delay(500)
        }
        val stillAlive = isPidAlive(session.injectorPid)
        sessions.remove(sessionId)
        JSONObject().apply {
            put("success", !stillAlive)
            put("session_id", sessionId)
            put("target_package", session.targetPackage)
            if (stillAlive) put("error", "Injector process didn't exit even after SIGKILL.")
        }
    }

    /** Lists every session this controller believes is still running,
     * pruning any whose injector process has since died on its own (e.g.
     * the target app was force-stopped, killing frida-inject's attach
     * target out from under it). */
    suspend fun listSessions(): JSONObject = withContext(Dispatchers.IO) {
        val alive = JSONArray()
        val dead = mutableListOf<String>()
        for ((id, session) in sessions) {
            if (isPidAlive(session.injectorPid)) {
                alive.put(
                    JSONObject().apply {
                        put("session_id", id)
                        put("target_package", session.targetPackage)
                        put("target_pid", session.targetPid)
                        put("script", session.scriptLabel)
                    },
                )
            } else {
                dead.add(id)
            }
        }
        dead.forEach { sessions.remove(it) }
        JSONObject().apply {
            put("success", true)
            put("sessions", alive)
        }
    }
}
