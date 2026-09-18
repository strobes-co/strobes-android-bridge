package co.strobes.bridge

import android.os.Build
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Speaks the exact protocol strobes/agents/shell_bridge_consumer.py expects,
 * mirroring strobes_shell_agent/client.py (the desktop daemon) message for
 * message — see that file for the canonical reference. The platform side
 * doesn't know or care which daemon it's talking to; this is what makes the
 * Android app a drop-in bridge alongside the desktop one, reusing the same
 * Shell model / REST endpoints / fetch tools.
 *
 * Commands implemented: shell_execute, shell_execute_code (bash/sh only),
 * env_info, file_read/file_write/file_list/file_upload/file_download. That
 * last group is what lets an agent install an APK — file_upload the bytes,
 * then shell_execute("pm install ...") (or install-create/install-write/
 * install-commit per split, for a split APK) — and pull back binary UI-
 * automation artifacts (screencap PNGs, uiautomator dump XML) without the
 * UTF-8 mangling shell_execute's stdout capture would cause.
 *
 * proxy_start/proxy_stop/proxy_status/proxy_history/proxy_clear_history
 * control the embedded MITM proxy (see ProxyController/MitmProxyServer) —
 * device-wide HTTP(S) traffic interception via root, with captured
 * request/response history readable back over this same channel instead of
 * requiring an external mitmproxy/Burp instance. proxy_install_root_ca /
 * proxy_uninstall_root_ca stage (only stage — see the dispatch case for why)
 * a root-manager module (Magisk/KernelSU/APatch) that, after a reboot, trusts the proxy's CA in the actual
 * system store rather than just the user-cert-store proxy_start installs
 * into.
 *
 * Reliability/safety behavior layered on top of the raw protocol:
 *  - Liveness watchdog: an app-level ping every 30s AND a read-side timeout
 *    that force-closes a half-open socket (TCP alive, peer gone) so the
 *    service's reconnect loop takes over instead of the device looking
 *    connected forever.
 *  - Shell-backed commands are serialized behind a mutex so overlapping
 *    commands don't interleave on the shared libsu shell.
 *  - Every command runs under a dispatch deadline and always emits a
 *    response (even a timeout/oversize error), so a wedged handler or an
 *    over-cap payload can never silently strand the agent's request.
 *  - Replay dedup: a command re-issued after a mid-command disconnect
 *    returns its cached result instead of re-running a non-idempotent action.
 *  - A "cancel" message aborts an in-flight command by request_id.
 *  - identify/env_info advertise protocol_version + the supported command
 *    set so the platform can plan instead of probing.
 *
 * Differences from the desktop client, deliberately:
 *  - No PTY support (pty_open is answered with a graceful "not supported"
 *    error instead of hanging the platform's request).
 *  - No background-job (shell_bg_*) commands in this first cut. Long UI
 *    automation flows should be driven as a sequence of ordinary
 *    shell_execute calls instead; a stuck one can be aborted with "cancel".
 *  - Destructive device-lifecycle commands (reboot, factory wipe,
 *    uninstalling the bridge, nuking a filesystem root) are refused over the
 *    remote channel — see ShellCommandRouter.classifyDestructive.
 */
class BridgeWebSocketClient(
    private val serverUrl: String,
    private val orgId: String,
    private val apiKey: String,
    private val bridgeId: String,
    private val shellName: String,
    private val scope: CoroutineScope,
    private val listener: Listener,
) {
    interface Listener {
        fun onStatusChanged(connected: Boolean, detail: String)
    }

    companion object {
        private const val TAG = "StrobesBridgeWS"
        private const val PING_INTERVAL_MS = 30_000L

        // If we haven't heard ANY frame back (pong or otherwise) within this
        // window, the socket is presumed half-open (TCP alive, peer gone —
        // common on cellular/NAT) and we tear it down so the service's
        // reconnect loop kicks in. Two missed pings' worth of grace.
        private const val PONG_TIMEOUT_MS = PING_INTERVAL_MS * 2 + 5_000L

        // The platform WS frame cap is 10MB; keep responses safely under it.
        // A response that would exceed this is replaced with a structured
        // "too large" error rather than being silently dropped by okhttp
        // (WebSocket.send() just returns false and discards an oversized
        // frame, which would hang the agent forever waiting on a reply).
        private const val MAX_RESPONSE_BYTES = 9_000_000

        // Advertised so the platform can plan instead of probing with
        // commands and reading back "Unknown command". Bump on any
        // wire-visible protocol change.
        private const val PROTOCOL_VERSION = 2

        val SUPPORTED_COMMANDS: List<String> = listOf(
            "shell_execute", "shell_execute_code", "env_info",
            "file_read", "file_write", "file_list", "file_upload", "file_download",
            "file_upload_chunk", "file_download_chunk",
            "list_packages", "network_info", "logcat",
            "device_identifiers", "read_sms",
            "proxy_start", "proxy_stop", "proxy_status", "proxy_history", "proxy_clear_history",
            "proxy_install_root_ca", "proxy_uninstall_root_ca",
            "frida_status", "frida_bypass_pinning", "frida_run_script",
            "frida_read_logs", "frida_stop_script", "frida_list_sessions",
        )

        // Commands that run through the shared libsu persistent root shell
        // (Shell.getShell()). Two of these overlapping would interleave on
        // one shell — mixed stdout, wrong exit codes — so they're serialized
        // behind shellMutex. Read-only/self-synchronized commands (proxy_*,
        // frida_*, env_info) run concurrently and stay responsive even while
        // a long shell_execute is in flight.
        private val SHELL_BACKED_COMMANDS = setOf(
            "shell_execute", "shell_execute_code",
            "file_read", "file_write", "file_list", "file_upload", "file_download",
            "file_upload_chunk", "file_download_chunk",
            "list_packages", "network_info", "logcat",
            "device_identifiers", "read_sms",
        )

        // Absolute ceiling on how long any single command may run before the
        // dispatcher gives up and returns a timeout response, so a wedged
        // handler (a Frida attach that never returns, a hung su) can't
        // silently strand the agent's request. Sized well above the largest
        // per-command timeout param an agent realistically sends.
        private const val MAX_COMMAND_MS = 10 * 60_000L
        private const val COMMAND_SLACK_MS = 15_000L

        // Process-global so it survives reconnects (each reconnect builds a
        // fresh BridgeWebSocketClient). Lets a command replayed by the
        // platform after a mid-command disconnect return the cached result
        // instead of re-executing a non-idempotent action (pm install, a
        // tap). Bounded LRU.
        private const val DEDUP_CAPACITY = 64
        private val recentResponses: MutableMap<String, JSONObject> =
            object : LinkedHashMap<String, JSONObject>(DEDUP_CAPACITY, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, JSONObject>) =
                    size > DEDUP_CAPACITY
            }
        private val dedupLock = Any()
    }

    private var ws: WebSocket? = null
    private var pingJob: Job? = null

    @Volatile
    private var lastInboundAtMs: Long = 0L

    // Serializes shell-backed commands (see SHELL_BACKED_COMMANDS).
    private val shellMutex = Mutex()

    // request_id -> Job for commands currently executing on THIS connection,
    // so a "cancel" message can abort one in flight.
    private val inFlight = ConcurrentHashMap<String, Job>()

    // request_ids already answered on THIS connection — makes sendResponse
    // exactly-once, closing the narrow race where a command completing at the
    // same instant a "cancel" arrives would otherwise emit two responses for
    // one request.
    private val responded: MutableSet<String> =
        java.util.Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

    private val client = OkHttpClient.Builder()
        .pingInterval(0, TimeUnit.SECONDS) // we send our own app-level JSON ping
        .readTimeout(0, TimeUnit.MILLISECONDS) // long-lived socket, no read timeout
        // Test devices routinely have a system-wide intercepting proxy configured
        // (Burp/mitmproxy, for capturing the TARGET app's traffic) — that's exactly
        // what this device is for. The bridge's own control channel to the Strobes
        // backend is platform signaling, not traffic under test, so it must not be
        // silently routed through whatever proxy happens to be set system-wide.
        .proxy(java.net.Proxy.NO_PROXY)
        .build()

    fun wsUrl(): String {
        val base = serverUrl.trim().removeSuffix("/")
        val wsBase = when {
            base.startsWith("https://") -> "wss://" + base.removePrefix("https://")
            base.startsWith("http://") -> "ws://" + base.removePrefix("http://")
            base.startsWith("ws://") || base.startsWith("wss://") -> base
            else -> "wss://$base"
        }
        return "$wsBase/ws/$orgId/shell-bridge/?api_key=$apiKey&bridge_id=$bridgeId"
    }

    fun connect() {
        val request = Request.Builder()
            .url(wsUrl())
            // The api_key is also in the query string because that's the
            // wire contract the platform's shell-bridge consumer parses.
            // Sending it as a header too lets the backend move to reading it
            // from here (and out of access logs) without breaking either
            // bridge — a header the server ignores is harmless.
            .header("Authorization", "Bearer $apiKey")
            .build()
        lastInboundAtMs = System.currentTimeMillis()
        ws = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "connected")
                lastInboundAtMs = System.currentTimeMillis()
                sendIdentify(webSocket)
                startPingLoop(webSocket)
                listener.onStatusChanged(true, "connected")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                lastInboundAtMs = System.currentTimeMillis()
                handleMessage(webSocket, text)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i(TAG, "closed: $code $reason")
                stopPingLoop()
                listener.onStatusChanged(false, "closed: $reason")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.w(TAG, "failure: ${t.message}")
                stopPingLoop()
                listener.onStatusChanged(false, "error: ${t.message}")
            }
        })
    }

    fun close() {
        stopPingLoop()
        try {
            ws?.close(1000, "client stop")
        } catch (_: Exception) {
        }
        ws = null
    }

    private fun sendIdentify(webSocket: WebSocket) {
        val root = RootShellExecutor.checkRoot()
        val (screenWidth, screenHeight) = try {
            DeviceInfoTools.screenResolution()
        } catch (e: Exception) {
            0 to 0
        }
        val data = JSONObject().apply {
            put("shell_name", shellName.ifBlank { Build.MODEL })
            put("os", "Android")
            put("host_os", "android")
            put("os_version", Build.VERSION.RELEASE)
            put("android_sdk", Build.VERSION.SDK_INT)
            put("arch", Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
            put("hostname", Build.MODEL)
            put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
            put("agent_version", "0.1.0")
            put("root_available", root.available)
            put("root_via", root.via)
            put("screen_width", screenWidth)
            put("screen_height", screenHeight)
            put("features", JSONArray(listOf("root_exec", "file_io", "device_inspection", "telephony", "traffic_interception")))
            // Let the platform plan against exactly what this bridge speaks,
            // rather than discovering gaps by getting "Unknown command" back.
            put("protocol_version", PROTOCOL_VERSION)
            put("commands", JSONArray(SUPPORTED_COMMANDS))
        }
        val payload = JSONObject().apply {
            put("type", "identify")
            put("data", data)
        }
        webSocket.send(payload.toString())
    }

    private fun startPingLoop(webSocket: WebSocket) {
        pingJob = scope.launch {
            while (isActive) {
                delay(PING_INTERVAL_MS)

                // Half-open detection: if nothing (not even a pong) has come
                // back within the grace window, the peer is gone even though
                // the TCP socket looks alive and no write has failed. Force a
                // close so the service's reconnect loop takes over instead of
                // the device appearing connected forever. (readTimeout is 0 —
                // reads never surface this on their own.)
                if (System.currentTimeMillis() - lastInboundAtMs > PONG_TIMEOUT_MS) {
                    Log.w(TAG, "no inbound frame in ${PONG_TIMEOUT_MS}ms — treating socket as dead")
                    try { webSocket.cancel() } catch (_: Exception) {}
                    break
                }

                val ping = JSONObject().apply {
                    put("type", "ping")
                    put("timestamp", System.currentTimeMillis() / 1000.0)
                }
                try {
                    if (!webSocket.send(ping.toString())) {
                        // Send-queue full / socket closing — don't wait for the
                        // watchdog, reconnect now.
                        webSocket.cancel()
                        break
                    }
                } catch (_: Exception) {
                    break
                }
            }
        }
    }

    private fun stopPingLoop() {
        pingJob?.cancel()
        pingJob = null
    }

    private fun handleMessage(webSocket: WebSocket, text: String) {
        val msg = try {
            JSONObject(text)
        } catch (e: Exception) {
            Log.w(TAG, "invalid JSON from server: $e")
            return
        }

        when (msg.optString("type")) {
            "identify_ack" -> {
                val data = msg.optJSONObject("data")
                Log.i(TAG, "identify_ack bridge_id=${data?.optString("bridge_id")}")
            }
            "pong" -> { /* keepalive acknowledged (liveness bumped in onMessage) */ }
            "command" -> dispatchCommand(webSocket, msg)
            "cancel" -> {
                // Abort an in-flight command so a stuck long-running action
                // doesn't hold its request slot until the dispatcher's own
                // MAX_COMMAND_MS ceiling.
                val requestId = msg.optString("request_id", "")
                val job = inFlight[requestId]
                if (job != null) {
                    job.cancel()
                    sendResponse(webSocket, requestId, JSONObject().apply {
                        put("success", false)
                        put("error", "Command cancelled by platform")
                        put("cancelled", true)
                    })
                }
            }
            "pty_open" -> {
                val requestId = msg.optString("request_id", "")
                if (requestId.isNotEmpty()) {
                    sendResponse(webSocket, requestId, JSONObject().apply {
                        put("success", false)
                        put("error", "PTY is not supported by the Android bridge yet")
                    })
                }
            }
            "pty_input", "pty_resize", "pty_close" -> { /* no PTY session to route to */ }
            else -> Log.d(TAG, "unhandled message type: ${msg.optString("type")}")
        }
    }

    /**
     * Entry point for an inbound "command" frame. Handles replay dedup and
     * registers the executing coroutine as cancellable BEFORE it starts (via
     * a LAZY job) so there's no window where a "cancel" can't find it.
     */
    private fun dispatchCommand(webSocket: WebSocket, msg: JSONObject) {
        val requestId = msg.optString("request_id", "")

        // Replay dedup: if the platform re-issues a command after a
        // mid-command disconnect, return the cached result rather than
        // re-running a non-idempotent action (pm install, a tap).
        if (requestId.isNotEmpty()) {
            val cached = synchronized(dedupLock) { recentResponses[requestId] }
            if (cached != null) {
                Log.i(TAG, "replaying cached response for request_id=$requestId")
                sendResponse(webSocket, requestId, cached)
                return
            }
        }

        val job = scope.launch(start = CoroutineStart.LAZY) { handleCommand(webSocket, msg) }
        if (requestId.isNotEmpty()) inFlight[requestId] = job
        job.start()
    }

    private suspend fun handleCommand(webSocket: WebSocket, msg: JSONObject) {
        val requestId = msg.optString("request_id", "")
        val command = msg.optString("command", "")
        val params = msg.optJSONObject("params") ?: JSONObject()

        Log.i(TAG, "executing command=$command request_id=$requestId")

        try {
            val requestedTimeoutSec = params.optInt("timeout", 60)
            val deadlineMs = (requestedTimeoutSec.toLong() * 1000L + COMMAND_SLACK_MS)
                .coerceIn(COMMAND_SLACK_MS, MAX_COMMAND_MS)

            val result: JSONObject? = withTimeoutOrNull(deadlineMs) {
                if (command in SHELL_BACKED_COMMANDS) {
                    // Serialize shell-backed commands so overlapping ones
                    // don't interleave on the shared libsu shell.
                    shellMutex.withLock { dispatch(command, params) }
                } else {
                    dispatch(command, params)
                }
            }

            val response = result ?: JSONObject().apply {
                put("success", false)
                put("error", "Command '$command' exceeded the bridge dispatch deadline (${deadlineMs}ms)")
                put("timeout", true)
            }
            if (requestId.isNotEmpty()) synchronized(dedupLock) { recentResponses[requestId] = response }
            sendResponse(webSocket, requestId, response)
        } catch (e: CancellationException) {
            // Cancelled via a "cancel" message — that handler already sent
            // the response. Just unwind; do not send twice.
            throw e
        } catch (e: Exception) {
            sendResponse(webSocket, requestId, JSONObject().apply {
                put("success", false)
                put("error", e.message ?: "command dispatch failed")
            })
        } finally {
            if (requestId.isNotEmpty()) inFlight.remove(requestId)
        }
    }

    private suspend fun dispatch(command: String, params: JSONObject): JSONObject {
        return try {
            when (command) {
                "shell_execute" -> ShellCommandRouter.execute(
                    params.optString("command", ""),
                    params.optInt("timeout", 60),
                )
                "shell_execute_code" -> {
                    // No per-language interpreters on-device; bash/sh-style code
                    // runs directly, matching the desktop daemon's own bash/sh
                    // branch. Non-shell languages are reported as unsupported
                    // rather than silently doing the wrong thing.
                    val language = params.optString("language", "bash").lowercase()
                    if (language in setOf("bash", "sh", "shell")) {
                        ShellCommandRouter.execute(
                            params.optString("code", ""),
                            params.optInt("timeout", 60),
                        )
                    } else {
                        JSONObject().apply {
                            put("success", false)
                            put("error", "Unsupported language on Android bridge: $language (only bash/sh)")
                        }
                    }
                }
                "env_info" -> envInfo()

                // File I/O — lets an agent push an APK (file_upload) then
                // `pm install`/`pm install-create`+`install-write`+`install-commit`
                // it via shell_execute, and pull back binary UI-automation
                // artifacts (screencap PNGs, uiautomator dump XML) without the
                // UTF-8 mangling shell_execute's stdout capture would cause.
                "file_read" -> FileTransfer.readFile(params.optString("path", ""))
                "file_write" -> FileTransfer.writeFile(
                    params.optString("path", ""),
                    params.optString("content", ""),
                    params.optString("mode", "overwrite"),
                )
                "file_list" -> FileTransfer.listFiles(
                    params.optString("directory", "."),
                    params.optBoolean("recursive", false),
                )
                "file_upload" -> FileTransfer.uploadFile(
                    params.optString("path", ""),
                    params.optString("content_b64", ""),
                )
                "file_download" -> FileTransfer.downloadFile(params.optString("path", ""))

                // Chunked transfer — the plain file_upload/file_download cap
                // out at ~7.5MB (WS frame limit), which is smaller than most
                // real APKs. These move a file in offset-addressed slices so
                // an agent can push/pull an arbitrarily large file (a big
                // APK, a video capture) over the same channel.
                "file_upload_chunk" -> FileTransfer.uploadChunk(
                    params.optString("path", ""),
                    params.optString("content_b64", ""),
                    params.optLong("offset", 0),
                    params.optBoolean("first", false),
                )
                "file_download_chunk" -> FileTransfer.downloadChunk(
                    params.optString("path", ""),
                    params.optLong("offset", 0),
                    params.optInt("length", 0),
                )

                // Structured device inspection — parsed wrappers over what
                // could be done via shell_execute, so agents get JSON back
                // instead of parsing pm/ip/logcat text themselves.
                "list_packages" -> DeviceInfoTools.listPackages(
                    params.optBoolean("system_apps", false),
                    params.optInt("timeout", 30),
                )
                "network_info" -> DeviceInfoTools.networkInfo(params.optInt("timeout", 30))
                "logcat" -> DeviceInfoTools.logcat(
                    params.optInt("lines", 500),
                    params.optString("filter", ""),
                    params.optString("package", ""),
                    params.optInt("timeout", 30),
                )

                // Restricted telephony fields (IMEI/phone number/SMS), read via
                // root shell since the normal TelephonyManager/SmsManager APIs
                // refuse these to any non-system app on modern Android. Primary
                // legitimate use: automating a target app's SMS-OTP flow.
                "device_identifiers" -> TelephonyTools.deviceIdentifiers(params.optInt("timeout", 15))
                "read_sms" -> TelephonyTools.readSms(
                    params.optString("address", ""),
                    params.optInt("limit", 50),
                    params.optInt("timeout", 15),
                )

                // Embedded MITM proxy — traffic interception from every app on
                // the device that honors the system HTTP proxy setting (root
                // sets that setting AND live-trusts our CA; see ProxyController).
                "proxy_start" -> ProxyController.start()
                "proxy_stop" -> ProxyController.stop(params.optBoolean("uninstall_ca", false))
                "proxy_status" -> ProxyController.status()
                "proxy_history" -> ProxyController.history(
                    params.optLong("since_id", 0),
                    params.optInt("limit", 200),
                    params.optString("host_filter", "").ifBlank { null },
                    params.optBoolean("include_bodies", true),
                )
                "proxy_clear_history" -> ProxyController.clearHistory()

                // Root/system trust-store CA path — deliberately staging-only
                // over this remote channel. A reboot is required to activate
                // it and is NEVER exposed here: a remote command that could
                // reboot the physical device it's driving is a hazard this
                // bridge does not take on. That step stays a local, human-
                // confirmed action in the app's own UI (see
                // ProxyController.rebootForRootCa / RootCaModuleInstaller).
                "proxy_install_root_ca" -> ProxyController.installRootCaModule()
                "proxy_uninstall_root_ca" -> ProxyController.uninstallRootCaModule()

                // Runtime cert/SSL-pinning bypass (Frida) — see FridaController's
                // doc comment for the on-device injection architecture. The
                // target app must already be running (launch it first via a
                // normal am start/monkey shell_execute call).
                "frida_status" -> FridaController.status()
                "frida_bypass_pinning" -> FridaController.bypassPinning(
                    params.optString("package_name").ifBlank { null },
                    params.optInt("timeout", 60),
                )
                "frida_run_script" -> FridaController.runScript(
                    params.optString("package_name"),
                    params.optString("script"),
                    params.optString("label", "custom"),
                )
                "frida_read_logs" -> FridaController.readLogs(
                    params.optString("session_id"),
                    params.optInt("tail_lines", 200),
                )
                "frida_stop_script" -> FridaController.stopScript(params.optString("session_id"))
                "frida_list_sessions" -> FridaController.listSessions()

                else -> JSONObject().apply {
                    put("success", false)
                    put("error", "Unknown command: $command")
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            JSONObject().apply {
                put("success", false)
                put("error", e.message ?: "command dispatch failed")
            }
        }
    }

    private fun envInfo(): JSONObject {
        val root = RootShellExecutor.checkRoot()
        val (screenWidth, screenHeight) = try {
            DeviceInfoTools.screenResolution()
        } catch (e: Exception) {
            0 to 0
        }
        return JSONObject().apply {
            put("success", true)
            put("os", "Android")
            put("os_version", Build.VERSION.RELEASE)
            put("android_sdk", Build.VERSION.SDK_INT)
            put("arch", Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
            put("hostname", Build.MODEL)
            put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
            put("root_available", root.available)
            put("root_via", root.via)
            put("root_detail", root.detail)
            put("screen_width", screenWidth)
            put("screen_height", screenHeight)
            put("protocol_version", PROTOCOL_VERSION)
            put("commands", JSONArray(SUPPORTED_COMMANDS))
        }
    }

    private fun sendResponse(webSocket: WebSocket, requestId: String, data: JSONObject) {
        if (requestId.isEmpty()) return
        // Exactly-once: first caller to claim this request_id wins.
        if (!responded.add(requestId)) return
        var text = JSONObject().apply {
            put("type", "response")
            put("request_id", requestId)
            put("data", data)
        }.toString()

        // Oversized frames are silently dropped by okhttp (send() returns
        // false, no exception) — which would hang the agent forever waiting
        // on a reply. Replace an over-limit payload with a structured error
        // so the agent gets an actionable response instead of nothing. (Bulk
        // data has dedicated chunked paths: proxy_history's since_id/limit,
        // file_download_chunk.)
        if (text.length > MAX_RESPONSE_BYTES) {
            Log.w(TAG, "response for $requestId is ${text.length} bytes — exceeds cap, replacing with error")
            text = JSONObject().apply {
                put("type", "response")
                put("request_id", requestId)
                put("data", JSONObject().apply {
                    put("success", false)
                    put(
                        "error",
                        "Response too large (${text.length} bytes, cap $MAX_RESPONSE_BYTES). " +
                            "Fetch it in slices instead: proxy_history with since_id/limit (or " +
                            "include_bodies=false), or file_download_chunk with offset/length.",
                    )
                    put("too_large", true)
                    put("size", text.length)
                })
            }.toString()
        }

        try {
            if (!webSocket.send(text)) {
                Log.w(TAG, "send() returned false for $requestId (socket closing / queue full)")
            }
        } catch (e: Exception) {
            Log.w(TAG, "failed to send response for $requestId: ${e.message}")
        }
    }
}
