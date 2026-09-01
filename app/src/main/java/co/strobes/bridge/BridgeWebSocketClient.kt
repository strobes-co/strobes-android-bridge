package co.strobes.bridge

import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
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
 * a Magisk module that, after a reboot, trusts the proxy's CA in the actual
 * system store rather than just the user-cert-store proxy_start installs
 * into.
 *
 * Differences from the desktop client, deliberately:
 *  - No PTY support (pty_open is answered with a graceful "not supported"
 *    error instead of hanging the platform's request).
 *  - No background-job (shell_bg_*) commands in this first cut. Long UI
 *    automation flows should be driven as a sequence of ordinary
 *    shell_execute calls instead.
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
    }

    private var ws: WebSocket? = null
    private var pingJob: Job? = null

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
        val request = Request.Builder().url(wsUrl()).build()
        ws = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "connected")
                sendIdentify(webSocket)
                startPingLoop(webSocket)
                listener.onStatusChanged(true, "connected")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
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
            put("features", listOf("root_exec", "file_io", "device_inspection", "telephony", "traffic_interception"))
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
                val ping = JSONObject().apply {
                    put("type", "ping")
                    put("timestamp", System.currentTimeMillis() / 1000.0)
                }
                try {
                    webSocket.send(ping.toString())
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
            "pong" -> { /* keepalive acknowledged */ }
            "command" -> scope.launch { handleCommand(webSocket, msg) }
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

    private suspend fun handleCommand(webSocket: WebSocket, msg: JSONObject) {
        val requestId = msg.optString("request_id", "")
        val command = msg.optString("command", "")
        val params = msg.optJSONObject("params") ?: JSONObject()

        Log.i(TAG, "executing command=$command request_id=$requestId")

        val result: JSONObject = try {
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
                // ProxyController.rebootForRootCa / MagiskModuleInstaller).
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
        } catch (e: Exception) {
            JSONObject().apply {
                put("success", false)
                put("error", e.message ?: "command dispatch failed")
            }
        }

        sendResponse(webSocket, requestId, result)
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
        }
    }

    private fun sendResponse(webSocket: WebSocket, requestId: String, data: JSONObject) {
        if (requestId.isEmpty()) return
        val payload = JSONObject().apply {
            put("type", "response")
            put("request_id", requestId)
            put("data", data)
        }
        try {
            webSocket.send(payload.toString())
        } catch (e: Exception) {
            Log.w(TAG, "failed to send response for $requestId: ${e.message}")
        }
    }
}
