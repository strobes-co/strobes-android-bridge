package co.strobes.bridge

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Persistent foreground service — the Android analog of the desktop bridge
 * daemon's `connect_forever()` loop in strobes_shell_agent/client.py. Owns
 * one BridgeWebSocketClient at a time and reconnects with the same backoff
 * schedule as the desktop client (1s -> 60s, x2) so both bridge types behave
 * identically from the platform's point of view.
 */
class BridgeForegroundService : Service() {

    companion object {
        const val ACTION_START = "co.strobes.bridge.action.START"
        const val ACTION_STOP = "co.strobes.bridge.action.STOP"
        private const val CHANNEL_ID = "strobes_bridge_channel"
        private const val NOTIFICATION_ID = 1001

        private const val INITIAL_BACKOFF_MS = 1_000L
        private const val MAX_BACKOFF_MS = 60_000L

        private val _status = MutableStateFlow("stopped")
        val status: StateFlow<String> = _status
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var client: BridgeWebSocketClient? = null
    private var loopJob: Job? = null
    private val stateLock = Mutex()

    // A foreground service survives being killed, but Doze still suspends its
    // network and defers the ping loop's delay() — an idle test phone would
    // go silent and the agent would see a dead device. A partial wake lock
    // keeps the CPU (not the screen) alive while the bridge is running so the
    // control channel stays responsive unattended. The battery-optimization
    // exemption that lets this actually hold under Doze is requested from the
    // onboarding wizard; without it Android may still throttle, but the lock
    // is the necessary half we own here.
    private var wakeLock: PowerManager.WakeLock? = null

    @Volatile
    private var running = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        ProxyController.init(applicationContext)
        DeviceContext.init(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopBridge()
                stopSelf()
            }
            else -> startBridge()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopBridge()
        super.onDestroy()
    }

    private fun startBridge() {
        if (running) return
        running = true
        Prefs.setBridgeRunning(this, true)
        acquireWakeLock()
        startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))
        loopJob = serviceScope.launch { connectLoop() }

        // Interception must be continuous, not something an agent/human has
        // to remember to switch on first — a target app already running (or
        // launched) before a later explicit proxy_start call keeps its
        // pre-existing keep-alive connections and silently bypasses capture
        // even once the proxy comes up. Starting it here, as early in the
        // bridge's own lifecycle as possible, closes that window for
        // anything launched after the bridge. ProxyController.start() is
        // idempotent (MitmProxyServer.start() is a no-op if already
        // running), so a later remote/manual proxy_start just confirms
        // state rather than restarting anything.
        serviceScope.launch {
            try {
                ProxyController.start()
            } catch (_: Exception) {
                // Best-effort — status card / android_proxy_status still
                // reports the real state either way; nothing else depends
                // on this succeeding synchronously.
            }
        }
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(PowerManager::class.java) ?: return
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "StrobesBridge::control").apply {
            setReferenceCounted(false)
            // No timeout: the bridge is meant to run for the length of an
            // engagement. It's released deterministically in stopBridge().
            acquire()
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        } catch (_: Exception) {
        }
        wakeLock = null
    }

    private fun stopBridge() {
        running = false
        Prefs.setBridgeRunning(this, false)
        loopJob?.cancel()
        client?.close()
        client = null
        releaseWakeLock()
        _status.value = "stopped"
        stopForeground(STOP_FOREGROUND_REMOVE)

        // A live system-wide proxy setting pointing at a now-dead local port
        // would break ALL network access on the device the moment this
        // service goes away — this must not be left dangling. Full teardown
        // (unlike the standalone proxy_stop command, which defaults to
        // leaving the CA trusted) also drops the CA trust: stopping the
        // whole bridge reads as "done with this session," not "pause."
        serviceScope.launch {
            try {
                ProxyController.stop(uninstallCa = true)
            } catch (_: Exception) {
                // Best-effort — nothing left to report to once the service is gone.
            }
        }
    }

    private suspend fun connectLoop() {
        var backoffMs = INITIAL_BACKOFF_MS

        while (running) {
            val serverUrl = Prefs.serverUrl(this)
            val orgId = Prefs.orgId(this)
            val apiKey = Prefs.apiKey(this)
            val bridgeId = Prefs.bridgeId(this)
            val shellName = Prefs.shellName(this)

            if (serverUrl.isBlank() || orgId.isBlank() || apiKey.isBlank()) {
                _status.value = "not paired"
                updateNotification("Not paired")
                return
            }

            val disconnectSignal = kotlinx.coroutines.CompletableDeferred<Unit>()

            val c = BridgeWebSocketClient(
                serverUrl, orgId, apiKey, bridgeId, shellName, serviceScope,
                object : BridgeWebSocketClient.Listener {
                    override fun onStatusChanged(connected: Boolean, detail: String) {
                        _status.value = if (connected) "connected" else "disconnected: $detail"
                        updateNotification(_status.value)
                        if (connected) {
                            backoffMs = INITIAL_BACKOFF_MS
                        } else if (!disconnectSignal.isCompleted) {
                            disconnectSignal.complete(Unit)
                        }
                    }
                },
            )
            stateLock.withLock { client = c }
            c.connect()

            disconnectSignal.await()
            if (!running) break

            delay(backoffMs)
            backoffMs = (backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Strobes Bridge", NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shows the Strobes bridge connection status"
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val stopIntent = Intent(this, BridgeForegroundService::class.java).setAction(ACTION_STOP)
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Strobes Bridge")
            .setContentText(statusText)
            .setSmallIcon(R.drawable.ic_stat_bridge)
            .setOngoing(true)
            .addAction(0, "Stop", stopPendingIntent)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(statusText))
    }
}
