package co.strobes.bridge

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * adb-only debug hook, e.g.:
 *   adb shell am broadcast -n co.strobes.bridge/.DebugCommandReceiver \
 *     -a co.strobes.bridge.DEBUG_SHELL --es cmd "input tap 100 200"
 *
 * Runs the exact ShellCommandRouter.execute() path BridgeWebSocketClient's
 * shell_execute handler calls, from inside the actual long-lived app
 * process — exists because `am instrument` (the normal way to exercise app
 * code from adb) force-stops the app first, and Android's accessibility
 * manager treats a force-stopped, actively-bound accessibility service as a
 * crash: after enough of those it silently drops the service from
 * enabled_accessibility_services, which makes instrumented tests of the
 * non-root automation path unreliable in a way real usage never hits (a
 * device owner enabling it once via Settings never gets force-stopped).
 * This receiver lets that same code be verified against a live, normally
 * long-running process instead.
 *
 * Self-disables outside a debuggable build (checked at runtime, not just
 * gated by a manifest flavor, so it can't accidentally ship live even if
 * this ever gets built with a release signing config). Not exported —
 * `adb shell` can still target it directly by component name, but another
 * app on the device cannot.
 */
class DebugCommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) return
        val cmd = intent.getStringExtra("cmd") ?: return
        DeviceContext.init(context.applicationContext)
        CoroutineScope(Dispatchers.IO).launch {
            val result = ShellCommandRouter.execute(cmd, 15)
            android.util.Log.i("StrobesDebugCmd", "cmd=[$cmd] result=$result")
        }
    }
}
