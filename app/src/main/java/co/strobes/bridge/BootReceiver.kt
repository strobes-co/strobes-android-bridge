package co.strobes.bridge

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restarts the bridge service after a reboot, if it was running before. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Prefs.isPaired(context) || !Prefs.wasBridgeRunning(context)) return

        val serviceIntent = Intent(context, BridgeForegroundService::class.java)
            .setAction(BridgeForegroundService.ACTION_START)
        context.startForegroundService(serviceIntent)
    }
}
