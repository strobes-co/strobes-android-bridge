package co.strobes.bridge

import android.content.Context

/**
 * Process-wide application Context holder — same convention as
 * ProxyController.init(), just shared across the non-root code paths
 * (AccessibilityAutomation, FileTransfer's virtual-fs fallback,
 * DeviceInfoTools' PackageManager/ConnectivityManager fallback) instead of
 * threading a Context argument through every one of them individually.
 */
object DeviceContext {
    @Volatile private var appContext: Context? = null

    fun init(context: Context) {
        if (appContext == null) appContext = context.applicationContext
    }

    fun require(): Context = appContext ?: error("DeviceContext.init() was never called")
}
