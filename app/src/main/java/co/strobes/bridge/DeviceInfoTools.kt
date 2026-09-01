package co.strobes.bridge

import org.json.JSONArray
import org.json.JSONObject

/**
 * Structured device-inspection commands — list_packages / network_info /
 * logcat. Everything here is just a parsed wrapper around a shell_execute
 * call an agent could already make (`pm list packages`, `ip addr`, `logcat
 * -d`); these exist so agents get structured JSON back instead of having to
 * parse raw command text themselves every time, the same reason env_info
 * exists as its own command rather than "just shell_execute getprop".
 */
object DeviceInfoTools {

    /**
     * Mirrors `pm list packages -f --show-versioncode` (optionally `-3` for
     * third-party only, the common pentest-relevant subset).
     * -> {success, packages: [{package, apk_path, version_code}], count}
     */
    suspend fun listPackages(systemApps: Boolean, timeoutSeconds: Int): JSONObject {
        if (!RootShellExecutor.checkRoot().available) return listPackagesViaPackageManager(systemApps)
        val flags = if (systemApps) "-f --show-versioncode" else "-3 -f --show-versioncode"
        val result = RootShellExecutor.executeShellCommand("pm list packages $flags", timeoutSeconds)
        if (!result.optBoolean("success", false)) {
            return JSONObject().apply {
                put("success", false)
                put("error", result.optString("stderr", "pm list packages failed"))
            }
        }
        // Line shape: package:/data/app/~~xyz==/com.example.app-abc==/base.apk=com.example.app versionCode:123
        val lineRe = Regex("""^package:(.+)=(\S+)(?:\s+versionCode:(\d+))?$""")
        val packages = JSONArray()
        result.optString("stdout", "").lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty()) return@forEach
            val m = lineRe.find(trimmed)
            if (m != null) {
                packages.put(JSONObject().apply {
                    put("package", m.groupValues[2])
                    put("apk_path", m.groupValues[1])
                    val vc = m.groupValues[3]
                    if (vc.isNotEmpty()) put("version_code", vc.toLong())
                })
            } else if (trimmed.startsWith("package:")) {
                // Fallback for older/odd pm output with no path (rare, e.g. no -f support)
                packages.put(JSONObject().apply { put("package", trimmed.removePrefix("package:")) })
            }
        }
        return JSONObject().apply {
            put("success", true)
            put("packages", packages)
            put("count", packages.length())
        }
    }

    /**
     * Network interfaces, routes, and DNS — gathered via `ip`, since Android
     * ships toybox's `ip`, not `ifconfig`/`netstat` in a consistently usable
     * form across versions. Sections are returned as raw text (parsing every
     * `ip addr` dialect reliably isn't worth the fragility) plus a best-effort
     * parsed `ip_addresses` list for the common case.
     * -> {success, ip_addresses: [{interface, address}], interfaces, routes, dns}
     */
    suspend fun networkInfo(timeoutSeconds: Int): JSONObject {
        if (!RootShellExecutor.checkRoot().available) return networkInfoViaConnectivityManager()
        val addrResult = RootShellExecutor.executeShellCommand("ip addr show 2>&1", timeoutSeconds)
        val routeResult = RootShellExecutor.executeShellCommand("ip route show 2>&1", timeoutSeconds)
        val dnsResult = RootShellExecutor.executeShellCommand(
            "getprop net.dns1; getprop net.dns2; getprop dhcp.wlan0.dns1; cat /etc/resolv.conf 2>/dev/null",
            timeoutSeconds,
        )

        if (!addrResult.optBoolean("success", false)) {
            return JSONObject().apply {
                put("success", false)
                put("error", addrResult.optString("stderr", "ip addr show failed"))
            }
        }

        val addrText = addrResult.optString("stdout", "")
        // e.g. "    inet 10.0.2.16/24 brd 10.0.2.255 scope global wlan0"
        val ifaceRe = Regex("""^\d+:\s+(\S+):""")
        val inetRe = Regex("""inet\s+([\d.]+)/\d+.*?\b(\S+)$""")
        var currentIface = ""
        val ipAddresses = JSONArray()
        addrText.lineSequence().forEach { rawLine ->
            val line = rawLine.trimStart()
            ifaceRe.find(rawLine)?.let { currentIface = it.groupValues[1] }
            inetRe.find(line)?.let { m ->
                ipAddresses.put(JSONObject().apply {
                    put("interface", currentIface)
                    put("address", m.groupValues[1])
                })
            }
        }

        return JSONObject().apply {
            put("success", true)
            put("ip_addresses", ipAddresses)
            put("interfaces", addrText)
            put("routes", routeResult.optString("stdout", ""))
            put("dns", dnsResult.optString("stdout", "").trim())
        }
    }

    /**
     * `logcat -d` (dump-and-exit, never blocks waiting for new lines).
     * `package`, if given, resolves to a PID via `pidof` and filters to it —
     * logcat has no direct by-package filter. `filter` is passed through
     * verbatim as logcat's tag:priority spec (e.g. "ActivityManager:I *:S").
     * -> {success, output, truncated}
     */
    suspend fun logcat(
        lines: Int,
        filter: String,
        packageName: String,
        timeoutSeconds: Int,
    ): JSONObject {
        val capped = lines.coerceIn(1, 5000)
        val cmdParts = mutableListOf("logcat", "-d", "-t", capped.toString())

        if (packageName.isNotBlank()) {
            val pidResult = RootShellExecutor.executeShellCommand("pidof ${shellQuote(packageName)}", timeoutSeconds)
            val pid = pidResult.optString("stdout", "").trim().split(" ").firstOrNull { it.isNotBlank() }
            if (pid.isNullOrBlank()) {
                return JSONObject().apply {
                    put("success", false)
                    put("error", "No running process found for package: $packageName")
                }
            }
            cmdParts += listOf("--pid=$pid")
        }
        if (filter.isNotBlank()) {
            cmdParts += filter
        }

        val result = RootShellExecutor.executeShellCommand(cmdParts.joinToString(" "), timeoutSeconds)
        return JSONObject().apply {
            put("success", result.optBoolean("success", false))
            put("output", result.optString("stdout", ""))
            if (!result.optBoolean("success", false)) {
                put("error", result.optString("stderr", "logcat failed"))
            }
        }
    }

    private fun shellQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    /** Real device pixel resolution — reported alongside other device_info
     * fields specifically so agent tools that show a (possibly downscaled,
     * see resize_if_needed on the backend) screenshot image can tell the
     * model the actual coordinate space `input tap`/`input swipe` expect,
     * instead of the model estimating tap coordinates directly off whatever
     * size image it was shown and silently mis-tapping by the scale factor. */
    fun screenResolution(): Pair<Int, Int> {
        val ctx = DeviceContext.require()
        val wm = ctx.getSystemService(android.content.Context.WINDOW_SERVICE) as android.view.WindowManager
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            val bounds = wm.currentWindowMetrics.bounds
            bounds.width() to bounds.height()
        } else {
            val metrics = android.util.DisplayMetrics()
            @Suppress("DEPRECATION")
            wm.defaultDisplay.getRealMetrics(metrics)
            metrics.widthPixels to metrics.heightPixels
        }
    }

    // -------------------------------------------------------------------
    // Non-root fallbacks — plain platform APIs, no shell involved.
    // -------------------------------------------------------------------

    private fun listPackagesViaPackageManager(systemApps: Boolean): JSONObject {
        val pm = DeviceContext.require().packageManager
        val packages = JSONArray()
        val installed = pm.getInstalledPackages(android.content.pm.PackageManager.GET_META_DATA)
        for (pkg in installed) {
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystem && !systemApps) continue
            packages.put(JSONObject().apply {
                put("package", pkg.packageName)
                put("apk_path", appInfo.sourceDir ?: "")
                put("version_code", pkg.longVersionCode)
            })
        }
        return JSONObject().apply {
            put("success", true)
            put("packages", packages)
            put("count", packages.length())
        }
    }

    private fun networkInfoViaConnectivityManager(): JSONObject {
        val ctx = DeviceContext.require()
        val cm = ctx.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val ipAddresses = JSONArray()
        val routesText = StringBuilder()
        val dnsText = StringBuilder()

        for (network in cm.allNetworks) {
            val linkProperties = cm.getLinkProperties(network) ?: continue
            val ifaceName = linkProperties.interfaceName ?: "unknown"
            for (addr in linkProperties.linkAddresses) {
                ipAddresses.put(JSONObject().apply {
                    put("interface", ifaceName)
                    put("address", addr.address.hostAddress ?: addr.toString())
                })
            }
            for (route in linkProperties.routes) {
                routesText.append(ifaceName).append(": ").append(route.toString()).append("\n")
            }
            for (dns in linkProperties.dnsServers) {
                dnsText.append(ifaceName).append(": ").append(dns.hostAddress).append("\n")
            }
        }

        return JSONObject().apply {
            put("success", true)
            put("ip_addresses", ipAddresses)
            put("interfaces", "(non-root: parsed via ConnectivityManager, not `ip addr` text)")
            put("routes", routesText.toString())
            put("dns", dnsText.toString().trim())
        }
    }
}
