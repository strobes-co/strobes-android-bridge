package co.strobes.bridge

import org.json.JSONObject

/**
 * What BridgeWebSocketClient's "shell_execute"/"shell_execute_code" cases
 * actually call now, instead of RootShellExecutor directly. Root devices see
 * ZERO behavior change — this is a pure passthrough in that case. On a
 * non-root device, it pattern-matches the small set of shell idioms an
 * agent's android_* tools actually send (see strobes-dev's
 * android_device_tools.py: input tap/swipe/text, screencap -p, uiautomator
 * dump, am start) and translates each to the AccessibilityService
 * equivalent — so an agent that only ever speaks shell_execute keeps working
 * unmodified whether or not the device is rooted. Anything outside that set
 * (pm install/clear, arbitrary su-requiring commands, IMEI/SMS) genuinely
 * has no non-root equivalent and returns a clear, honest failure instead of
 * a silent no-op.
 */
object ShellCommandRouter {

    private val TAP_RE = Regex("""^input\s+tap\s+(-?\d+)\s+(-?\d+)\s*$""")
    private val SWIPE_RE = Regex("""^input\s+swipe\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)(?:\s+(\d+))?\s*$""")
    private val TEXT_RE = Regex("""^input\s+text\s+(.+)$""")
    private val KEYEVENT_RE = Regex("""^input\s+keyevent\s+(\S+)\s*$""")
    private val SCREENCAP_RE = Regex("""^screencap\s+-p\s+(\S+)\s*$""")
    private val UIAUTOMATOR_DUMP_RE = Regex("""^uiautomator\s+dump(?:\s+(\S+))?\s*$""")
    private val AM_START_PACKAGE_RE = Regex("""^am\s+start\s+(?:-n\s+)?(\S+)/(\S+)\s*$""")
    // `monkey -p <pkg> -c android.intent.category.LAUNCHER 1` is the real
    // Android idiom for "launch this app by package alone" (there's no `-p`
    // flag on `am start` itself) — this is what an agent sends when it
    // doesn't already know the launcher activity's exact name.
    private val MONKEY_LAUNCH_RE = Regex("""^monkey\s+.*-p\s+(\S+).*$""")

    suspend fun execute(command: String, timeoutSeconds: Int): JSONObject {
        if (RootShellExecutor.checkRoot().available) {
            return RootShellExecutor.executeShellCommand(command, timeoutSeconds)
        }
        return executeNonRoot(command.trim())
    }

    private suspend fun executeNonRoot(command: String): JSONObject {
        if (!StrobesAccessibilityService.isRunning()) {
            return fail(
                "Root is unavailable and the Strobes Accessibility Service isn't enabled — " +
                    "enable it in the app (Settings > Accessibility > Strobes Bridge) to unlock " +
                    "non-root tap/swipe/type/screenshot automation. See MainActivity's Automation " +
                    "Mode card for the full non-root capability list.",
            )
        }
        val svc = StrobesAccessibilityService.requireInstance()

        TAP_RE.find(command)?.let { m ->
            val (x, y) = m.destructured
            val ok = svc.tap(x.toInt(), y.toInt())
            return ok(if (ok) "" else "", success = ok, error = if (ok) null else "gesture dispatch was cancelled/rejected")
        }
        SWIPE_RE.find(command)?.let { m ->
            val g = m.groupValues
            val duration = g[5].toLongOrNull() ?: 300L
            val ok = svc.swipe(g[1].toInt(), g[2].toInt(), g[3].toInt(), g[4].toInt(), duration)
            return ok("", success = ok, error = if (ok) null else "gesture dispatch was cancelled/rejected")
        }
        TEXT_RE.find(command)?.let { m ->
            // `input text` encodes spaces as %s and expects a shell-quoted
            // argument; unquote/unescape the common cases an agent sends.
            var text = m.groupValues[1].trim()
            if (text.length >= 2 && ((text.first() == '\'' && text.last() == '\'') || (text.first() == '"' && text.last() == '"'))) {
                text = text.substring(1, text.length - 1)
            }
            text = text.replace("%s", " ")
            val ok = svc.typeText(text)
            return ok(
                "", success = ok,
                error = if (ok) null else "no focused editable field — tap the input field first",
            )
        }
        KEYEVENT_RE.find(command)?.let { m ->
            val ok = when (m.groupValues[1]) {
                "4", "KEYCODE_BACK" -> svc.pressBack()
                "3", "KEYCODE_HOME" -> svc.pressHome()
                "187", "KEYCODE_APP_SWITCH" -> svc.pressRecents()
                else -> return fail("keyevent ${m.groupValues[1]} has no non-root equivalent (only BACK/HOME/RECENTS are reachable without root)")
            }
            return ok("", success = ok, error = if (ok) null else "global action was rejected")
        }
        SCREENCAP_RE.find(command)?.let { m ->
            val bitmap = svc.screenshot()
                ?: return fail(
                    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) {
                        "Non-root screenshots need Android 11+ (AccessibilityService.takeScreenshot); this device is older."
                    } else {
                        "Screenshot capture failed or was denied."
                    },
                )
            val bytes = java.io.ByteArrayOutputStream().use { out ->
                bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out)
                out.toByteArray()
            }
            bitmap.recycle()
            VirtualFs.write(m.groupValues[1], bytes)
            return ok("")
        }
        UIAUTOMATOR_DUMP_RE.find(command)?.let { m ->
            val xml = svc.dumpUiTreeXml()
            val outPath = m.groupValues[1].ifBlank { "/sdcard/window_dump.xml" }
            VirtualFs.write(outPath, xml.toByteArray(Charsets.UTF_8))
            return ok("UI hierchary dumped to: $outPath")
        }
        AM_START_PACKAGE_RE.find(command)?.let { m ->
            return launchComponent(m.groupValues[1], m.groupValues[2])
        }
        MONKEY_LAUNCH_RE.find(command)?.let { m ->
            return launchPackage(m.groupValues[1])
        }
        if (command.startsWith("pm list packages")) {
            // Same data list_packages already exposes structurally — shell_execute
            // callers get a plain package-per-line list, matching real `pm` output.
            val systemApps = command.contains("-a") || !command.contains("-3")
            val result = DeviceInfoTools.listPackages(systemApps, 15)
            if (!result.optBoolean("success")) return result
            val packages = result.optJSONArray("packages")
            val lines = StringBuilder()
            if (packages != null) {
                for (i in 0 until packages.length()) {
                    lines.append("package:").append(packages.getJSONObject(i).optString("package")).append("\n")
                }
            }
            return ok(lines.toString())
        }

        return fail(
            "Root is unavailable and this command has no non-root translation. Supported without " +
                "root: input tap/swipe/text/keyevent (BACK/HOME/RECENTS), screencap -p <path>, " +
                "uiautomator dump [<path>], am start -n <pkg>/<activity>, monkey -p <pkg> -c android.intent.category.LAUNCHER 1, " +
                "pm list packages. Command was: $command",
        )
    }

    private fun launchComponent(pkg: String, activity: String): JSONObject {
        val ctx = DeviceContext.require()
        val resolvedActivity = if (activity.startsWith(".")) pkg + activity else activity
        val intent = android.content.Intent().apply {
            setClassName(pkg, resolvedActivity)
            addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            ctx.startActivity(intent)
            ok("Starting: Intent { cmp=$pkg/$resolvedActivity }")
        } catch (e: Exception) {
            fail("Could not launch $pkg/$resolvedActivity without root: ${e.message}")
        }
    }

    private fun launchPackage(pkg: String): JSONObject {
        val ctx = DeviceContext.require()
        val intent = ctx.packageManager.getLaunchIntentForPackage(pkg)
            ?: return fail("No launcher activity found for package $pkg (or it isn't installed)")
        intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        return try {
            ctx.startActivity(intent)
            ok("Starting: Intent { pkg=$pkg }")
        } catch (e: Exception) {
            fail("Could not launch $pkg without root: ${e.message}")
        }
    }

    private fun ok(stdout: String, success: Boolean = true, error: String? = null): JSONObject =
        JSONObject().apply {
            put("success", success)
            put("stdout", stdout)
            put("stderr", error ?: "")
            put("exit_code", if (success) 0 else 1)
            put("duration_ms", 0)
            if (error != null) put("error", error)
        }

    private fun fail(error: String): JSONObject = ok("", success = false, error = error)
}
