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
        // A cloud agent drives this device unattended: an irreversible or
        // session-severing command (reboot, factory wipe, uninstalling the
        // bridge itself, nuking a filesystem root) must NOT be reachable
        // over the remote channel just because shell_execute is a root
        // passthrough. The dispatch comments elsewhere claim reboot "is
        // never exposed here" — without this guard, shell_execute("reboot")
        // silently made that claim false. Destructive device lifecycle
        // actions stay human-confirmed, in the app's own UI (e.g. the
        // reboot-for-root-CA flow in DeviceStatusActivity).
        classifyDestructive(command.trim())?.let { reason ->
            return fail(reason)
        }
        if (RootShellExecutor.checkRoot().available) {
            return RootShellExecutor.executeShellCommand(command, timeoutSeconds)
        }
        return executeNonRoot(command.trim())
    }

    /**
     * Pure classification of whether a shell command is a blocked
     * destructive/lifecycle action. Returns a human-readable rejection
     * reason, or null if the command is allowed. Kept side-effect-free (no
     * Android, no root check) so it's unit-testable off-device and so the
     * policy lives in exactly one place.
     *
     * Scope is deliberately narrow — only genuinely irreversible or
     * connection-severing operations, matched precisely so ordinary pentest
     * work (e.g. `rm -rf /data/local/tmp/foo`, uninstalling a *target* app)
     * is untouched. Splits on `;`, `&&`, `||`, `|`, and newlines so a
     * blocked verb can't be smuggled past as the second half of a compound
     * command.
     */
    fun classifyDestructive(command: String): String? {
        val segments = command
            .split(Regex("""[\n;]|&&|\|\||\|"""))
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        for (seg in segments) {
            destructiveReason(seg)?.let { return it }
        }
        return null
    }

    private const val SELF_PKG = "co.strobes.bridge"

    private fun destructiveReason(seg: String): String? {
        // Normalize leading `su -c`/`sh -c`/`toybox`/`busybox` wrappers so
        // e.g. `su -c reboot` is classified by its real verb, not the wrapper.
        val s = seg
            .removePrefix("su -c ").removePrefix("su root ")
            .removePrefix("sh -c ").removePrefix("toybox ").removePrefix("busybox ")
            .trim()
            .removeSurrounding("\"").removeSurrounding("'")
            .trim()
        val word0 = s.substringBefore(' ').substringAfterLast('/') // strip any path

        // Power/lifecycle: rebooting or powering off the very device the
        // agent is driving orphans the session.
        if (word0 in setOf("reboot", "shutdown", "halt", "poweroff")) {
            return "'$word0' is blocked over the remote bridge: rebooting/powering off the device " +
                "the agent is driving would orphan the session. Do it from the app UI on-device."
        }
        if (Regex("""^svc\s+power\s+(reboot|shutdown)""").containsMatchIn(s)) {
            return "'svc power' reboot/shutdown is blocked over the remote bridge — do it from the app UI on-device."
        }

        // Factory reset / recovery wipe — irreversible.
        if (Regex("""(^|\s)(--wipe_data|--wipe_cache)(\s|$)""").containsMatchIn(s) ||
            word0 == "fastboot" ||
            Regex("""^recovery\b""").containsMatchIn(s) ||
            Regex("""MASTER_CLEAR|FACTORY_RESET""").containsMatchIn(s)
        ) {
            return "Factory-reset / recovery-wipe commands are blocked over the remote bridge (irreversible)."
        }

        // Filesystem destruction of a real root (not a scratch subdir).
        if (word0 == "rm") {
            val recursive = Regex("""(^|\s)-[a-zA-Z]*[rR][a-zA-Z]*f|(^|\s)-[a-zA-Z]*f[a-zA-Z]*[rR]|(^|\s)-[rR]\s""").containsMatchIn(s) ||
                Regex("""(^|\s)--recursive""").containsMatchIn(s)
            if (recursive) {
                val protectedRoots = listOf("/", "/system", "/data", "/sdcard", "/vendor", "/storage")
                // Match a protected root as a whole path token, allowing a
                // trailing slash or wildcard but NOT a deeper path segment.
                val targets = Regex("""(?<=\s)(/[^\s]*)""").findAll(s).map { it.value.trimEnd('/', '*') }
                for (t in targets) {
                    val normalized = if (t.isEmpty()) "/" else t
                    if (normalized in protectedRoots) {
                        return "Recursive delete of a filesystem root ('$normalized') is blocked over the remote bridge. " +
                            "Deleting scoped paths (e.g. /data/local/tmp/...) is allowed."
                    }
                }
            }
        }

        // Low-level block-device destruction.
        if (word0 == "mkfs" || Regex("""^mkfs\.""").containsMatchIn(word0)) {
            return "'mkfs' (reformatting a filesystem) is blocked over the remote bridge."
        }
        if (word0 == "dd" && Regex("""of=/dev/block/""").containsMatchIn(s)) {
            return "'dd' to a block device is blocked over the remote bridge (can brick the device)."
        }

        // Removing the bridge itself severs the very channel this ran over.
        if (Regex("""^pm\s+(uninstall|clear|disable(-user)?)\b""").containsMatchIn(s) &&
            s.contains(SELF_PKG)
        ) {
            return "Uninstalling/clearing/disabling the Strobes Bridge app itself ($SELF_PKG) is blocked — " +
                "it would sever this control channel. Uninstall from the launcher on-device instead."
        }

        return null
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
