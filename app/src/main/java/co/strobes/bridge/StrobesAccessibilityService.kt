package co.strobes.bridge

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Bitmap
import android.graphics.Path
import android.hardware.HardwareBuffer
import android.os.Build
import android.os.Bundle
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executor
import kotlin.coroutines.resume

/**
 * Non-root UI automation, standing in for what `input tap`/`input text`/
 * `screencap`/`uiautomator dump` do via root shell (see ShellCommandRouter,
 * which routes to these instead of RootShellExecutor when root isn't
 * available). This can only automate what an AccessibilityService is
 * actually allowed to: synthetic gestures, text into the FOCUSED editable
 * field, a handful of global actions (back/home/recents), and a screenshot —
 * there's no non-root equivalent of arbitrary shell (no `pm`, no `am start`
 * beyond launching one app's own launcher intent, no `su`).
 *
 * Requires the user to grant this service manually in
 * Settings > Accessibility (see MainActivity's onboarding card) — nothing
 * here can self-enable that; Android deliberately disallows it.
 */
class StrobesAccessibilityService : AccessibilityService() {

    companion object {
        @Volatile private var instance: StrobesAccessibilityService? = null

        fun isRunning(): Boolean = instance != null

        fun requireInstance(): StrobesAccessibilityService =
            instance ?: error("Accessibility service not enabled — see Settings > Accessibility > Strobes Bridge.")
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) { /* no event-driven behavior needed */ }
    override fun onInterrupt() {}

    // -------------------------------------------------------------------
    // Gestures
    // -------------------------------------------------------------------

    suspend fun tap(x: Int, y: Int): Boolean {
        val path = Path().apply { moveTo(x.toFloat(), y.toFloat()) }
        val stroke = GestureDescription.StrokeDescription(path, 0, 60)
        return dispatchGestureAwait(GestureDescription.Builder().addStroke(stroke).build())
    }

    suspend fun swipe(x1: Int, y1: Int, x2: Int, y2: Int, durationMs: Long): Boolean {
        val path = Path().apply {
            moveTo(x1.toFloat(), y1.toFloat())
            lineTo(x2.toFloat(), y2.toFloat())
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceAtLeast(1))
        return dispatchGestureAwait(GestureDescription.Builder().addStroke(stroke).build())
    }

    private suspend fun dispatchGestureAwait(gesture: GestureDescription): Boolean =
        suspendCancellableCoroutine { cont ->
            val callback = object : GestureResultCallback() {
                override fun onCompleted(gestureDescription: GestureDescription?) {
                    if (cont.isActive) cont.resume(true)
                }
                override fun onCancelled(gestureDescription: GestureDescription?) {
                    if (cont.isActive) cont.resume(false)
                }
            }
            val accepted = dispatchGesture(gesture, callback, null)
            if (!accepted && cont.isActive) cont.resume(false)
        }

    // -------------------------------------------------------------------
    // Text input — into whichever node currently has input focus. There's
    // no non-root way to target an arbitrary node blind the way `input
    // text` can; the caller is expected to have tapped the field first.
    // -------------------------------------------------------------------

    fun typeText(text: String): Boolean {
        val node = rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return false
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        }
        return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    // -------------------------------------------------------------------
    // Global actions — the only keyevents reachable without root; there's
    // no non-root path for an arbitrary keycode.
    // -------------------------------------------------------------------

    fun pressBack(): Boolean = performGlobalAction(GLOBAL_ACTION_BACK)
    fun pressHome(): Boolean = performGlobalAction(GLOBAL_ACTION_HOME)
    fun pressRecents(): Boolean = performGlobalAction(GLOBAL_ACTION_RECENTS)

    // -------------------------------------------------------------------
    // Screenshot — AccessibilityService.takeScreenshot() needs API 30+;
    // there is no non-root screenshot path below that (screencap itself
    // needs a system/shell UID, and MediaProjection needs a per-request
    // user consent dialog this headless bridge has no Activity to show).
    // -------------------------------------------------------------------

    suspend fun screenshot(): Bitmap? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        return suspendCancellableCoroutine { cont ->
            val executor = Executor { it.run() }
            takeScreenshot(
                Display.DEFAULT_DISPLAY,
                executor,
                object : TakeScreenshotCallback {
                    override fun onSuccess(result: ScreenshotResult) {
                        val bitmap = try {
                            val hw: HardwareBuffer = result.hardwareBuffer
                            val bmp = Bitmap.wrapHardwareBuffer(hw, result.colorSpace)
                            // wrapHardwareBuffer's Bitmap is hardware-backed (not
                            // directly PNG-encodable/pixel-readable) — copy to a
                            // normal software bitmap before handing it back.
                            val software = bmp?.copy(Bitmap.Config.ARGB_8888, false)
                            hw.close()
                            software
                        } catch (e: Exception) {
                            null
                        }
                        if (cont.isActive) cont.resume(bitmap)
                    }
                    override fun onFailure(errorCode: Int) {
                        if (cont.isActive) cont.resume(null)
                    }
                },
            )
        }
    }

    // -------------------------------------------------------------------
    // UI tree dump — emitted in the same shape as `uiautomator dump`'s XML
    // (node/index/text/resource-id/class/bounds/clickable) so an agent's
    // existing bounds-parsing logic (it already reads real uiautomator XML
    // for tap-coordinate discovery) needs no changes to consume this too.
    // -------------------------------------------------------------------

    fun dumpUiTreeXml(): String {
        val root = rootInActiveWindow
        val sb = StringBuilder()
        sb.append("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>")
        sb.append("<hierarchy rotation=\"0\">")
        if (root != null) {
            appendNode(sb, root, 0)
            root.recycle()
        }
        sb.append("</hierarchy>")
        return sb.toString()
    }

    private fun appendNode(sb: StringBuilder, node: AccessibilityNodeInfo, index: Int) {
        val bounds = android.graphics.Rect()
        node.getBoundsInScreen(bounds)
        sb.append("<node index=\"").append(index).append("\"")
        sb.append(" text=\"").append(xmlEscape(node.text?.toString().orEmpty())).append("\"")
        sb.append(" resource-id=\"").append(xmlEscape(node.viewIdResourceName.orEmpty())).append("\"")
        sb.append(" class=\"").append(xmlEscape(node.className?.toString().orEmpty())).append("\"")
        sb.append(" content-desc=\"").append(xmlEscape(node.contentDescription?.toString().orEmpty())).append("\"")
        sb.append(" clickable=\"").append(node.isClickable).append("\"")
        sb.append(" enabled=\"").append(node.isEnabled).append("\"")
        sb.append(" focused=\"").append(node.isFocused).append("\"")
        sb.append(" scrollable=\"").append(node.isScrollable).append("\"")
        sb.append(" password=\"").append(node.isPassword).append("\"")
        sb.append(" bounds=\"[").append(bounds.left).append(",").append(bounds.top)
            .append("][").append(bounds.right).append(",").append(bounds.bottom).append("]\"")
        val childCount = node.childCount
        if (childCount == 0) {
            sb.append(" />")
        } else {
            sb.append(">")
            for (i in 0 until childCount) {
                val child = node.getChild(i) ?: continue
                appendNode(sb, child, i)
                child.recycle()
            }
            sb.append("</node>")
        }
    }

    private fun xmlEscape(s: String): String = s
        .replace("&", "&amp;")
        .replace("\"", "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
}
