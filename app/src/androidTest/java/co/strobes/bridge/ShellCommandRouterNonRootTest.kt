package co.strobes.bridge

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs ON the device, calling ShellCommandRouter.execute() exactly the way
 * BridgeWebSocketClient's shell_execute handler does — this is the actual
 * production non-root code path (regex match -> StrobesAccessibilityService
 * gesture/text/screenshot/dump calls), not a simulation of it. Requires:
 *   1. The device has no root (asserted, not assumed — fails loudly if root
 *      IS available, since that would silently test the wrong code path).
 *   2. Settings > Accessibility > Strobes Bridge is already enabled before
 *      running (can't be granted from a test — it's a user-consent gate by
 *      design, same as on a real device).
 *
 * Run with: ./gradlew connectedAndroidTest --tests ShellCommandRouterNonRootTest
 *
 * KNOWN HARNESS CAVEAT (confirmed, not theoretical): `am instrument` force-
 * stops the app before each run, and Android's accessibility manager treats
 * a force-stopped, actively-bound accessibility service as a crash — after
 * enough of those (repeated test runs in a row) it silently drops the
 * service from enabled_accessibility_services, and this test starts failing
 * with "isn't enabled" even though nothing in the app changed. Real usage
 * never hits this (a device owner enabling it once via Settings never gets
 * force-stopped). If this test fails that way, re-enable accessibility
 * (`adb shell settings put secure enabled_accessibility_services co.strobes.bridge/co.strobes.bridge.StrobesAccessibilityService`)
 * and re-run — or, to sidestep the force-stop entirely, drive
 * ShellCommandRouter through DebugCommandReceiver instead (adb broadcast
 * into the already-running process, no instrumentation involved).
 */
@RunWith(AndroidJUnit4::class)
class ShellCommandRouterNonRootTest {

    private fun failTest(message: String): Nothing = throw AssertionError(message)

    @Test
    fun exercisesRealNonRootAutomationPath() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        DeviceContext.init(context)

        val root = RootShellExecutor.checkRoot()
        if (root.available) {
            fail(
                "This device has root available — this test specifically verifies the NON-ROOT " +
                    "fallback path and would silently pass for the wrong reason (root passthrough) " +
                    "if it ran here. Run it on a genuinely non-rooted device/emulator instead.",
            )
        }
        // am instrument force-stops the app before relaunching it for the
        // test — a force-stop puts the package in Android's "stopped"
        // state, which specifically blocks the OS from auto-rebinding any
        // of its components (including an already-enabled accessibility
        // service) until something explicitly launches one of its
        // activities. So: launch MainActivity FIRST (this is also exactly
        // what a real device owner does — open the app — before anything
        // else works, root or not), THEN poll for the rebind.
        context.startActivity(
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        )
        Thread.sleep(1500)

        var waited = 0L
        while (!StrobesAccessibilityService.isRunning() && waited < 8000) {
            Thread.sleep(250)
            waited += 250
        }
        if (!StrobesAccessibilityService.isRunning()) {
            fail(
                "Strobes Accessibility Service isn't enabled (waited ${waited}ms for a rebind after " +
                    "launching MainActivity). Enable it first: adb shell settings put secure " +
                    "enabled_accessibility_services co.strobes.bridge/co.strobes.bridge.StrobesAccessibilityService",
            )
        }

        // --- uiautomator dump: locate the Organization ID field for real ---
        val dumpPath = "/sdcard/e2e_dump_1.xml"
        val dump1 = ShellCommandRouter.execute("uiautomator dump $dumpPath", 10)
        assertTrue("uiautomator dump failed: ${dump1.optString("stderr")}", dump1.optBoolean("success"))
        val xml1 = String(VirtualFs.read(dumpPath) ?: ByteArray(0), Charsets.UTF_8)
        assertTrue("dump XML didn't mention input_org_id — is MainActivity really foregrounded?", xml1.contains("input_org_id"))

        val bounds = Regex(
            """resource-id="co\.strobes\.bridge:id/input_org_id"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"""",
        ).find(xml1) ?: failTest("Couldn't parse input_org_id's bounds out of the real UI dump")
        val (left, top, right, bottom) = bounds.destructured
        val tapX = (left.toInt() + right.toInt()) / 2
        val tapY = (top.toInt() + bottom.toInt()) / 2

        // --- input tap: focus the field via a real dispatched gesture ---
        val tapResult = ShellCommandRouter.execute("input tap $tapX $tapY", 10)
        assertTrue("tap failed: ${tapResult.optString("stderr")}", tapResult.optBoolean("success"))
        Thread.sleep(500)

        // --- input text: type into whatever now has focus ---
        val marker = "strobes-e2e-${System.nanoTime()}"
        val textResult = ShellCommandRouter.execute("input text '$marker'", 10)
        assertTrue("text entry failed: ${textResult.optString("stderr")}", textResult.optBoolean("success"))
        Thread.sleep(500)

        // --- uiautomator dump again: confirm the typed text is REALLY on screen ---
        val dumpPath2 = "/sdcard/e2e_dump_2.xml"
        val dump2 = ShellCommandRouter.execute("uiautomator dump $dumpPath2", 10)
        assertTrue(dump2.optBoolean("success"))
        val xml2 = String(VirtualFs.read(dumpPath2) ?: ByteArray(0), Charsets.UTF_8)
        assertTrue(
            "typed marker text '$marker' did not appear in the post-type UI dump — " +
                "tap+type round trip did not actually reach the field",
            xml2.contains(marker),
        )

        // --- screencap: confirm a real, non-empty PNG comes back through VirtualFs ---
        val screenshotPath = "/sdcard/e2e_screenshot.png"
        val screenshotResult = ShellCommandRouter.execute("screencap -p $screenshotPath", 10)
        assertTrue("screenshot failed: ${screenshotResult.optString("stderr")}", screenshotResult.optBoolean("success"))
        val pngBytes = VirtualFs.read(screenshotPath) ?: ByteArray(0)
        assertTrue("screenshot file is empty", pngBytes.size > 100)
        val pngMagic = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47)
        assertEquals(pngMagic.toList(), pngBytes.take(4))

        // --- input swipe: dispatch a real scroll gesture ---
        val swipeResult = ShellCommandRouter.execute("input swipe 500 1800 500 400 300", 10)
        assertTrue("swipe failed: ${swipeResult.optString("stderr")}", swipeResult.optBoolean("success"))

        // --- input keyevent: BACK is one of the only two non-root-reachable keyevents ---
        val backResult = ShellCommandRouter.execute("input keyevent 4", 10)
        assertTrue("keyevent BACK failed: ${backResult.optString("stderr")}", backResult.optBoolean("success"))

        // --- pm list packages: confirm our own package shows up in a real listing ---
        val pmResult = ShellCommandRouter.execute("pm list packages -3", 10)
        assertTrue("pm list packages failed: ${pmResult.optString("stderr")}", pmResult.optBoolean("success"))
        assertTrue(
            "pm list packages output didn't include co.strobes.bridge itself",
            pmResult.optString("stdout").contains("co.strobes.bridge"),
        )

        // --- monkey launch: relaunch our own app by package alone (the real idiom) ---
        val monkeyResult = ShellCommandRouter.execute(
            "monkey -p co.strobes.bridge -c android.intent.category.LAUNCHER 1", 10,
        )
        assertTrue("monkey launch failed: ${monkeyResult.optString("stderr")}", monkeyResult.optBoolean("success"))
    }
}
