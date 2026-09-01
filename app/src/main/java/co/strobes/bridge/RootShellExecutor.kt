package co.strobes.bridge

import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Root command execution for the Android bridge — the on-device analog of
 * strobes_shell_agent/executor.py's execute_shell_command(), same result
 * shape: {success, stdout, stderr, exit_code, duration_ms, error?}.
 *
 * Two paths, tried in order (matches the "support both" design decision):
 *  1. libsu — talks to a Magisk/KernelSU/APatch su daemon. Works for a
 *     normal app UID as long as the user has granted this app root in their
 *     root manager's prompt. Preferred: persistent shell, proper stdout/
 *     stderr separation, reliable exit codes. This is the path that matters
 *     in practice for any of the three common root managers — all of them
 *     act as a broker that explicitly authorizes THIS app's UID for root,
 *     which is the piece stock AOSP's own su has no concept of at all.
 *  2. Bare `su` via ProcessBuilder (see tryBareSu's own doc comment for the
 *     exact invocation and why) — for a device with a plain AOSP su binary
 *     and no root manager. Confirmed empirically (not just documented): on
 *     a genuine bare-AOSP `userdebug`/`eng` build, this su authorizes ONLY
 *     the adb shell UID (2000) or an already-root caller — an ordinary
 *     installed app's own UID gets flatly denied ("inaccessible or not
 *     found") even just to stat the binary, let alone exec it. So this path
 *     realistically only helps in the narrow case where the calling UID
 *     itself already has some root-equivalent standing (e.g. a shell-driven
 *     test harness), not the common "app wants root on an unmanaged device"
 *     case — that case has no fix at the app level; it needs a root manager
 *     (Magisk/KernelSU/APatch), full stop. No root-request prompt is
 *     possible on this path either way: the OS either lets this UID exec su
 *     or it doesn't.
 */
object RootShellExecutor {

    data class RootStatus(val available: Boolean, val via: String, val detail: String)

    fun checkRoot(): RootStatus {
        return try {
            val shell = Shell.getShell()
            if (shell.isRoot) {
                RootStatus(true, "libsu", "Root granted via su daemon (Magisk/KernelSU/APatch).")
            } else {
                // libsu couldn't get a root shell; see if a bare su binary answers anyway.
                val bare = tryBareSu("id", 5)
                if (bare.exitCode == 0) {
                    RootStatus(true, "su", "Root via bare su binary (no root manager detected).")
                } else {
                    // The common failure shape when a bare (non-Magisk/KernelSU/APatch)
                    // su binary exists but only authorizes the adb shell UID, not this
                    // app's own UID — confirmed empirically, not assumed: an ordinary
                    // app gets denied even just stat-ing the su binary. No amount of
                    // retrying or invocation-syntax tweaking fixes that from here; a
                    // root manager app is the only actual fix, so say so plainly
                    // instead of leaving this reading like a transient/fixable error.
                    val rawDetail = bare.stderr.ifBlank { "su not usable" }
                    val looksLikeUnauthorizedBareSu = Regex(
                        "inaccessible or not found|permission denied|invalid uid/gid",
                        RegexOption.IGNORE_CASE,
                    ).containsMatchIn(rawDetail)
                    val detail = if (looksLikeUnauthorizedBareSu) {
                        "No root manager (Magisk/KernelSU/APatch) is installed, and this device's " +
                            "own su binary only authorizes the adb shell, not an installed app's UID " +
                            "($rawDetail). Install one of those three to grant this app root."
                    } else {
                        "No root access available: $rawDetail"
                    }
                    RootStatus(false, "none", detail)
                }
            }
        } catch (e: Exception) {
            RootStatus(false, "none", e.message ?: "root check failed")
        }
    }

    /** Mirrors executor.py's execute_shell_command(command, timeout, cwd) -> dict. */
    suspend fun executeShellCommand(command: String, timeoutSeconds: Int): JSONObject {
        val start = System.nanoTime()
        val result = withContext(Dispatchers.IO) {
            withTimeoutOrNull(timeoutSeconds.toLong() * 1000L) {
                runViaLibsuOrBareSu(command)
            }
        }
        val durationMs = (System.nanoTime() - start) / 1_000_000

        val out = JSONObject()
        if (result == null) {
            out.put("success", false)
            out.put("stdout", "")
            out.put("stderr", "Command timed out after ${timeoutSeconds}s")
            out.put("exit_code", -1)
            out.put("duration_ms", durationMs)
            out.put("error", "timeout")
        } else {
            out.put("success", result.exitCode == 0)
            out.put("stdout", result.stdout)
            out.put("stderr", result.stderr)
            out.put("exit_code", result.exitCode)
            out.put("duration_ms", durationMs)
        }
        return out
    }

    private data class RawResult(val exitCode: Int, val stdout: String, val stderr: String)

    private fun runViaLibsuOrBareSu(command: String): RawResult {
        val shell = try { Shell.getShell() } catch (e: Exception) { null }
        if (shell != null && shell.isRoot) {
            val r = Shell.cmd(command).exec()
            return RawResult(r.code, r.out.joinToString("\n"), r.err.joinToString("\n"))
        }
        return tryBareSu(command, null)
    }

    /** Fallback for a bare AOSP su with no daemon. Genuine bare AOSP images
     * (no Magisk/KernelSU/APatch — e.g. a plain `userdebug`/`eng` "Google
     * APIs" emulator, as opposed to the Magisk-adjacent "Google Play" image)
     * ship toybox's su, whose usage is `su WHO COMMAND...` (WHO/COMMAND
     * optional) — there is no `-c` flag at all. `su -c command` on that su fails immediately with
     * "su: invalid uid/gid '-c'" (confirmed empirically), which used to make
     * this whole fallback silently useless on exactly the device class its
     * own doc comment claims to support. Explicitly invoking `sh -c command`
     * as the COMMAND (rather than relying on any top-level `-c` flag) works
     * the same way on both toybox su and Magisk's su — this is the
     * lowest-common-denominator invocation, not toybox-specific.
     * `command` is passed as ProcessBuilder's own argv element — it must NOT be
     * shell-quoted here (that would hand sh a string starting with a literal
     * quote character, which is exactly the "inaccessible or not found" bug
     * this comment used to not warn about). */
    private fun tryBareSu(command: String, timeoutSeconds: Int?): RawResult {
        return try {
            val proc = ProcessBuilder("su", "root", "sh", "-c", command)
                .redirectErrorStream(false)
                .start()
            val stdout = proc.inputStream.bufferedReader().use(BufferedReader::readText)
            val stderr = proc.errorStream.bufferedReader().use(BufferedReader::readText)
            val exited = if (timeoutSeconds != null) {
                proc.waitFor(timeoutSeconds.toLong(), java.util.concurrent.TimeUnit.SECONDS)
            } else true
            if (!exited) {
                proc.destroyForcibly()
                RawResult(-1, stdout, "$stderr\n(killed after timeout)")
            } else {
                RawResult(proc.exitValue(), stdout, stderr)
            }
        } catch (e: Exception) {
            RawResult(-1, "", e.message ?: "su exec failed")
        }
    }
}
