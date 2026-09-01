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
 *  1. libsu — talks to a Magisk/KernelSU su daemon. Works for a normal app
 *     UID as long as the user has granted this app root in their root
 *     manager's prompt. Preferred: persistent shell, proper stdout/stderr
 *     separation, reliable exit codes.
 *  2. Bare `su -c <command>` via ProcessBuilder — works on a bare AOSP
 *     eng/userdebug build where /system/(xbin|bin)/su exists but there is no
 *     Magisk daemon (common on test emulators). No root-request prompt is
 *     possible here: the OS either lets this UID exec su or it doesn't.
 */
object RootShellExecutor {

    data class RootStatus(val available: Boolean, val via: String, val detail: String)

    fun checkRoot(): RootStatus {
        return try {
            val shell = Shell.getShell()
            if (shell.isRoot) {
                RootStatus(true, "libsu", "Root granted via su daemon (Magisk/KernelSU).")
            } else {
                // libsu couldn't get a root shell; see if a bare su binary answers anyway.
                val bare = tryBareSu("id", 5)
                if (bare.exitCode == 0) {
                    RootStatus(true, "su", "Root via bare su binary (no root manager detected).")
                } else {
                    RootStatus(false, "none", "No root access available: ${bare.stderr.ifBlank { "su not usable" }}")
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

    /** Fallback for a bare AOSP su with no daemon: `su -c <command>` as one process.
     * `command` is passed as ProcessBuilder's own argv element — it must NOT be
     * shell-quoted here (that would hand su a string starting with a literal
     * quote character, which is exactly the "inaccessible or not found" bug
     * this comment used to not warn about). */
    private fun tryBareSu(command: String, timeoutSeconds: Int?): RawResult {
        return try {
            val proc = ProcessBuilder("su", "-c", command)
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
