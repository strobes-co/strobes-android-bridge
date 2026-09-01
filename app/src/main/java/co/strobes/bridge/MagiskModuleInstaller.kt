package co.strobes.bridge

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Installs the MITM proxy's CA into the REAL system trust store — the thing
 * ProxyTools.kt's user-cert-store approach is a live, no-reboot substitute
 * for, because a direct SELinux/dm-verity bypass isn't achievable with plain
 * root (see that file's doc comment for exactly what was tried and why it
 * failed). A Magisk module is the actual sanctioned mechanism for this:
 * Magisk's own boot-time "magic mount" merges module files into /system
 * with correctly-labeled SELinux contexts, because Magisk — not this app —
 * is the one asking the kernel to allow it.
 *
 * Trade-off, and why this is a SEPARATE, human-gated path rather than what
 * proxy_start does automatically: the merge only happens at boot. Writing
 * these files has no effect until the device reboots, and the reboot itself
 * is disruptive (kills every running app, this bridge's own connection
 * included) — so this must never fire without the human explicitly choosing
 * it, unlike the user-cert-store install which is safe to do automatically.
 *
 * Once active (post-reboot), this is trusted by any app relying on the
 * system store's default behavior — the common case — closing the gap the
 * user-cert-store path leaves for apps that don't explicitly opt in via
 * their network security config.
 */
object MagiskModuleInstaller {

    private const val MODULE_ID = "strobes_mitm_ca"
    private const val MODULE_DIR = "/data/adb/modules/$MODULE_ID"

    private fun modulePropContents(): String = """
        id=$MODULE_ID
        name=Strobes Bridge MITM CA
        version=v1
        versionCode=1
        author=strobes
        description=Merges the Strobes Bridge embedded MITM proxy's CA cert into the system trust store at boot.
    """.trimIndent()

    /** Writes the module (cert + module.prop) under /data/adb/modules. Takes
     * effect only after the device reboots — this function does not reboot. */
    suspend fun install(context: Context, pem: String, fileName: String): JSONObject {
        val certFile = File(context.filesDir, fileName)
        certFile.writeText(pem)
        val propFile = File(context.filesDir, "module.prop")
        propFile.writeText(modulePropContents())

        val certsDir = "$MODULE_DIR/system/etc/security/cacerts"
        val script = """
            set -e
            mkdir -p $certsDir
            rm -f $MODULE_DIR/remove
            cp '${propFile.absolutePath}' $MODULE_DIR/module.prop
            cp '${certFile.absolutePath}' $certsDir/$fileName
            chmod 644 $MODULE_DIR/module.prop $certsDir/$fileName
            find $MODULE_DIR -type d -exec chmod 755 {} +
        """.trimIndent()

        val result = RootShellExecutor.executeShellCommand(script, 20)
        if (result.optBoolean("success")) {
            result.put("reboot_required", true)
        }
        return result
    }

    /** Marks the module for removal on the NEXT boot — Magisk's own
     * convention (a file literally named `remove` inside the module dir),
     * rather than deleting files out from under an active magic-mount. */
    suspend fun uninstall(): JSONObject {
        val result = RootShellExecutor.executeShellCommand(
            "[ -d $MODULE_DIR ] && touch $MODULE_DIR/remove || true", 10,
        )
        if (result.optBoolean("success")) {
            result.put("reboot_required", true)
        }
        return result
    }

    suspend fun isModuleStaged(): Boolean {
        val result = RootShellExecutor.executeShellCommand(
            "[ -d $MODULE_DIR ] && [ ! -f $MODULE_DIR/remove ] && echo yes || echo no", 10,
        )
        return result.optString("stdout").trim() == "yes"
    }

    /** True only once the module has actually taken effect — i.e. the cert
     * is really present in /system, meaning a reboot happened AFTER install. */
    suspend fun isActiveInSystemStore(fileName: String): Boolean {
        val result = RootShellExecutor.executeShellCommand(
            "[ -f /system/etc/security/cacerts/$fileName ] && echo yes || echo no", 10,
        )
        return result.optString("stdout").trim() == "yes"
    }

    /** The disruptive part, deliberately isolated in its own function so
     * callers can't reach it except by a clearly separate, explicit call —
     * never bundled into install(). */
    suspend fun rebootNow(): JSONObject {
        return RootShellExecutor.executeShellCommand("reboot", 5)
    }
}
