package co.strobes.bridge

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.security.KeyChain
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * Root-level device plumbing for the embedded MITM proxy: pointing the
 * system-wide HTTP proxy at it, and trusting its CA cert so HTTPS
 * interception doesn't fail every TLS handshake with an untrusted-cert error.
 *
 * Scope note (proxy): this covers every app that honors the system proxy
 * setting (the default for anything using Android's stock HTTP stack — the
 * same mechanism this bridge's OWN OkHttp client explicitly opts OUT of via
 * Proxy.NO_PROXY in BridgeWebSocketClient.kt, which is direct proof it's
 * respected on this exact stack). A small minority of apps set their HTTP
 * client to bypass the system proxy deliberately; transparently redirecting
 * those too would need iptables NAT plus SO_ORIGINAL_DST lookup (native
 * code) and is out of scope for this pass.
 *
 * Scope note (CA trust) — live-patching the SYSTEM trust store turned out to
 * be blocked two layers deep on a stock enforcing-SELinux device, root or
 * not: `/` sits on a dm-verity block device (remounting rw is refused at the
 * kernel level, not just a permissions error), and even a tmpfs overlay
 * mount labeled with the cacerts SELinux context gets a kernel-level
 * `avc: denied { associate }` — a MAC policy restriction Magisk's root
 * doesn't grant by default (Magisk explicitly does NOT mean "SELinux is
 * off"). The genuinely live, no-reboot mechanism root CAN reach is the
 * per-user cert store, which lives on a normal (non-verity) /data partition
 * with no special context requirements: `/data/misc/user/0/cacerts-added/`.
 * That's this app's real CA install target now. Trade-off: since Android P
 * (API 24+), an app trusts a user-added cert only if it opts in via network
 * security config — most apps targeting a modern SDK don't, so this won't
 * intercept every hardened app's traffic. It's still strictly better than
 * nothing achievable live, and identical to what the honest RUNBOOK fallback
 * would tell a human tester to do by hand in the same situation.
 */
object ProxyTools {

    private const val USER_CACERTS_DIR = "/data/misc/user/0/cacerts-added"

    /** Installs [pem] into the live user cert store as [fileName] (the
     * caller-computed subject-hash filename) — a normal /data write, no
     * reboot, no SELinux relabeling trick required. See the scope note above
     * for which apps this does and doesn't cover. */
    suspend fun installCaCert(context: Context, pem: String, fileName: String): JSONObject {
        val certFile = File(context.filesDir, fileName)
        certFile.writeText(pem)

        val script = """
            set -e
            mkdir -p $USER_CACERTS_DIR
            cp '${certFile.absolutePath}' $USER_CACERTS_DIR/$fileName
            chmod 644 $USER_CACERTS_DIR/$fileName
        """.trimIndent()

        return RootShellExecutor.executeShellCommand(script, 20)
    }

    suspend fun uninstallCaCert(fileName: String): JSONObject {
        return RootShellExecutor.executeShellCommand("rm -f $USER_CACERTS_DIR/$fileName", 15)
    }

    suspend fun isCaCertInstalled(fileName: String): Boolean {
        val result = RootShellExecutor.executeShellCommand(
            "[ -f $USER_CACERTS_DIR/$fileName ] && echo yes || echo no", 10,
        )
        return result.optString("stdout").trim() == "yes"
    }

    // -------------------------------------------------------------------
    // Non-root CA path: android.security.KeyChain — the standard system
    // "install a CA certificate" flow (a real system dialog, no root, no
    // shell). Works on top of root too, so this is now the ONE trust check
    // used regardless of root state — it reads whatever the OS actually
    // trusts (AndroidCAStore merges system + user certs), which is a more
    // honest signal than "does our root-written file still exist".
    // -------------------------------------------------------------------

    /** Builds the system "Install certificate" intent for [caCert] — must be
     * launched from an Activity (KeyChain.createInstallIntent() requires
     * startActivityForResult/ActivityResultLauncher, not available from a
     * Service). The user sees Android's own dialog and must confirm. */
    fun createCaInstallIntent(caCert: X509Certificate): Intent =
        KeyChain.createInstallIntent().apply {
            putExtra(KeyChain.EXTRA_CERTIFICATE, caCert.encoded)
            putExtra(KeyChain.EXTRA_NAME, "Strobes Bridge MITM CA")
        }

    /** True if [caCert] is actually trusted by the platform right now —
     * checked via the same "AndroidCAStore" KeyStore apps themselves
     * consult during TLS validation, so this reflects reality whether the
     * cert got there via root (writing straight to cacerts-added) or via
     * the KeyChain system dialog. */
    fun isCaTrusted(caCert: X509Certificate): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val ourFingerprint = fingerprint(caCert)
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val cert = keyStore.getCertificate(aliases.nextElement()) as? X509Certificate ?: continue
                if (fingerprint(cert) == ourFingerprint) return true
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    private fun fingerprint(cert: X509Certificate): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(cert.encoded)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** Saves the CA cert PEM into the public Downloads folder — PEM is a
     * genuinely installable format here (Java's X509 CertificateFactory,
     * which is what Android's own cert installer uses under the hood,
     * accepts both DER and Base64/PEM-with-markers input directly, no
     * conversion needed). Returns a content:// URI the caller can hand
     * straight to ACTION_VIEW so Android offers to install it immediately,
     * instead of just leaving a file sitting in Downloads. [createInstallIntent]/
     * KeyChain looks like the right API but doesn't complete an install from
     * inside a third-party app on modern Android — it just bounces to a
     * generic "must be installed in Settings" dialog with no way to finish
     * there, by OS policy (not a bug in this app). */
    fun saveCaCertToDownloads(context: Context, pem: String, baseName: String): JSONObject {
        val downloadName = "$baseName.crt"
        return try {
            val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = context.contentResolver
                // Re-downloading overwrites in place instead of piling up
                // "strobes-bridge-ca (1).crt", "(2)", ... on every tap.
                resolver.delete(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    "${MediaStore.Downloads.DISPLAY_NAME} = ?", arrayOf(downloadName),
                )
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, downloadName)
                    put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val inserted = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: return JSONObject().apply {
                        put("success", false)
                        put("error", "Could not create a Downloads entry")
                    }
                resolver.openOutputStream(inserted)?.use { it.write(pem.toByteArray()) }
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                resolver.update(inserted, values, null, null)
                inserted
            } else {
                @Suppress("DEPRECATION")
                val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                dir.mkdirs()
                val file = File(dir, downloadName)
                file.writeText(pem)
                androidx.core.content.FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
            }
            JSONObject().apply {
                put("success", true)
                put("file_name", downloadName)
                put("uri", uri.toString())
            }
        } catch (e: Exception) {
            JSONObject().apply {
                put("success", false)
                put("error", e.message ?: "Failed to save the certificate file")
            }
        }
    }

    /** Points the system-wide HTTP/HTTPS proxy at our local proxy server. */
    suspend fun setSystemProxy(port: Int): JSONObject {
        val script = """
            settings put global http_proxy 127.0.0.1:$port
            settings put global global_http_proxy_host 127.0.0.1
            settings put global global_http_proxy_port $port
            settings put global global_http_proxy_exclusion_list ""
        """.trimIndent()
        return RootShellExecutor.executeShellCommand(script, 15)
    }

    suspend fun clearSystemProxy(): JSONObject {
        val script = """
            settings put global http_proxy :0
            settings put global global_http_proxy_host ""
            settings put global global_http_proxy_port ""
        """.trimIndent()
        return RootShellExecutor.executeShellCommand(script, 15)
    }
}
