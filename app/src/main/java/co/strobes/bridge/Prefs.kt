package co.strobes.bridge

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.util.UUID

/**
 * Pairing config, mirroring strobes_shell_agent/config.py's env vars
 * (STROBES_URL / STROBES_API_KEY / STROBES_ORG_ID / STROBES_BRIDGE_ID) —
 * same fields, same meaning, just persisted on-device instead of via .env.
 *
 * The api_key is the sole trust boundary for this bridge (root command
 * execution on the paired device), so it's stored in an encrypted file
 * rather than plain SharedPreferences.
 */
object Prefs {
    private const val FILE_NAME = "strobes_bridge_secure_prefs"

    private fun prefs(context: Context): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                FILE_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        } catch (e: Exception) {
            // Falls back to a plain prefs file only if Keystore is unavailable
            // (e.g. some emulator images) — still better than crashing.
            context.getSharedPreferences(FILE_NAME + "_fallback", Context.MODE_PRIVATE)
        }
    }

    fun serverUrl(context: Context): String = prefs(context).getString("server_url", "") ?: ""
    fun orgId(context: Context): String = prefs(context).getString("org_id", "") ?: ""
    fun apiKey(context: Context): String = prefs(context).getString("api_key", "") ?: ""
    fun shellName(context: Context): String = prefs(context).getString("shell_name", "") ?: ""

    fun bridgeId(context: Context): String {
        val p = prefs(context)
        var id = p.getString("bridge_id", null)
        if (id == null) {
            id = UUID.randomUUID().toString()
            p.edit().putString("bridge_id", id).apply()
        }
        return id
    }

    /**
     * Pin the bridge_id to a server-issued value (from a pairing deep link),
     * so this app connects as the exact Shell row the platform already
     * created — instead of the self-generated fallback id from [bridgeId].
     */
    fun setBridgeId(context: Context, bridgeId: String) {
        if (bridgeId.isBlank()) return
        prefs(context).edit().putString("bridge_id", bridgeId).apply()
    }

    fun isPaired(context: Context): Boolean =
        serverUrl(context).isNotBlank() && orgId(context).isNotBlank() && apiKey(context).isNotBlank()

    fun save(context: Context, serverUrl: String, orgId: String, apiKey: String, shellName: String) {
        prefs(context).edit()
            .putString("server_url", serverUrl.trim())
            .putString("org_id", orgId.trim())
            .putString("api_key", apiKey.trim())
            .putString("shell_name", shellName.trim())
            .apply()
    }

    fun clear(context: Context) {
        prefs(context).edit().clear().apply()
    }

    fun setBridgeRunning(context: Context, running: Boolean) {
        prefs(context).edit().putBoolean("bridge_running", running).apply()
    }

    fun wasBridgeRunning(context: Context): Boolean =
        prefs(context).getBoolean("bridge_running", false)
}
