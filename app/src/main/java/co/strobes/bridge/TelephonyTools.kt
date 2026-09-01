package co.strobes.bridge

import org.json.JSONArray
import org.json.JSONObject

/**
 * Device identifiers + SMS access via root shell — deliberately bypasses the
 * normal TelephonyManager API (which refuses IMEI/phone-number reads on
 * modern Android even with READ_PHONE_STATE, for anything but a system/
 * carrier-privileged app) by shelling out as root instead, the same way
 * forensic/MDM tooling on rooted devices does.
 *
 * Primary legitimate use on the Strobes bridge: automating a target app's
 * SMS-OTP login/verification flow end-to-end (read the code the app just
 * sent, type it back in) — a completely standard mobile pentest scenario —
 * plus device-fingerprinting checks (does the target app read/exfiltrate
 * the IMEI, phone number, etc. it shouldn't).
 *
 * Everything here is best-effort: IMEI/phone-number retrieval varies by
 * OEM, Android version, and whether a SIM/carrier profile is even present
 * (an emulator with no cellular radio will report nulls for most of this).
 */
object TelephonyTools {

    /** -> {success, imei, phone_number, serial, android_id, sim_serial} — any may be null. */
    suspend fun deviceIdentifiers(timeoutSeconds: Int): JSONObject {
        if (!RootShellExecutor.checkRoot().available) return deviceIdentifiersNonRoot()
        val serial = RootShellExecutor.executeShellCommand(
            "getprop ro.serialno; getprop ro.boot.serialno", timeoutSeconds,
        ).optString("stdout", "").lineSequence().firstOrNull { it.isNotBlank() }?.trim()

        val androidId = RootShellExecutor.executeShellCommand(
            "settings get secure android_id", timeoutSeconds,
        ).optString("stdout", "").trim().takeIf { it.isNotBlank() && it != "null" }

        val imei = parseServiceCallString(
            RootShellExecutor.executeShellCommand("service call iphonesubinfo 1", timeoutSeconds)
                .optString("stdout", ""),
        )

        // Transaction code for getLine1Number has moved across Android versions
        // (12/13/14/15ish) — try the two most common and take whichever answers.
        val phoneNumber = listOf(15, 13).firstNotNullOfOrNull { code ->
            parseServiceCallString(
                RootShellExecutor.executeShellCommand("service call iphonesubinfo $code", timeoutSeconds)
                    .optString("stdout", ""),
            )
        }

        val simSerial = parseServiceCallString(
            RootShellExecutor.executeShellCommand("service call iphonesubinfo 11", timeoutSeconds)
                .optString("stdout", ""),
        )

        return JSONObject().apply {
            put("success", true)
            // org.json's put(key, null) silently drops the key — use the
            // explicit JSONObject.NULL sentinel so callers always see the
            // field, even when the value genuinely couldn't be read.
            put("imei", imei ?: JSONObject.NULL)
            put("phone_number", phoneNumber ?: JSONObject.NULL)
            put("serial", serial ?: JSONObject.NULL)
            put("android_id", androidId ?: JSONObject.NULL)
            put("sim_serial", simSerial ?: JSONObject.NULL)
            put(
                "note",
                "Best-effort — depends on OEM/Android version and whether a SIM/carrier " +
                    "profile is present. An emulator with no cellular radio returns nulls here.",
            )
        }
    }

    /**
     * Reads the SMS content provider directly as root (bypasses the normal
     * READ_SMS permission check, same technique as `content query`). Typical
     * use: poll for the OTP the target app just triggered, filtering by the
     * sender address if known.
     * -> {success, messages: [{address, body, date, type}]}
     */
    suspend fun readSms(address: String, limit: Int, timeoutSeconds: Int): JSONObject {
        val capped = limit.coerceIn(1, 200)
        if (!RootShellExecutor.checkRoot().available) return readSmsViaContentResolver(address, capped)
        val where = if (address.isNotBlank()) {
            " --where ${shellQuote("address='${address.replace("'", "''")}'")}"
        } else {
            ""
        }
        val cmd = "content query --uri content://sms --sort ${shellQuote("date DESC")}$where " +
            "--projection address:body:date:type | head -n $capped"
        val result = RootShellExecutor.executeShellCommand(cmd, timeoutSeconds)
        if (!result.optBoolean("success", false)) {
            return JSONObject().apply {
                put("success", false)
                put("error", result.optString("stderr", "content query failed"))
            }
        }

        // Each line: "Row: 0 address=+1555..., body=Your code is 123456, date=..., type=1"
        val messages = JSONArray()
        result.optString("stdout", "").lineSequence().forEach { line ->
            if (!line.contains("address=")) return@forEach
            val fields = mutableMapOf<String, String>()
            Regex("""(\w+)=([^,]*?)(?=,\s*\w+=|$)""").findAll(line).forEach { m ->
                fields[m.groupValues[1]] = m.groupValues[2].trim()
            }
            if (fields.containsKey("address") || fields.containsKey("body")) {
                messages.put(JSONObject().apply {
                    put("address", fields["address"] ?: "")
                    put("body", fields["body"] ?: "")
                    put("date", fields["date"]?.toLongOrNull() ?: 0L)
                    put("type", fields["type"]?.toIntOrNull() ?: 0) // 1=inbox 2=sent
                })
            }
        }

        return JSONObject().apply {
            put("success", true)
            put("messages", messages)
            put("count", messages.length())
        }
    }

    /** Non-root fallback — IMEI/phone-number/serial genuinely aren't
     * readable by a normal app on modern Android even with
     * READ_PHONE_STATE (system/carrier-privileged only, unlike SMS which
     * has a real permission-gated path). android_id is the one honest
     * per-install identifier available without root. */
    private fun deviceIdentifiersNonRoot(): JSONObject {
        val androidId = try {
            android.provider.Settings.Secure.getString(
                DeviceContext.require().contentResolver, android.provider.Settings.Secure.ANDROID_ID,
            )
        } catch (e: Exception) {
            null
        }
        return JSONObject().apply {
            put("success", true)
            put("imei", JSONObject.NULL)
            put("phone_number", JSONObject.NULL)
            put("serial", JSONObject.NULL)
            put("android_id", androidId ?: JSONObject.NULL)
            put("sim_serial", JSONObject.NULL)
            put(
                "note",
                "Non-root: IMEI/phone number/serial/SIM serial are restricted to system/" +
                    "carrier-privileged apps on modern Android — there's no runtime-permission " +
                    "path to them like there is for SMS. android_id is the one identifier a " +
                    "normal app can still read.",
            )
        }
    }

    /** Non-root SMS read via the standard content provider — needs the
     * READ_SMS runtime permission granted (requested from the onboarding
     * wizard's Permissions step); no root, no `content query` shell-out.
     * Same result shape as the root path above. */
    private fun readSmsViaContentResolver(address: String, limit: Int): JSONObject {
        val ctx = DeviceContext.require()
        if (androidx.core.content.ContextCompat.checkSelfPermission(ctx, android.Manifest.permission.READ_SMS)
            != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            return JSONObject().apply {
                put("success", false)
                put("error", "READ_SMS permission not granted — enable it from the onboarding wizard's Permissions step.")
            }
        }
        val messages = JSONArray()
        val selection = if (address.isNotBlank()) "address = ?" else null
        val selectionArgs = if (address.isNotBlank()) arrayOf(address) else null
        val projection = arrayOf(
            android.provider.Telephony.Sms.ADDRESS,
            android.provider.Telephony.Sms.BODY,
            android.provider.Telephony.Sms.DATE,
            android.provider.Telephony.Sms.TYPE,
        )
        try {
            ctx.contentResolver.query(
                android.provider.Telephony.Sms.CONTENT_URI, projection, selection, selectionArgs,
                "${android.provider.Telephony.Sms.DATE} DESC",
            )?.use { cursor ->
                val addrIdx = cursor.getColumnIndex(android.provider.Telephony.Sms.ADDRESS)
                val bodyIdx = cursor.getColumnIndex(android.provider.Telephony.Sms.BODY)
                val dateIdx = cursor.getColumnIndex(android.provider.Telephony.Sms.DATE)
                val typeIdx = cursor.getColumnIndex(android.provider.Telephony.Sms.TYPE)
                while (cursor.moveToNext() && messages.length() < limit) {
                    messages.put(JSONObject().apply {
                        put("address", cursor.getString(addrIdx) ?: "")
                        put("body", cursor.getString(bodyIdx) ?: "")
                        put("date", cursor.getLong(dateIdx))
                        put("type", cursor.getInt(typeIdx))
                    })
                }
            }
        } catch (e: Exception) {
            return JSONObject().apply {
                put("success", false)
                put("error", e.message ?: "SMS content provider query failed")
            }
        }
        return JSONObject().apply {
            put("success", true)
            put("messages", messages)
            put("count", messages.length())
        }
    }

    /**
     * Parses `service call <svc> <code>` binder-parcel text output into the
     * UTF-16 string it encodes — the standard technique for reading
     * restricted TelephonyManager fields via a root shell. Returns null on
     * any parse failure or an empty/absent result (never throws).
     */
    private fun parseServiceCallString(raw: String): String? {
        try {
            // Each "Result: Parcel(...)" line's data lines look like:
            //   0x00000000: 00000000 0000000f 00350031 00310032 ...
            // Skip the 2 header words (status, string length), then decode
            // the remaining 32-bit words as little-endian UTF-16 code units.
            val hexWords = mutableListOf<String>()
            Regex("""0x[0-9a-fA-F]+:\s+(.+)""").findAll(raw).forEach { m ->
                hexWords += m.groupValues[1].trim().split(Regex("\\s+"))
            }
            if (hexWords.size < 3) return null

            val chars = StringBuilder()
            // First word after the status word is the string length (UTF-16 units).
            val lengthWord = hexWords[1]
            val length = lengthWord.toLongOrNull(16)?.let {
                // Word is stored little-endian-by-byte within the 8 hex chars.
                java.lang.Long.reverseBytes(it shl 32).ushr(32)
            } ?: return null
            if (length <= 0 || length > 4096) return null

            var unitsRead = 0
            for (i in 2 until hexWords.size) {
                if (unitsRead >= length) break
                val word = hexWords[i].padStart(8, '0')
                // Each 8-hex-char word holds two little-endian UTF-16 code units.
                val unit1 = word.substring(4, 6) + word.substring(6, 8)
                val unit2 = word.substring(0, 2) + word.substring(2, 4)
                for (u in listOf(unit1, unit2)) {
                    if (unitsRead >= length) break
                    val code = u.toIntOrNull(16) ?: 0
                    if (code != 0) chars.append(code.toChar())
                    unitsRead++
                }
            }
            val out = chars.toString().trim()
            return out.ifBlank { null }
        } catch (e: Exception) {
            return null
        }
    }

    private fun shellQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"
}
