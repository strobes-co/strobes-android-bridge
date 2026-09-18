package co.strobes.bridge

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device round-trip for the chunked file transfer path that lets an agent
 * move a file larger than the single-frame (~7.5MB) cap — the fix for "most
 * real APKs are bigger than file_upload can carry". Root-agnostic: exercises
 * whichever byte backend is live (root real-file, or the non-root VirtualFs
 * sandbox), the same way BridgeWebSocketClient's handlers call it.
 *
 * Run with: ./gradlew connectedAndroidTest --tests FileTransferChunkTest
 */
@RunWith(AndroidJUnit4::class)
class FileTransferChunkTest {

    @Test
    fun chunkedUploadDownloadRoundTrips() = runBlocking {
        DeviceContext.init(InstrumentationRegistry.getInstrumentation().targetContext)

        val path = "/sdcard/strobes_chunk_test_${System.nanoTime()}.bin"
        val total = 1_000_000
        val data = ByteArray(total) { (it * 31 + 7).toByte() }
        val chunk = 300_000

        // --- upload in ordered chunks ---
        var offset = 0
        var first = true
        while (offset < total) {
            val end = minOf(offset + chunk, total)
            val slice = data.copyOfRange(offset, end)
            val b64 = android.util.Base64.encodeToString(slice, android.util.Base64.NO_WRAP)
            val res = FileTransfer.uploadChunk(path, b64, offset.toLong(), first)
            assertTrue("upload chunk @${offset} failed: ${res.optString("error")}", res.optBoolean("success"))
            assertEquals((end).toLong(), res.optLong("total_size"))
            offset = end
            first = false
        }

        // --- out-of-order chunk must be rejected with the expected offset ---
        val stray = android.util.Base64.encodeToString(ByteArray(10), android.util.Base64.NO_WRAP)
        val badRes = FileTransfer.uploadChunk(path, stray, 5L, false)
        assertFalse("stray offset should be rejected", badRes.optBoolean("success"))
        assertEquals(total.toLong(), badRes.optLong("expected_offset"))

        // --- download in chunks and reassemble ---
        val out = java.io.ByteArrayOutputStream()
        offset = 0
        while (true) {
            val res = FileTransfer.downloadChunk(path, offset.toLong(), chunk)
            assertTrue("download chunk @${offset} failed: ${res.optString("error")}", res.optBoolean("success"))
            assertEquals(total.toLong(), res.optLong("total_size"))
            val bytes = android.util.Base64.decode(res.optString("content_b64"), android.util.Base64.DEFAULT)
            out.write(bytes)
            offset += bytes.size
            if (res.optBoolean("eof")) break
            if (bytes.isEmpty()) break // safety against an infinite loop on a broken read
        }

        assertArrayEquals("reassembled bytes differ from source", data, out.toByteArray())

        // cleanup best-effort (root path only; VirtualFs is process-scoped)
        if (RootShellExecutor.checkRoot().available) {
            RootShellExecutor.executeShellCommand("rm -f '$path'", 10)
        }
    }
}
