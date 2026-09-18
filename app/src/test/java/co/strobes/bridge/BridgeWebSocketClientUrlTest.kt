package co.strobes.bridge

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Off-device unit tests for the ws:// URL derivation — the scheme/host
 * rewrite that has to be exactly right for the bridge to reach the platform's
 * shell-bridge endpoint regardless of how the server URL was pasted in.
 */
class BridgeWebSocketClientUrlTest {

    private fun client(serverUrl: String) = BridgeWebSocketClient(
        serverUrl = serverUrl,
        orgId = "org1",
        apiKey = "KEY",
        bridgeId = "bridge1",
        shellName = "test",
        scope = CoroutineScope(Dispatchers.Default),
        listener = object : BridgeWebSocketClient.Listener {
            override fun onStatusChanged(connected: Boolean, detail: String) {}
        },
    )

    private val suffix = "/ws/org1/shell-bridge/?api_key=KEY&bridge_id=bridge1"

    @Test fun httpsBecomesWss() {
        assertEquals("wss://app.strobes.co$suffix", client("https://app.strobes.co").wsUrl())
    }

    @Test fun httpBecomesWs() {
        assertEquals("ws://10.0.0.5:8000$suffix", client("http://10.0.0.5:8000").wsUrl())
    }

    @Test fun bareHostDefaultsToWss() {
        assertEquals("wss://app.strobes.co$suffix", client("app.strobes.co").wsUrl())
    }

    @Test fun trailingSlashIsStripped() {
        assertEquals("wss://app.strobes.co$suffix", client("https://app.strobes.co/").wsUrl())
    }

    @Test fun explicitWsSchemesPreserved() {
        assertEquals("wss://app.strobes.co$suffix", client("wss://app.strobes.co").wsUrl())
        assertEquals("ws://app.strobes.co$suffix", client("ws://app.strobes.co").wsUrl())
    }
}
