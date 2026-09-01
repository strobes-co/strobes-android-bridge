package co.strobes.bridge

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

private const val TAG = "StrobesMitmProxy"

/**
 * Embedded MITM proxy: an explicit HTTP proxy (what `settings put global
 * http_proxy` points every proxy-aware app at) that also terminates TLS on
 * CONNECT tunnels using a fresh leaf cert per host, signed by
 * [MitmCertAuthority]'s CA — the same shape as mitmproxy/Burp's
 * interception mode, just embedded on-device instead of external.
 *
 * One accept loop, one thread per connection (blocking IO) — this is a
 * capture tool for a bounded pentest session, not a production proxy, so
 * simplicity beats throughput here.
 */
class MitmProxyServer(private val certAuthority: MitmCertAuthority) {

    @Volatile private var running = false
    @Volatile private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private val connectionThreads = CopyOnWriteArrayList<Thread>()
    private val sslContextCache = ConcurrentHashMap<String, SSLContext>()

    var port: Int = 0
        private set

    fun isRunning(): Boolean = running

    /** Binds loopback-only (127.0.0.1) — this proxy is for THIS device's own
     * apps via the system proxy setting, never meant to be reachable from
     * the network. [requestedPort] = 0 picks any free port. */
    @Synchronized
    fun start(requestedPort: Int = 0): Int {
        if (running) return port
        val ss = ServerSocket(requestedPort, 50, InetAddress.getByName("127.0.0.1"))
        serverSocket = ss
        port = ss.localPort
        running = true

        acceptThread = Thread({
            while (running) {
                val client = try {
                    ss.accept()
                } catch (e: Exception) {
                    if (running) Log.w(TAG, "accept() failed: ${e.message}")
                    break
                }
                val t = Thread({ handleConnection(client) }, "mitm-conn-${client.port}")
                connectionThreads.add(t)
                t.start()
            }
        }, "mitm-accept")
        acceptThread?.start()
        return port
    }

    @Synchronized
    fun stop() {
        running = false
        try { serverSocket?.close() } catch (_: Exception) { /* already closed */ }
        serverSocket = null
        for (t in connectionThreads) t.interrupt()
        connectionThreads.clear()
    }

    private fun handleConnection(client: Socket) {
        try {
            client.soTimeout = 30_000
            val firstMsg = HttpMessageUtil.readMessage(client.getInputStream()) ?: return
            val parts = firstMsg.startLine.split(" ")
            if (parts.size < 2) return
            val method = parts[0]

            if (method.equals("CONNECT", ignoreCase = true)) {
                val hostPort = parts[1]
                val host = hostPort.substringBefore(":")
                val targetPort = hostPort.substringAfter(":", "443").toIntOrNull() ?: 443

                client.getOutputStream().write(
                    "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII),
                )
                client.getOutputStream().flush()

                val sslContext = sslContextCache.getOrPut(host) { buildServerSslContext(host) }
                val sslSocket = sslContext.socketFactory.createSocket(client, host, targetPort, true) as SSLSocket
                sslSocket.useClientMode = false
                try {
                    sslSocket.startHandshake()
                    relayLoop(sslSocket.inputStream, sslSocket.outputStream, "https", host, targetPort, null)
                } finally {
                    try { sslSocket.close() } catch (_: Exception) { /* client already gone */ }
                }
                return // sslSocket.close() also closes the underlying `client` socket
            }

            relayLoop(client.getInputStream(), client.getOutputStream(), "http", null, null, firstMsg)
        } catch (e: Exception) {
            // Client disconnects, TLS handshake aborts from a cert-pinning app
            // rejecting our leaf cert, etc. — expected noise for a MITM proxy,
            // not something worth a history entry (there's no request to log yet).
            Log.d(TAG, "connection ended: ${e.message}")
        } finally {
            try { client.close() } catch (_: Exception) { /* already closed */ }
        }
    }

    /** Reads and relays requests on one client connection until it closes.
     * [firstMessage], when given, is the already-consumed first request
     * (read earlier just to decide CONNECT vs plain HTTP). */
    private fun relayLoop(
        clientIn: InputStream,
        clientOut: OutputStream,
        scheme: String,
        tlsHost: String?,
        tlsPort: Int?,
        firstMessage: HttpMessageUtil.ParsedMessage?,
    ) {
        var pending = firstMessage
        while (running) {
            val reqMsg = pending ?: HttpMessageUtil.readMessage(clientIn) ?: return
            pending = null

            val reqParts = reqMsg.startLine.split(" ", limit = 3)
            if (reqParts.size < 2) return
            val method = reqParts[0]
            val requestUri = reqParts[1]
            val (host, port, path) = resolveTarget(requestUri, reqMsg.headers, tlsHost, tlsPort)

            val startNs = System.nanoTime()
            var status = 0
            var statusText = ""
            var respHeaders: List<Pair<String, String>> = emptyList()
            var respBody = ByteArray(0)
            var respTruncated = false
            var error: String? = null

            try {
                val upstream: Socket = if (scheme == "https") {
                    trustAllSslSocketFactory.createSocket(host, port)
                } else {
                    Socket(host, port)
                }
                upstream.soTimeout = 30_000
                try {
                    val outHeaders = reqMsg.headers.filterNot {
                        it.first.equals("Proxy-Connection", true) || it.first.equals("Connection", true)
                    } + ("Connection" to "close")
                    HttpMessageUtil.writeMessage(
                        upstream.getOutputStream(),
                        "$method $path HTTP/1.1",
                        HttpMessageUtil.framingHeadersFor(outHeaders, reqMsg.body.size),
                        reqMsg.body,
                    )
                    val respMsg = HttpMessageUtil.readMessage(upstream.getInputStream())
                    if (respMsg != null) {
                        val statusParts = respMsg.startLine.split(" ", limit = 3)
                        status = statusParts.getOrNull(1)?.toIntOrNull() ?: 0
                        statusText = statusParts.getOrNull(2) ?: ""
                        respHeaders = respMsg.headers
                        respBody = respMsg.body
                        respTruncated = respMsg.bodyTruncated
                    } else {
                        error = "No response from upstream"
                    }
                } finally {
                    upstream.close()
                }
            } catch (e: Exception) {
                error = e.message ?: e.javaClass.simpleName
            }

            val statusLine = if (status != 0) "HTTP/1.1 $status $statusText" else "HTTP/1.1 502 Bad Gateway"
            val respHeadersOut = HttpMessageUtil.framingHeadersFor(respHeaders, respBody.size) +
                ("Connection" to "keep-alive")
            try {
                HttpMessageUtil.writeMessage(clientOut, statusLine, respHeadersOut, respBody)
            } catch (e: Exception) {
                return // client's gone; nothing left to relay to
            }

            val durationMs = (System.nanoTime() - startNs) / 1_000_000
            ProxyHistoryStore.add(
                CapturedExchange(
                    id = ProxyHistoryStore.nextId(),
                    timestampMs = System.currentTimeMillis(),
                    scheme = scheme, host = host, method = method, path = path,
                    requestHeaders = reqMsg.headers, requestBody = reqMsg.body,
                    requestBodyTruncated = reqMsg.bodyTruncated,
                    status = status, statusText = statusText, responseHeaders = respHeaders,
                    responseBody = respBody, responseBodyTruncated = respTruncated,
                    durationMs = durationMs, error = error,
                ),
            )

            if (error != null) return // don't keep looping a client past a broken exchange
        }
    }

    /** Absolute-URI proxy form (`GET http://host/path`, used for plain HTTP
     * through an explicit proxy) vs. relative form (`GET /path` + Host
     * header, what a CONNECT-tunneled TLS session actually carries). */
    private fun resolveTarget(
        requestUri: String,
        headers: List<Pair<String, String>>,
        fallbackHost: String?,
        fallbackPort: Int?,
    ): Triple<String, Int, String> {
        if (requestUri.startsWith("http://", true) || requestUri.startsWith("https://", true)) {
            val uri = URI(requestUri)
            val host = uri.host ?: fallbackHost ?: "unknown"
            val port = if (uri.port != -1) uri.port else if (uri.scheme.equals("https", true)) 443 else 80
            val path = uri.rawPath.ifEmpty { "/" } + (uri.rawQuery?.let { "?$it" } ?: "")
            return Triple(host, port, path)
        }
        val hostHeader = HttpMessageUtil.header(headers, "Host")
        val host = fallbackHost ?: hostHeader?.substringBefore(":") ?: "unknown"
        val port = fallbackPort ?: hostHeader?.substringAfter(":", "")?.toIntOrNull()
            ?: if (fallbackHost != null) 443 else 80
        return Triple(host, port, requestUri)
    }

    private fun buildServerSslContext(host: String): SSLContext {
        val (leafCert, leafKey) = certAuthority.leafFor(host)
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("leaf", leafKey, "strobes".toCharArray(), arrayOf<X509Certificate>(leafCert, certAuthority.caCert))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "strobes".toCharArray())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        return ctx
    }

    /** Upstream (real-server) leg: we're not evaluating whether the ORIGIN
     * server's cert is trustworthy, only relaying — the interesting security
     * question (does the app being tested validate certs) lives entirely on
     * the client-facing leg, which presents our real, freshly-signed leaf. */
    private val trustAllSslSocketFactory by lazy {
        val trustAll = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            },
        )
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        ctx.socketFactory
    }
}
