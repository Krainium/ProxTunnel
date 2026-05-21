package com.krainium.proxtunnel

import android.net.VpnService
import android.util.Log
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import java.io.*
import java.net.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory as JSSLSocketFactory

/**
 * SSH-over-HTTP-upgrade tunnel routed through Cloudflare CDN.
 *
 * The phone connects to ws.netfragile.store:443 (Cloudflare IP — the ISP allows it
 * because WhatsApp uses Cloudflare).  An HTTP WebSocket-style upgrade request is sent
 * to /ssh-ws.  After the 101 response the connection carries raw SSH protocol.
 *
 * A built-in SOCKS5 server is started on 127.0.0.1:[localPort].
 * ProxyVpnService connects all tunnelled traffic to this SOCKS5 server.
 * Each SOCKS5 connection maps to one JSch direct-tcpip channel through the SSH session.
 *
 * No Termux required.  No external scripts.  Everything runs inside ProxTunnel.
 */
class SshWsTunnel(
    private val vpnService: VpnService,
    val wsHost: String  = "ws.netfragile.store",
    val wsPort: Int     = 443,
    val wsPath: String  = "/ssh-ws",
    val sshUser: String = "root",
    val sshPass: String = "",
    val localPort: Int  = 11090
) {
    companion object {
        private const val TAG          = "SshWsTunnel"
        private const val CONN_TIMEOUT = 30_000
        private const val CHAN_TIMEOUT = 15_000
        private const val BUF          = 16_384

        // Max concurrent SSH channels — limits thread count and prevents OOM
        private const val MAX_CHANNELS = 24

        // WhatsApp-style headers make DPI see this as WhatsApp Web traffic
        private val WA_HEADERS = listOf(
            "User-Agent: WhatsApp/2.24.8.78 A",
            "Origin: https://web.whatsapp.com"
        )
    }

    @Volatile var isConnected = false
        private set

    @Volatile private var session: Session? = null
    @Volatile private var rawSocket: SSLSocket? = null
    private var socks5Server: ServerSocket? = null
    private val running       = AtomicBoolean(false)

    // Bounded thread pool: keeps thread count predictable and prevents OOM.
    // MAX_CHANNELS * 2 (each channel needs 2 threads) + 4 for accept + overhead.
    private val executor = ThreadPoolExecutor(
        4, MAX_CHANNELS * 2 + 8,
        60L, TimeUnit.SECONDS,
        LinkedBlockingQueue(MAX_CHANNELS * 4),
        ThreadPoolExecutor.CallerRunsPolicy()   // back-pressure instead of OOM
    )

    // Semaphore gates how many SSH channels may be open simultaneously.
    private val channelSlots = Semaphore(MAX_CHANNELS)

    // ── Public API ─────────────────────────────────────────────────────────────

    /** Blocks until SSH is fully authenticated. Throws on failure. */
    @Throws(Exception::class)
    fun connect() {
        Log.i(TAG, "Connecting → $wsHost:$wsPort$wsPath")

        val sock    = openProtectedSocket()
        rawSocket   = sock
        val streams = doHttpUpgrade(sock)

        val jsch = JSch()
        val sess = jsch.getSession(sshUser, wsHost, 22)
        sess.setPassword(sshPass)
        sess.setConfig("StrictHostKeyChecking",     "no")
        sess.setConfig("PreferredAuthentications",  "password")
        // Send a keepalive every 25 s so the server never sees an idle connection
        sess.setConfig("ServerAliveInterval",       "25")
        sess.setConfig("ServerAliveCountMax",       "6")
        // Disable compression — simpler and faster on mobile
        sess.setConfig("compression.s2c",           "none")
        sess.setConfig("compression.c2s",           "none")
        sess.setTimeout(CONN_TIMEOUT)
        sess.setSocketFactory(RawStreamFactory(sock, streams.first, streams.second))
        sess.connect(CONN_TIMEOUT)

        session     = sess
        isConnected = true
        Log.i(TAG, "SSH authenticated as $sshUser — starting internal SOCKS5 on port $localPort")
        startSocks5Server()
    }

    fun disconnect() {
        running.set(false)
        isConnected = false
        try { socks5Server?.close() } catch (_: Exception) {}
        try { session?.disconnect()  } catch (_: Exception) {}
        try { rawSocket?.close()     } catch (_: Exception) {}
        executor.shutdownNow()
    }

    // ── SSL + VPN-protected socket ─────────────────────────────────────────────

    private fun openProtectedSocket(): SSLSocket {
        val plain = Socket()
        try { plain.bind(InetSocketAddress(0)) } catch (_: Exception) {}
        for (i in 1..3) {
            if (vpnService.protect(plain)) break
            Thread.sleep(50)
        }
        plain.connect(InetSocketAddress(wsHost, wsPort), CONN_TIMEOUT)

        val ssl = (JSSLSocketFactory.getDefault() as JSSLSocketFactory)
            .createSocket(plain, wsHost, wsPort, true) as SSLSocket
        ssl.startHandshake()
        Log.d(TAG, "TLS handshake OK")
        return ssl
    }

    // ── HTTP upgrade ───────────────────────────────────────────────────────────

    private fun doHttpUpgrade(sock: SSLSocket): Pair<InputStream, OutputStream> {
        val out = sock.outputStream
        val inp = sock.inputStream

        val req = buildString {
            append("GET $wsPath HTTP/1.1\r\n")
            append("Host: $wsHost\r\n")
            for (h in WA_HEADERS) append("$h\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("\r\n")
        }
        out.write(req.toByteArray(Charsets.US_ASCII))
        out.flush()

        // Read response byte-by-byte to avoid consuming SSH data
        val resp = StringBuilder()
        val one  = ByteArray(1)
        while (!resp.endsWith("\r\n\r\n")) {
            val n = inp.read(one)
            if (n < 0) throw IOException("Connection closed during HTTP upgrade")
            resp.append(one[0].toInt().toChar())
        }
        if (!resp.contains("101")) {
            throw IOException("HTTP upgrade failed: ${resp.take(120)}")
        }
        Log.d(TAG, "HTTP 101 OK — SSH stream live")
        return Pair(inp, out)
    }

    // ── JSch SocketFactory (wraps the already-connected SSL streams) ────────────

    private inner class RawStreamFactory(
        private val sock: Socket,
        private val inp:  InputStream,
        private val out:  OutputStream
    ) : SocketFactory {
        override fun createSocket(host: String, port: Int): Socket =
            FakeSocket(sock, inp, out)
        override fun getInputStream(s: Socket):  InputStream  = inp
        override fun getOutputStream(s: Socket): OutputStream = out
    }

    /**
     * A Socket that delegates all I/O to the already-connected SSL streams.
     *
     * JSch calls several Socket methods after createSocket(); we must override
     * every one it may touch to prevent SocketException on the unconnected base
     * Socket, and to accurately reflect the real SSL socket's lifecycle.
     */
    private inner class FakeSocket(
        private val backing: Socket,
        private val inp: InputStream,
        private val out: OutputStream
    ) : Socket() {
        override fun getInputStream()             = inp
        override fun getOutputStream()            = out
        override fun isConnected()                = !backing.isClosed
        override fun isClosed()                   = backing.isClosed
        override fun isInputShutdown()            = false
        override fun isOutputShutdown()           = false
        override fun isBound()                    = true
        override fun getInetAddress(): InetAddress = try {
            InetAddress.getByName(wsHost)
        } catch (_: Exception) { InetAddress.getByName("0.0.0.0") }
        override fun getLocalAddress(): InetAddress = InetAddress.getByName("127.0.0.1")
        override fun getPort()                    = wsPort
        override fun getLocalPort()               = 0
        override fun close()                      { try { backing.close() } catch (_: Exception) {} }
        override fun setTcpNoDelay(on: Boolean)   { /* no-op — socket is already connected */ }
        override fun setKeepAlive(on: Boolean)    { /* no-op */ }
        override fun setReuseAddress(on: Boolean) { /* no-op */ }
        override fun setSendBufferSize(sz: Int)   { /* no-op */ }
        override fun setReceiveBufferSize(sz: Int){ /* no-op */ }
        override fun setSoLinger(on: Boolean, l: Int) { /* no-op */ }
        override fun setOOBInline(on: Boolean)    { /* no-op */ }
        override fun setSoTimeout(t: Int) {
            try { backing.soTimeout = t } catch (_: Exception) {}
        }
        override fun getSoTimeout() =
            try { backing.soTimeout } catch (_: Exception) { 0 }
    }

    // ── Internal SOCKS5 server ─────────────────────────────────────────────────

    private fun startSocks5Server() {
        val ss = ServerSocket(localPort, 256, InetAddress.getByName("127.0.0.1"))
        socks5Server = ss
        running.set(true)
        executor.submit {
            while (running.get() && !ss.isClosed) {
                try {
                    val client = ss.accept()
                    executor.submit { handleSocks5(client) }
                } catch (_: IOException) {
                    if (!running.get()) break
                } catch (_: RejectedExecutionException) {
                    // Executor is saturated; refuse the connection
                    Log.w(TAG, "Executor full — dropping incoming SOCKS5 connection")
                }
            }
        }
    }

    private fun handleSocks5(client: Socket) {
        // Acquire a channel slot — prevents OOM from unbounded channel creation
        if (!channelSlots.tryAcquire(CHAN_TIMEOUT.toLong(), TimeUnit.MILLISECONDS)) {
            Log.w(TAG, "No free channel slots — rejecting connection")
            try { client.close() } catch (_: Exception) {}
            return
        }
        try {
            client.soTimeout = 15_000
            val inp = DataInputStream(client.getInputStream())
            val out = client.getOutputStream()

            // SOCKS5 auth negotiation
            if (inp.read() != 5) { client.close(); return }
            val nMethods = inp.read()
            if (nMethods > 0) { val m = ByteArray(nMethods); inp.readFully(m) }
            out.write(byteArrayOf(5, 0)); out.flush()   // no-auth selected

            // SOCKS5 CONNECT request
            val hdr = ByteArray(4); inp.readFully(hdr)
            if (hdr[0].toInt() != 5 || hdr[1].toInt() != 1) { client.close(); return }
            val host = when (hdr[3].toInt() and 0xFF) {
                1 -> {
                    val b = ByteArray(4); inp.readFully(b)
                    b.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                3 -> {
                    val n = inp.read(); val b = ByteArray(n); inp.readFully(b); String(b)
                }
                4 -> {
                    val b = ByteArray(16); inp.readFully(b)
                    Inet6Address.getByAddress(b).hostAddress ?: ""
                }
                else -> { client.close(); return }
            }
            val port = ((inp.read() and 0xFF) shl 8) or (inp.read() and 0xFF)

            // Open JSch direct-tcpip channel
            val sess = session ?: run { client.close(); return }
            if (!sess.isConnected) { client.close(); return }

            val ch = sess.openChannel("direct-tcpip") as ChannelDirectTCPIP
            ch.setHost(host); ch.setPort(port)
            ch.setOrgIPAddress("127.0.0.1"); ch.setOrgPort(0)

            // Input stream MUST be obtained before connect() to avoid data loss
            val chIn  = ch.inputStream
            val chOut = ch.outputStream
            ch.connect(CHAN_TIMEOUT)

            // Send SOCKS5 success (ATYP=IPv4, addr=0.0.0.0, port=0)
            out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); out.flush()
            client.soTimeout = 0
            Log.d(TAG, "SSH channel open → $host:$port")

            val done = AtomicBoolean(false)

            // client → SSH (relay thread)
            executor.submit {
                val buf = ByteArray(BUF)
                try {
                    while (!done.get()) {
                        val n = client.getInputStream().read(buf)
                        if (n < 0) break
                        chOut.write(buf, 0, n); chOut.flush()
                    }
                } catch (_: Exception) {}
                finally {
                    done.set(true)
                    try { ch.disconnect() } catch (_: Exception) {}
                }
            }

            // SSH → client (this handleSocks5 thread)
            val buf = ByteArray(BUF)
            try {
                while (!done.get()) {
                    val n = chIn.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n); out.flush()
                }
            } catch (_: Exception) {}
            finally {
                done.set(true)
                try { ch.disconnect() } catch (_: Exception) {}
            }

        } catch (e: Exception) {
            Log.w(TAG, "SOCKS5 channel error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            channelSlots.release()
            try { client.close() } catch (_: Exception) {}
        }
    }
}
