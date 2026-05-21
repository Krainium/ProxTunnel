package com.krainium.proxtunnel

import android.util.Log
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Establishes a proxy tunnel.
 *
 * SOCKS5 mode auto-falls-back to HTTP CONNECT when the SOCKS5 greeting is
 * rejected (e.g. the proxy is actually an HTTP proxy).  This makes the app
 * work even when the user selects the wrong protocol mode.
 *
 * Error messages are prefixed with a phase tag so the UI can tell the user
 * exactly where things went wrong:
 *   "socks5-greeting: …"  → proxy not SOCKS5, try HTTP mode
 *   "socks5-connect: …"   → proxy accepted SOCKS5 but blocked the destination
 *   "http-connect: …"     → HTTP proxy rejected the CONNECT request
 */
object ProxyClient {

    private const val TAG     = "ProxyClient"
    private const val TIMEOUT = 15_000

    fun connect(
        vpn: ProxyVpnService,
        config: ProxyConfig,
        dstIp: ByteArray,
        dstPort: Int,
        hostname: String? = null
    ): Socket = when (config.type) {
        ProxyType.SOCKS5 -> connectWithSocks5Fallback(vpn, config, dstIp, dstPort, hostname)
        ProxyType.HTTP   -> connectHttpWithFallback(vpn, config, dstIp, dstPort, hostname)
        ProxyType.SSH_WS -> connectWithSocks5Fallback(vpn, config, dstIp, dstPort, hostname)
    }

    // ── SOCKS5 with HTTP auto-fallback ────────────────────────────────────────

    private fun connectWithSocks5Fallback(
        vpn: ProxyVpnService,
        config: ProxyConfig,
        dstIp: ByteArray,
        dstPort: Int,
        hostname: String?
    ): Socket {
        val sock = protectedSocket(vpn, config)
        return try {
            connectSocks5(sock, dstIp, dstPort, hostname, config)
        } catch (e: IOException) {
            val msg = e.message ?: ""
            // If the SOCKS5 greeting was rejected (connection reset / wrong protocol),
            // silently retry using HTTP CONNECT — the proxy is likely HTTP only.
            if ("socks5-greeting" in msg) {
                Log.w(TAG, "SOCKS5 greeting failed ($msg) — retrying as HTTP CONNECT")
                try { sock.close() } catch (_: Exception) {}
                connectHttpWithFallback(vpn, config, dstIp, dstPort, hostname)
            } else {
                throw e
            }
        }
    }

    // ── SOCKS5 ────────────────────────────────────────────────────────────────

    private fun connectSocks5(
        sock: Socket,
        dstIp: ByteArray,
        dstPort: Int,
        hostname: String?,
        config: ProxyConfig
    ): Socket {
        val out = sock.getOutputStream()
        val inp = DataInputStream(sock.getInputStream())

        // Phase 1 — greeting
        out.write(if (config.hasAuth) byteArrayOf(0x05, 0x02, 0x00, 0x02)
                  else                byteArrayOf(0x05, 0x01, 0x00))
        out.flush()

        val gr = ByteArray(2)
        try { inp.readFully(gr) }
        catch (e: Exception) {
            sock.close()
            throw IOException("socks5-greeting: ${e.message}")
        }
        if (gr[0] != 0x05.toByte()) {
            sock.close()
            throw IOException("socks5-greeting: not SOCKS5 (server sent 0x${"%02x".format(gr[0])})")
        }
        if (gr[1] == 0xFF.toByte()) {
            sock.close()
            throw IOException("socks5-greeting: no auth method accepted — add credentials?")
        }

        // Phase 2 — optional username/password auth
        if (gr[1] == 0x02.toByte()) {
            val user = config.username.toByteArray(Charsets.UTF_8)
            val pass = config.password.toByteArray(Charsets.UTF_8)
            val auth = ByteArray(3 + user.size + pass.size)
            auth[0] = 0x01; auth[1] = user.size.toByte()
            user.copyInto(auth, 2)
            auth[2 + user.size] = pass.size.toByte()
            pass.copyInto(auth, 3 + user.size)
            out.write(auth); out.flush()

            val ar = ByteArray(2)
            try { inp.readFully(ar) }
            catch (e: Exception) { sock.close(); throw IOException("socks5-auth: ${e.message}") }
            if (ar[1] != 0x00.toByte()) {
                sock.close()
                throw IOException("socks5-auth: credentials rejected (status=${ar[1].toInt() and 0xFF})")
            }
        }

        // Phase 3 — CONNECT request
        val port2 = byteArrayOf((dstPort shr 8).toByte(), (dstPort and 0xFF).toByte())

        if (hostname != null) {
            // ATYP=0x03 domain — proxy resolves the name, enabling correct SNI routing
            val nb = hostname.toByteArray(Charsets.UTF_8)
            if (nb.size > 255) throw IOException("socks5-connect: hostname too long")
            val req = ByteArray(7 + nb.size)
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00  // VER CMD RSV
            req[3] = 0x03                                   // ATYP=domain
            req[4] = nb.size.toByte()
            nb.copyInto(req, 5)
            port2.copyInto(req, 5 + nb.size)
            out.write(req)
        } else {
            // ATYP=0x01 IPv4 — used for direct (non-FakeDns) destinations
            val req = ByteArray(10)
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01
            dstIp.copyInto(req, 4); port2.copyInto(req, 8)
            out.write(req)
        }
        out.flush()

        val resp = ByteArray(4)
        try { inp.readFully(resp) }
        catch (e: Exception) { sock.close(); throw IOException("socks5-connect: ${e.message}") }

        if (resp[0] != 0x05.toByte()) { sock.close(); throw IOException("socks5-connect: bad version") }
        if (resp[1] != 0x00.toByte()) {
            sock.close()
            val code = resp[1].toInt() and 0xFF
            val reason = when (code) {
                1 -> "general failure"
                2 -> "connection not allowed"
                3 -> "network unreachable"
                4 -> "host unreachable"
                5 -> "connection refused"
                6 -> "TTL expired"
                7 -> "command not supported"
                8 -> "address type not supported"
                else -> "code=$code"
            }
            throw IOException("socks5-connect: rejected ($reason)")
        }

        // Drain the bound-address field so the stream is positioned at data
        when (resp[3].toInt() and 0xFF) {
            0x01 -> { val t = ByteArray(6);  inp.readFully(t) }   // IPv4 + port
            0x04 -> { val t = ByteArray(18); inp.readFully(t) }   // IPv6 + port
            0x03 -> { val len = inp.read(); val t = ByteArray(len + 2); inp.readFully(t) }
            else -> {}
        }

        Log.d(TAG, "SOCKS5 OK → ${hostname ?: PacketUtils.ipToString(dstIp)}:$dstPort")
        return sock
    }

    // ── HTTP CONNECT ──────────────────────────────────────────────────────────
    // Tries two formats in order:
    //   1. HTTP/1.1 with Host header  (RFC 7231 §4.3.6)
    //   2. HTTP/1.0 bare (no extra headers) — accepted by Squid, nginx, HAProxy
    // If the proxy RSTs both, the last IOException is re-thrown.

    private fun connectHttp(
        sock: Socket,
        dstIp: ByteArray,
        dstPort: Int,
        hostname: String?,
        config: ProxyConfig,
        useHttp10: Boolean = false
    ): Socket {
        val target = if (hostname != null) "$hostname:$dstPort"
                     else "${PacketUtils.ipToString(dstIp)}:$dstPort"

        val sb = StringBuilder()
        if (useHttp10) {
            // Bare HTTP/1.0 — maximally compatible fallback
            sb.append("CONNECT $target HTTP/1.0\r\n")
            if (config.hasAuth) {
                val cred = android.util.Base64.encodeToString(
                    "${config.username}:${config.password}".toByteArray(Charsets.UTF_8),
                    android.util.Base64.NO_WRAP)
                sb.append("Proxy-Authorization: Basic $cred\r\n")
            }
        } else {
            // Standard HTTP/1.1 with minimal headers
            sb.append("CONNECT $target HTTP/1.1\r\n")
            sb.append("Host: $target\r\n")
            if (config.hasAuth) {
                val cred = android.util.Base64.encodeToString(
                    "${config.username}:${config.password}".toByteArray(Charsets.UTF_8),
                    android.util.Base64.NO_WRAP)
                sb.append("Proxy-Authorization: Basic $cred\r\n")
            }
        }
        sb.append("\r\n")

        val out = sock.getOutputStream()
        out.write(sb.toString().toByteArray(Charsets.US_ASCII))
        out.flush()

        val inp = sock.getInputStream()
        val statusLine = try { readLine(inp) }
        catch (e: Exception) {
            sock.close()
            if (!useHttp10) {
                // HTTP/1.1 was RST'd — retry as bare HTTP/1.0 on a fresh socket
                Log.w(TAG, "HTTP/1.1 CONNECT RST for $target — retrying HTTP/1.0")
                throw IOException("__retry_http10__:${e.message}")
            }
            throw IOException("http-connect: ${e.message}")
        }

        Log.d(TAG, "HTTP${if (useHttp10) "/1.0" else "/1.1"} CONNECT ← $statusLine")

        if (statusLine.isEmpty()) {
            // Proxy closed the connection without sending a response (RST or EOF)
            sock.close()
            if (!useHttp10) {
                Log.w(TAG, "HTTP/1.1 CONNECT empty response for $target — retrying HTTP/1.0")
                throw IOException("__retry_http10__:empty response")
            }
            throw IOException("http-connect: empty response from proxy")
        }

        if (!statusLine.contains("200")) {
            sock.close()
            throw IOException("http-connect: $statusLine")
        }
        while (readLine(inp).isNotEmpty()) { /* drain headers */ }

        Log.d(TAG, "HTTP OK → $target")
        return sock
    }

    private fun connectHttpWithFallback(
        vpn: ProxyVpnService,
        config: ProxyConfig,
        dstIp: ByteArray,
        dstPort: Int,
        hostname: String?
    ): Socket {
        val sock11 = protectedSocket(vpn, config)
        return try {
            connectHttp(sock11, dstIp, dstPort, hostname, config, useHttp10 = false)
        } catch (e: IOException) {
            try { sock11.close() } catch (_: Exception) {}
            if ("__retry_http10__" in (e.message ?: "")) {
                val sock10 = protectedSocket(vpn, config)
                try {
                    connectHttp(sock10, dstIp, dstPort, hostname, config, useHttp10 = true)
                } catch (e2: IOException) {
                    try { sock10.close() } catch (_: Exception) {}
                    throw e2
                }
            } else {
                throw e
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun protectedSocket(vpn: ProxyVpnService, config: ProxyConfig): Socket {
        val s = Socket()
        // Android's Socket() is lazily initialised — the OS-level file descriptor is NOT
        // created until the first syscall (bind/connect).  VpnService.protect(Socket) works
        // by binding the fd to the underlying network; if the fd doesn't exist yet it returns
        // false silently.  Calling bind(0) before protect() forces the OS socket to be
        // created immediately, giving protect() a valid fd to work with.
        try { s.bind(InetSocketAddress(0)) } catch (_: Exception) {}

        // Retry protect() up to 3 times — on heavily loaded devices it can fail transiently.
        var isProtected = false
        for (attempt in 1..3) {
            if (vpn.protect(s)) { isProtected = true; break }
            Log.w(TAG, "protect() attempt $attempt failed, retrying…")
            Thread.sleep(50)
        }
        if (!isProtected) {
            try { s.close() } catch (_: Exception) {}
            throw IOException("VpnService.protect() failed — cannot create proxy socket outside VPN")
        }

        s.soTimeout = TIMEOUT

        // Performance tuning — applied before connect() so the kernel uses them immediately.
        // tcpNoDelay: disable Nagle's algorithm → individual small packets (TLS handshake,
        //   HTTP headers) are sent instantly instead of waiting to be coalesced.
        // Buffer sizes: 256 KB kernel socket buffers reduce copy overhead for bulk transfers.
        runCatching { s.setTcpNoDelay(true) }
        runCatching { s.setReceiveBufferSize(262144) }
        runCatching { s.setSendBufferSize(262144) }

        s.connect(InetSocketAddress(config.host, config.port), TIMEOUT)
        return s
    }

    private fun readLine(inp: InputStream): String {
        val sb = StringBuilder()
        var prev = -1
        while (true) {
            val c = inp.read()
            if (c < 0) break
            if (c == '\n'.code && prev == '\r'.code) {
                if (sb.isNotEmpty()) sb.deleteCharAt(sb.lastIndex)
                break
            }
            sb.append(c.toChar())
            prev = c
        }
        return sb.toString()
    }
}
