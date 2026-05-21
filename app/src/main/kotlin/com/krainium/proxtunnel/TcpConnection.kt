package com.krainium.proxtunnel

import android.util.Log
import java.io.IOException
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Represents a single proxied TCP connection.
 *
 * [hostname] is the real domain name resolved by FakeDns (null for direct-IP destinations).
 * It is passed to ProxyClient so the SOCKS5/HTTP-CONNECT request uses the hostname rather
 * than the raw IP — required by most production proxies for SNI routing and filtering.
 */
class TcpConnection(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    private val tunOut: OutputStream,
    private val vpn: ProxyVpnService,
    private val config: ProxyConfig,
    private val hostname: String? = null   // real hostname from FakeDns, or null
) {
    companion object {
        private const val TAG    = "TcpConnection"
        private const val BUF_SZ = 32768   // 32 KB — halves iteration count for bulk transfers
    }

    private val closed = AtomicBoolean(false)
    private var proxySocket: Socket? = null

    @Volatile var localSeq:  Long = (Math.random() * 0x7FFFFFFFL).toLong()
    @Volatile var remoteSeq: Long = 0L

    private val pendingFromDevice = ArrayDeque<ByteArray>()
    private val pendingLock       = Object()

    // ── Called from the packet loop ───────────────────────────────────────────

    fun onSyn(deviceSeq: Long) {
        remoteSeq = PacketUtils.seqAdd(deviceSeq, 1)

        val synAck = PacketUtils.buildTcpPacket(
            srcIp = dstIp, dstIp = srcIp,
            srcPort = dstPort, dstPort = srcPort,
            seq = localSeq, ack = remoteSeq,
            flags = PacketUtils.FLAG_SYN or PacketUtils.FLAG_ACK
        )
        localSeq = PacketUtils.seqAdd(localSeq, 1)
        writeTun(synAck)

        Thread({ connectToProxy() }, "Conn-$srcPort").start()
    }

    fun onData(data: ByteArray, deviceSeq: Long) {
        if (closed.get()) return
        remoteSeq = PacketUtils.seqAdd(deviceSeq, data.size)

        val ack = PacketUtils.buildTcpPacket(
            srcIp = dstIp, dstIp = srcIp,
            srcPort = dstPort, dstPort = srcPort,
            seq = localSeq, ack = remoteSeq,
            flags = PacketUtils.FLAG_ACK
        )
        writeTun(ack)

        val sock = proxySocket
        if (sock != null && !sock.isClosed) {
            try {
                sock.getOutputStream().apply { write(data); flush() }
                ProxyVpnService.bytesUploaded.addAndGet(data.size.toLong())
            } catch (e: IOException) {
                Log.w(TAG, "Proxy write failed: ${e.message}")
                close()
            }
        } else {
            synchronized(pendingLock) { pendingFromDevice.add(data) }
        }
    }

    fun onFin(deviceSeq: Long) {
        remoteSeq = PacketUtils.seqAdd(deviceSeq, 1)
        val finAck = PacketUtils.buildTcpPacket(
            srcIp = dstIp, dstIp = srcIp,
            srcPort = dstPort, dstPort = srcPort,
            seq = localSeq, ack = remoteSeq,
            flags = PacketUtils.FLAG_FIN or PacketUtils.FLAG_ACK
        )
        localSeq = PacketUtils.seqAdd(localSeq, 1)
        writeTun(finAck)
        close()
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private fun connectToProxy() {
        try {
            // Use the real hostname (from FakeDns) when available so proxies can
            // use SNI routing.  Fall back to the raw IP for direct connections.
            val sock = ProxyClient.connect(vpn, config, dstIp, dstPort, hostname)

            // Drain any data that arrived before the proxy handshake completed
            val pending: List<ByteArray>
            synchronized(pendingLock) {
                // Set socket BEFORE clearing the queue so concurrent onData() calls
                // that race past the null-check use the socket (not the queue).
                proxySocket = sock
                pending = pendingFromDevice.toList()
                pendingFromDevice.clear()
            }

            val out = sock.getOutputStream()
            for (chunk in pending) {
                out.write(chunk)
                ProxyVpnService.bytesUploaded.addAndGet(chunk.size.toLong())
            }
            if (pending.isNotEmpty()) out.flush()

            forwardProxyToDevice(sock)
        } catch (e: Exception) {
            val raw  = e.message ?: e.javaClass.simpleName
            val dest = "${hostname ?: PacketUtils.ipToString(dstIp)}:$dstPort"
            // Provide actionable hints based on the phase tag injected by ProxyClient
            val hint = when {
                "socks5-greeting" in raw -> "$dest — SOCKS5 greeting rejected (proxy may be HTTP)"
                "socks5-auth"     in raw -> "$dest — $raw"
                "socks5-connect"  in raw -> "$dest — $raw"
                "http-connect"    in raw -> "$dest — $raw"
                else                     -> "$dest — $raw"
            }
            Log.w(TAG, "Proxy connect failed: $hint")
            ProxyVpnService.proxyErrors.incrementAndGet()
            ProxyVpnService.lastError = hint
            sendRst()
            close()
        }
    }

    private fun forwardProxyToDevice(sock: Socket) {
        val buf = ByteArray(BUF_SZ)
        try {
            val inp = sock.getInputStream()
            while (!closed.get()) {
                val n = inp.read(buf)
                if (n < 0) break
                if (n == 0) continue

                val data = buf.copyOf(n)
                ProxyVpnService.bytesDownloaded.addAndGet(n.toLong())

                val pkt = PacketUtils.buildTcpPacket(
                    srcIp = dstIp, dstIp = srcIp,
                    srcPort = dstPort, dstPort = srcPort,
                    seq = localSeq, ack = remoteSeq,
                    flags = PacketUtils.FLAG_PSH or PacketUtils.FLAG_ACK,
                    data = data
                )
                localSeq = PacketUtils.seqAdd(localSeq, n)
                writeTun(pkt)
            }
        } catch (e: IOException) {
            if (!closed.get()) Log.d(TAG, "Proxy read ended: ${e.message}")
        } finally {
            if (!closed.get()) {
                val fin = PacketUtils.buildTcpPacket(
                    srcIp = dstIp, dstIp = srcIp,
                    srcPort = dstPort, dstPort = srcPort,
                    seq = localSeq, ack = remoteSeq,
                    flags = PacketUtils.FLAG_FIN or PacketUtils.FLAG_ACK
                )
                localSeq = PacketUtils.seqAdd(localSeq, 1)
                writeTun(fin)
                close()
            }
        }
    }

    private fun sendRst() {
        writeTun(PacketUtils.buildRstPacket(
            srcIp = dstIp, dstIp = srcIp,
            srcPort = dstPort, dstPort = srcPort, seq = localSeq
        ))
    }

    fun close() {
        if (closed.getAndSet(true)) return
        try { proxySocket?.close() } catch (_: Exception) {}
    }

    private fun writeTun(pkt: ByteArray) {
        try { synchronized(tunOut) { tunOut.write(pkt) } }
        catch (e: IOException) { Log.w(TAG, "TUN write failed: ${e.message}") }
    }
}
