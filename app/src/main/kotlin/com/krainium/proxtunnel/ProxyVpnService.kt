package com.krainium.proxtunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.pm.ServiceInfo
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class ProxyVpnService : VpnService() {

    companion object {
        private const val TAG             = "ProxyVpnService"
        private const val CHANNEL_ID      = "proxtunnel_vpn"
        private const val NOTIFICATION_ID = 1
        // VPN tun address — /24 is more compatible than /32 on some ROMs
        private const val VPN_ADDRESS     = "10.200.0.1"
        // Fake-DNS routes: 198.18.0.0/15 is the RFC 2544 test range;
        // no real host will ever be in it, so routing it into the VPN is safe.
        private const val FAKE_DNS_ROUTE  = "198.18.0.0"
        private const val FAKE_DNS_PREFIX = 15          // 198.18.0.0 – 198.19.255.255
        // Virtual DNS server IP advertised to apps — answered entirely in-process
        private const val VIRTUAL_DNS     = "10.200.0.2"
        private const val BUF_SIZE        = 32768

        const val ACTION_START = "com.krainium.proxtunnel.START"
        const val ACTION_STOP  = "com.krainium.proxtunnel.STOP"
        const val EXTRA_CONFIG = "config_type"
        const val EXTRA_HOST   = "host"
        const val EXTRA_PORT   = "port"
        const val EXTRA_USER   = "username"
        const val EXTRA_PASS   = "password"

        @Volatile var isRunning = false
            private set

        var onStateChange: ((Boolean) -> Unit)? = null

        val bytesUploaded   = AtomicLong(0)
        val bytesDownloaded = AtomicLong(0)

        // Diagnostic counters — displayed in MainActivity for live debugging
        val pktsRead    = AtomicLong(0)
        val dnsAnswered = AtomicLong(0)
        val tcpSynCount = AtomicLong(0)
        val proxyErrors = AtomicLong(0)
        @Volatile var lastError: String = ""
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running     = AtomicBoolean(false)
    private val connections = ConcurrentHashMap<Int, TcpConnection>()
    private var readerThread: Thread? = null
    private lateinit var config: ProxyConfig
    private var sshTunnel: SshWsTunnel? = null

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate() { super.onCreate(); createNotificationChannel() }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopVpn(); return START_NOT_STICKY }

        val rawType = intent?.getStringExtra(EXTRA_CONFIG) ?: "SOCKS5"
        val type    = try { ProxyType.valueOf(rawType) } catch (_: Exception) { ProxyType.SOCKS5 }

        if (type == ProxyType.SSH_WS) {
            // SSH_WS mode: connect the tunnel first, then start VPN using the internal SOCKS5
            val wsHost  = intent?.getStringExtra(EXTRA_HOST)  ?: "ws.netfragile.store"
            val wsPort  = intent?.getIntExtra(EXTRA_PORT, 443) ?: 443
            val sshUser = intent?.getStringExtra(EXTRA_USER)  ?: "root"
            val sshPass = intent?.getStringExtra(EXTRA_PASS)  ?: ""

            val tunnel = SshWsTunnel(
                vpnService = this,
                wsHost     = wsHost,
                wsPort     = wsPort,
                sshUser    = sshUser,
                sshPass    = sshPass
            )
            sshTunnel = tunnel

            Thread({
                try {
                    tunnel.connect()
                    // Redirect VPN traffic through the internal SOCKS5 on loopback
                    config = ProxyConfig(
                        type     = ProxyType.SOCKS5,
                        host     = "127.0.0.1",
                        port     = tunnel.localPort,
                        username = "",
                        password = ""
                    )
                    startVpn()
                } catch (e: Exception) {
                    Log.e(TAG, "SSH tunnel setup failed: ${e.message}", e)
                    lastError = "SSH: ${e.message}"
                    onStateChange?.invoke(false)
                    stopSelf()
                }
            }, "SshWsTunnel-Setup").apply { isDaemon = true; start() }
        } else {
            config = ProxyConfig(
                type     = type,
                host     = intent?.getStringExtra(EXTRA_HOST) ?: "",
                port     = intent?.getIntExtra(EXTRA_PORT, 1080) ?: 1080,
                username = intent?.getStringExtra(EXTRA_USER) ?: "",
                password = intent?.getStringExtra(EXTRA_PASS) ?: ""
            )
            startVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }
    override fun onRevoke()  { stopVpn(); super.onRevoke()  }

    // ── VPN start / stop ──────────────────────────────────────────────────────

    private fun startVpn() {
        if (running.getAndSet(true)) return
        Log.i(TAG, "Starting VPN (${config.type} → ${config.host}:${config.port})")

        bytesUploaded.set(0); bytesDownloaded.set(0)
        pktsRead.set(0); dnsAnswered.set(0); tcpSynCount.set(0); proxyErrors.set(0)
        lastError = ""

        // Compute split routes that cover all of 0.0.0.0/0 EXCEPT the proxy server's /32.
        // This guarantees that traffic to the proxy never enters the VPN tunnel, even if
        // VpnService.protect() fails on a particular socket — eliminating the routing loop
        // that manifests as "Connection reset" / EADDRNOTAVAIL.
        //
        // Special case: loopback proxy (127.x / localhost).  The kernel routes loopback
        // addresses entirely in-process — packets to 127.x NEVER hit the TUN interface,
        // so there is zero risk of a routing loop.  Android's VpnService.Builder also
        // rejects addRoute() calls that overlap the loopback range on many devices/ROMs,
        // which crashes the service.  Use the full default route here instead.
        val exclusionRoutes = if (isLoopbackProxy(config.host)) {
            Log.i(TAG, "Loopback proxy detected — using full 0.0.0.0/0 route (no exclusion needed)")
            listOf(Pair("0.0.0.0", 0))
        } else {
            buildExclusionRoutes(config.host)
        }
        Log.i(TAG, "VPN routes: ${exclusionRoutes.size} blocks (proxy ${config.host}/32 excluded)")

        val builder = Builder()
            .setSession("ProxTunnel")
            .addAddress(VPN_ADDRESS, 24)
            .addDnsServer(VIRTUAL_DNS)
            .setMtu(BUF_SIZE)

        for ((net, prefix) in exclusionRoutes) {
            builder.addRoute(net, prefix)
        }

        // When the proxy is loopback AND is an external process (Termux), exclude Termux from
        // the VPN to avoid routing loops.
        // SSH_WS mode (sshTunnel != null) uses an internal SOCKS5 — no exclusion needed.
        if (isLoopbackProxy(config.host) && sshTunnel == null) {
            val termuxPackages = listOf(
                "com.termux",
                "com.termux.fdroid",
                "com.termux.nightly"
            )
            for (pkg in termuxPackages) {
                try {
                    packageManager.getPackageInfo(pkg, 0)
                    builder.addDisallowedApplication(pkg)
                    Log.i(TAG, "Excluded $pkg from VPN tunnel (loopback proxy — anti-loop)")
                } catch (_: Exception) {
                    // Package not installed — skip silently
                }
            }
        }

        val pfd = builder.establish()

        if (pfd == null) {
            Log.e(TAG, "establish() returned null — VPN permission not granted?")
            running.set(false)
            lastError = "VPN permission denied"
            return
        }

        vpnInterface = pfd

        // foregroundServiceType="dataSync" (0x1) only — Android 12 (API 31-32) will
        // hard-reject any APK whose manifest has SPECIAL_USE (0x40000000).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, buildNotification(config),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, buildNotification(config))
        }

        isRunning = true
        onStateChange?.invoke(true)
        Log.i(TAG, "VPN tunnel up — fake DNS on $VIRTUAL_DNS")

        readerThread = Thread({ packetLoop(pfd) }, "VpnReader").apply {
            isDaemon = true
            start()
        }
    }

    private fun stopVpn() {
        if (!running.getAndSet(false)) return
        Log.i(TAG, "Stopping VPN")
        readerThread?.interrupt()
        connections.values.forEach { it.close() }
        connections.clear()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        try { sshTunnel?.disconnect() } catch (_: Exception) {}
        sshTunnel = null
        isRunning = false
        onStateChange?.invoke(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION") stopForeground(true)
        }
        stopSelf()
    }

    // ── Main packet loop ──────────────────────────────────────────────────────

    private fun packetLoop(pfd: ParcelFileDescriptor) {
        val inp = FileInputStream(pfd.fileDescriptor)
        val out = FileOutputStream(pfd.fileDescriptor)
        val buf = ByteArray(BUF_SIZE)

        Log.i(TAG, "Packet loop started")
        while (running.get()) {
            val n = try {
                inp.read(buf)
            } catch (e: InterruptedException) {
                break
            } catch (e: IOException) {
                if (!running.get()) break   // normal stop
                Log.w(TAG, "TUN read error: ${e.message}")
                continue
            }
            if (n <= 0) continue

            pktsRead.incrementAndGet()
            val pkt = buf.copyOf(n)

            if (PacketUtils.getIpVersion(pkt) != 4) continue
            val ipHdrLen = PacketUtils.getIpHeaderLen(pkt)
            if (ipHdrLen < 20 || n < ipHdrLen + 8) continue

            when (PacketUtils.getIpProtocol(pkt)) {
                6  -> handleTcpPacket(pkt, ipHdrLen, n, out)
                17 -> handleUdpPacket(pkt, ipHdrLen, n, out)
            }
        }
        Log.i(TAG, "Packet loop ended (pkts=${pktsRead.get()}, dns=${dnsAnswered.get()}, syns=${tcpSynCount.get()}, errs=${proxyErrors.get()})")
    }

    // ── TCP ───────────────────────────────────────────────────────────────────

    private fun handleTcpPacket(pkt: ByteArray, ipHdrLen: Int, n: Int, out: FileOutputStream) {
        val srcIp     = PacketUtils.getIpSrc(pkt)
        val dstIp     = PacketUtils.getIpDst(pkt)
        val srcPort   = PacketUtils.getTcpSrcPort(pkt, ipHdrLen)
        val dstPort   = PacketUtils.getTcpDstPort(pkt, ipHdrLen)
        val seq       = PacketUtils.getTcpSeq(pkt, ipHdrLen)
        val tcpHdrLen = PacketUtils.getTcpDataOffset(pkt, ipHdrLen)
        val flags     = PacketUtils.getTcpFlags(pkt, ipHdrLen)
        val dataStart = ipHdrLen + tcpHdrLen
        val dataLen   = n - dataStart
        val key       = srcPort

        when {
            PacketUtils.hasFlag(flags, PacketUtils.FLAG_SYN) &&
            !PacketUtils.hasFlag(flags, PacketUtils.FLAG_ACK) -> {
                tcpSynCount.incrementAndGet()
                // Look up the real hostname if dstIp is one of our fake IPs
                val hostname = if (FakeDns.isFake(dstIp)) FakeDns.lookup(dstIp) else null
                Log.d(TAG, "SYN → ${hostname ?: PacketUtils.ipToString(dstIp)}:$dstPort")
                val conn = TcpConnection(srcIp, dstIp, srcPort, dstPort,
                    out, this, config, hostname)
                connections[key] = conn
                conn.onSyn(seq)
            }
            PacketUtils.hasFlag(flags, PacketUtils.FLAG_RST) ->
                connections.remove(key)?.close()
            PacketUtils.hasFlag(flags, PacketUtils.FLAG_FIN) ->
                connections.remove(key)?.onFin(seq)
            dataLen > 0 && PacketUtils.hasFlag(flags, PacketUtils.FLAG_ACK) ->
                connections[key]?.onData(pkt.copyOfRange(dataStart, n), seq)
        }
    }

    // ── UDP / virtual DNS ─────────────────────────────────────────────────────

    /**
     * Handles UDP packets.  DNS queries (port 53 to our virtual DNS address) are
     * answered in-process via FakeDns — instant reply, no network round-trip needed.
     *
     * This is the approach used by all production proxy VPN apps (tun2socks, sing-box,
     * Super Proxy, etc.).  The fake IP returned to the app is later used to look up
     * the real hostname when a TCP SYN for that IP arrives.
     */
    private fun handleUdpPacket(pkt: ByteArray, ipHdrLen: Int, n: Int, out: FileOutputStream) {
        val dstPort = PacketUtils.getUdpDstPort(pkt, ipHdrLen)
        if (dstPort != 53) return  // only DNS

        val udpHdrLen    = 8
        val payloadStart = ipHdrLen + udpHdrLen
        val totalLen     = PacketUtils.getIpTotalLen(pkt)
        val payloadLen   = totalLen - ipHdrLen - udpHdrLen
        if (payloadLen <= 0 || payloadStart + payloadLen > n) return

        val query   = pkt.copyOfRange(payloadStart, payloadStart + payloadLen)
        val srcIp   = PacketUtils.getIpSrc(pkt)
        val dstIp   = PacketUtils.getIpDst(pkt)
        val srcPort = PacketUtils.getUdpSrcPort(pkt, ipHdrLen)

        val hostname = FakeDns.parseHostname(query)
        if (hostname == null) {
            Log.d(TAG, "DNS query with no parseable hostname — dropping")
            return
        }

        // Allocate (or reuse) a fake IP for this hostname
        val fakeIp   = FakeDns.allocate(hostname)
        val response = FakeDns.buildResponse(query, hostname, fakeIp)

        // Reply from the virtual DNS server back to the querying app
        val udpReply = PacketUtils.buildUdpPacket(
            srcIp = dstIp, dstIp = srcIp,
            srcPort = 53, dstPort = srcPort,
            data = response
        )
        synchronized(out) {
            try { out.write(udpReply) }
            catch (e: IOException) { Log.w(TAG, "TUN write (DNS reply) failed: ${e.message}") }
        }
        dnsAnswered.incrementAndGet()
        Log.d(TAG, "FakeDNS: $hostname → ${PacketUtils.ipToString(fakeIp)}")
    }

    // ── Route exclusion (VPN split-routing) ──────────────────────────────────
    //
    // Android VpnService.Builder.addRoute("0.0.0.0", 0) routes ALL traffic through the
    // VPN tunnel.  If our proxy socket's protect() ever fails, the socket is also routed
    // through the tunnel, which intercepts the connection to the proxy, creates a new
    // TcpConnection, which again tries to connect to the proxy... causing an infinite loop
    // that manifests as "Connection reset" or EADDRNOTAVAIL.
    //
    // Fix: instead of a default route, add a set of CIDR blocks that cover 0.0.0.0/0
    // MINUS the proxy server's /32.  Traffic to the proxy then has no VPN route and
    // travels directly via the real network interface — even without protect().
    //
    // Algorithm: binary recursive splitting of 0.0.0.0/0; at each level add the
    // "safe" half and recurse into the half containing the excluded IP until /32.
    // Produces exactly 32 route entries (one per bit level).

    private fun isLoopbackProxy(host: String): Boolean =
        host == "127.0.0.1" || host == "localhost" || host.startsWith("127.")

    private fun buildExclusionRoutes(proxyHost: String): List<Pair<String, Int>> {
        return try {
            val excl = ipStringToInt(proxyHost)   // may throw if host is a hostname
            val result = mutableListOf<Pair<String, Int>>()

            fun recurse(base: Int, prefix: Int) {
                if (prefix == 32) return           // this /32 IS the excluded proxy IP — skip
                val half = prefix + 1
                val rightBase = base or (1 shl (31 - prefix))
                val inRight = (excl ushr (31 - prefix)) and 1 == 1
                if (inRight) {
                    result.add(Pair(intToIpString(base), half))     // add left half
                    recurse(rightBase, half)                          // descend right
                } else {
                    result.add(Pair(intToIpString(rightBase), half)) // add right half
                    recurse(base, half)                               // descend left
                }
            }
            recurse(0, 0)
            result
        } catch (_: Exception) {
            // proxyHost is a hostname (not a dotted-quad) — fall back to full default route.
            // protect() remains the sole guard against loops in this case.
            Log.w(TAG, "buildExclusionRoutes: '$proxyHost' is not a dotted-quad IP, using 0.0.0.0/0")
            listOf(Pair("0.0.0.0", 0))
        }
    }

    private fun ipStringToInt(ip: String): Int {
        val p = ip.trim().split(".")
        if (p.size != 4) throw IllegalArgumentException("not an IPv4 address: $ip")
        return (p[0].toInt() shl 24) or (p[1].toInt() shl 16) or (p[2].toInt() shl 8) or p[3].toInt()
    }

    private fun intToIpString(n: Int): String =
        "${(n ushr 24) and 0xFF}.${(n ushr 16) and 0xFF}.${(n ushr 8) and 0xFF}.${n and 0xFF}"

    // ── Notification ──────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_ID, "ProxTunnel VPN",
                NotificationManager.IMPORTANCE_LOW)
                .apply { description = "VPN tunnel status" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    private fun buildNotification(cfg: ProxyConfig): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("ProxTunnel — Active")
            .setContentText("${cfg.type} via ${cfg.host}:${cfg.port}")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}
