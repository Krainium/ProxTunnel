package com.krainium.proxtunnel

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Virtual-DNS (fake-DNS) resolver.
 *
 * Instead of forwarding DNS queries to a real DNS server (which requires a working
 * network path that may not yet exist) we intercept every DNS query for an A record,
 * allocate a "fake" IPv4 from the 198.18.x.x reserved test range (RFC 2544), and
 * return it to the app immediately.
 *
 * When the app later opens a TCP connection to that fake IP, the VPN looks up the
 * real hostname and uses it in the SOCKS5 CONNECT (host type) or HTTP CONNECT request.
 * This gives us:
 *   – Sub-millisecond DNS replies (no round-trip to 8.8.8.8)
 *   – Hostname-based proxy CONNECT (required by many HTTP/SOCKS5 proxies)
 *   – Correct SNI in HTTPS (the proxy can see the real domain)
 */
object FakeDns {

    // 198.18.0.1 – 198.18.255.254 (65 534 slots, RFC 2544 test range)
    private val counter = AtomicInteger(1)
    private val hostnameToIp = ConcurrentHashMap<String, ByteArray>()
    private val ipToHostname = ConcurrentHashMap<Int, String>()

    /** Returns an existing or new fake IP for [hostname]. */
    fun allocate(hostname: String): ByteArray =
        hostnameToIp.getOrPut(hostname) {
            val n = counter.getAndIncrement() and 0xFFFF  // 0..65535
            val ip = byteArrayOf(198.toByte(), 18.toByte(),
                (n shr 8).toByte(), (n and 0xFF).toByte())
            ipToHostname[toInt(ip)] = hostname
            ip
        }

    /** Returns the hostname for a fake IP, or null if it is not a fake IP. */
    fun lookup(ip: ByteArray): String? = ipToHostname[toInt(ip)]

    /** True when [ip] is in the 198.18.0.0/16 range we own. */
    fun isFake(ip: ByteArray): Boolean =
        (ip[0].toInt() and 0xFF) == 198 && (ip[1].toInt() and 0xFF) == 18

    // ── DNS packet helpers ────────────────────────────────────────────────────

    /**
     * Parses the first QNAME from a DNS query payload.
     * Returns null if the packet is malformed or the query type is not A (0x0001).
     */
    fun parseHostname(query: ByteArray): String? {
        if (query.size < 17) return null  // minimum viable query

        // bytes 0-11: header; byte 12 starts QNAME
        var pos = 12
        val sb = StringBuilder()
        while (pos < query.size) {
            val labelLen = query[pos].toInt() and 0xFF
            if (labelLen == 0) { pos++; break }
            if (pos + 1 + labelLen > query.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..labelLen) sb.append(query[pos + i].toChar())
            pos += 1 + labelLen
        }
        if (sb.isEmpty()) return null
        // pos now points to QTYPE (2 bytes) QCLASS (2 bytes)
        if (pos + 3 >= query.size) return null
        val qtype = ((query[pos].toInt() and 0xFF) shl 8) or (query[pos + 1].toInt() and 0xFF)
        return if (qtype == 1 /* A */ || qtype == 28 /* AAAA */) sb.toString() else null
    }

    /**
     * Builds a minimal DNS response that answers [hostname] with [fakeIp].
     * The transaction ID and question section are copied from [query].
     */
    fun buildResponse(query: ByteArray, hostname: String, fakeIp: ByteArray): ByteArray {
        // Locate end of question section
        var pos = 12
        while (pos < query.size && (query[pos].toInt() and 0xFF) != 0) {
            val l = query[pos].toInt() and 0xFF
            pos += 1 + l
        }
        pos++         // skip root label
        pos += 4      // skip QTYPE + QCLASS
        val qSection = query.copyOfRange(12, pos)

        val out = java.io.ByteArrayOutputStream(pos + 28)

        // Header (12 bytes)
        out.write(query[0].toInt()); out.write(query[1].toInt())  // transaction ID
        out.write(0x81); out.write(0x80)  // response, recursion available, no error
        out.write(0x00); out.write(0x01)  // QDCOUNT = 1
        out.write(0x00); out.write(0x01)  // ANCOUNT = 1
        out.write(0x00); out.write(0x00)  // NSCOUNT = 0
        out.write(0x00); out.write(0x00)  // ARCOUNT = 0

        // Question section (verbatim)
        out.write(qSection)

        // Answer RR: pointer to question QNAME (0xC00C = offset 12)
        out.write(0xC0); out.write(0x0C)
        out.write(0x00); out.write(0x01)  // TYPE = A
        out.write(0x00); out.write(0x01)  // CLASS = IN
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x3C)  // TTL = 60 s
        out.write(0x00); out.write(0x04)  // RDLENGTH = 4
        out.write(fakeIp[0].toInt() and 0xFF)
        out.write(fakeIp[1].toInt() and 0xFF)
        out.write(fakeIp[2].toInt() and 0xFF)
        out.write(fakeIp[3].toInt() and 0xFF)

        return out.toByteArray()
    }

    private fun toInt(ip: ByteArray): Int =
        ((ip[0].toInt() and 0xFF) shl 24) or
        ((ip[1].toInt() and 0xFF) shl 16) or
        ((ip[2].toInt() and 0xFF) shl 8)  or
        (ip[3].toInt()  and 0xFF)
}
