package com.krainium.proxtunnel

object PacketUtils {

    const val FLAG_FIN: Int = 0x01
    const val FLAG_SYN: Int = 0x02
    const val FLAG_RST: Int = 0x04
    const val FLAG_PSH: Int = 0x08
    const val FLAG_ACK: Int = 0x10

    // ── IP header fields ──────────────────────────────────────────────────────

    fun getIpVersion(buf: ByteArray): Int = (buf[0].toInt() and 0xFF) shr 4

    fun getIpHeaderLen(buf: ByteArray): Int = (buf[0].toInt() and 0x0F) * 4

    fun getIpTotalLen(buf: ByteArray): Int =
        ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)

    fun getIpProtocol(buf: ByteArray): Int = buf[9].toInt() and 0xFF

    fun getIpSrc(buf: ByteArray): ByteArray = buf.copyOfRange(12, 16)
    fun getIpDst(buf: ByteArray): ByteArray = buf.copyOfRange(16, 20)

    // ── TCP header fields (off = IP header length from buf start) ─────────────

    fun getTcpSrcPort(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    fun getTcpDstPort(buf: ByteArray, off: Int): Int =
        ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)

    fun getTcpSeq(buf: ByteArray, off: Int): Long {
        var s = 0L
        for (i in 4..7) s = (s shl 8) or (buf[off + i].toLong() and 0xFF)
        return s
    }

    fun getTcpAck(buf: ByteArray, off: Int): Long {
        var s = 0L
        for (i in 8..11) s = (s shl 8) or (buf[off + i].toLong() and 0xFF)
        return s
    }

    /** Returns TCP data offset in bytes from start of TCP header. */
    fun getTcpDataOffset(buf: ByteArray, off: Int): Int =
        ((buf[off + 12].toInt() and 0xFF) shr 4) * 4

    fun getTcpFlags(buf: ByteArray, off: Int): Int = buf[off + 13].toInt() and 0xFF

    fun hasFlag(flags: Int, flag: Int): Boolean = flags and flag != 0

    // ── UDP header fields (off = IP header length from buf start) ─────────────

    fun getUdpSrcPort(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    fun getUdpDstPort(buf: ByteArray, off: Int): Int =
        ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)

    fun getUdpPayloadLen(buf: ByteArray, off: Int): Int =
        (((buf[off + 4].toInt() and 0xFF) shl 8) or (buf[off + 5].toInt() and 0xFF)) - 8

    // ── TCP packet builder ────────────────────────────────────────────────────

    fun buildTcpPacket(
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int,
        data: ByteArray = ByteArray(0),
        windowSize: Int = 65535
    ): ByteArray {
        val ipHdrLen  = 20
        val tcpHdrLen = 20
        val totalLen  = ipHdrLen + tcpHdrLen + data.size
        val buf = ByteArray(totalLen)

        // IPv4 header
        buf[0] = 0x45.toByte()
        buf[1] = 0
        buf[2] = (totalLen shr 8).toByte()
        buf[3] = totalLen.toByte()
        buf[4] = 0; buf[5] = 1          // identification
        buf[6] = 0x40; buf[7] = 0       // DF flag
        buf[8] = 64                      // TTL
        buf[9] = 6                       // protocol: TCP
        buf[10] = 0; buf[11] = 0        // checksum (computed below)
        srcIp.copyInto(buf, 12); dstIp.copyInto(buf, 16)

        // TCP header
        val t = ipHdrLen
        buf[t]     = (srcPort shr 8).toByte(); buf[t + 1] = srcPort.toByte()
        buf[t + 2] = (dstPort shr 8).toByte(); buf[t + 3] = dstPort.toByte()
        buf[t + 4] = (seq shr 24).toByte(); buf[t + 5] = (seq shr 16).toByte()
        buf[t + 6] = (seq shr 8).toByte();  buf[t + 7] = seq.toByte()
        buf[t + 8] = (ack shr 24).toByte(); buf[t + 9] = (ack shr 16).toByte()
        buf[t + 10] = (ack shr 8).toByte(); buf[t + 11] = ack.toByte()
        buf[t + 12] = 0x50.toByte()     // data offset = 5 (20 bytes)
        buf[t + 13] = flags.toByte()
        buf[t + 14] = (windowSize shr 8).toByte(); buf[t + 15] = windowSize.toByte()
        buf[t + 16] = 0; buf[t + 17] = 0  // checksum (computed below)
        buf[t + 18] = 0; buf[t + 19] = 0  // urgent

        if (data.isNotEmpty()) data.copyInto(buf, ipHdrLen + tcpHdrLen)

        // Checksums
        val tcpSeg = buf.copyOfRange(ipHdrLen, totalLen)
        val tcpCsum = pseudoHeaderChecksum(srcIp, dstIp, 6, tcpSeg)
        buf[t + 16] = (tcpCsum shr 8).toByte(); buf[t + 17] = tcpCsum.toByte()

        val ipCsum = checksum(buf, 0, ipHdrLen)
        buf[10] = (ipCsum shr 8).toByte(); buf[11] = ipCsum.toByte()

        return buf
    }

    fun buildRstPacket(
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        seq: Long
    ): ByteArray = buildTcpPacket(srcIp, dstIp, srcPort, dstPort, seq, 0, FLAG_RST)

    // ── UDP packet builder ────────────────────────────────────────────────────

    fun buildUdpPacket(
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        data: ByteArray
    ): ByteArray {
        val ipHdrLen  = 20
        val udpHdrLen = 8
        val totalLen  = ipHdrLen + udpHdrLen + data.size
        val buf = ByteArray(totalLen)

        // IPv4 header
        buf[0] = 0x45.toByte()
        buf[1] = 0
        buf[2] = (totalLen shr 8).toByte()
        buf[3] = totalLen.toByte()
        buf[4] = 0; buf[5] = 1
        buf[6] = 0x40; buf[7] = 0
        buf[8] = 64
        buf[9] = 17                      // protocol: UDP
        buf[10] = 0; buf[11] = 0
        srcIp.copyInto(buf, 12); dstIp.copyInto(buf, 16)

        // UDP header
        val u = ipHdrLen
        buf[u]     = (srcPort shr 8).toByte(); buf[u + 1] = srcPort.toByte()
        buf[u + 2] = (dstPort shr 8).toByte(); buf[u + 3] = dstPort.toByte()
        val udpLen = udpHdrLen + data.size
        buf[u + 4] = (udpLen shr 8).toByte(); buf[u + 5] = udpLen.toByte()
        buf[u + 6] = 0; buf[u + 7] = 0  // checksum (computed below)

        if (data.isNotEmpty()) data.copyInto(buf, ipHdrLen + udpHdrLen)

        // UDP checksum over pseudo-header
        val udpSeg = buf.copyOfRange(ipHdrLen, totalLen)
        val udpCsum = pseudoHeaderChecksum(srcIp, dstIp, 17, udpSeg)
        buf[u + 6] = (udpCsum shr 8).toByte(); buf[u + 7] = udpCsum.toByte()

        // IP checksum
        val ipCsum = checksum(buf, 0, ipHdrLen)
        buf[10] = (ipCsum shr 8).toByte(); buf[11] = ipCsum.toByte()

        return buf
    }

    // ── Checksums ─────────────────────────────────────────────────────────────

    fun ipChecksum(buf: ByteArray, offset: Int, length: Int): Int =
        checksum(buf, offset, length)

    fun tcpChecksum(srcIp: ByteArray, dstIp: ByteArray, tcpSegment: ByteArray): Int =
        pseudoHeaderChecksum(srcIp, dstIp, 6, tcpSegment)

    private fun pseudoHeaderChecksum(
        srcIp: ByteArray, dstIp: ByteArray,
        proto: Int, segment: ByteArray
    ): Int {
        val pseudo = ByteArray(12 + segment.size)
        srcIp.copyInto(pseudo, 0); dstIp.copyInto(pseudo, 4)
        pseudo[8]  = 0
        pseudo[9]  = proto.toByte()
        pseudo[10] = (segment.size shr 8).toByte()
        pseudo[11] = segment.size.toByte()
        segment.copyInto(pseudo, 12)
        return checksum(pseudo)
    }

    private fun checksum(data: ByteArray, offset: Int = 0, length: Int = data.size): Int {
        var sum = 0L
        var i = offset
        while (i < offset + length - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word; i += 2
        }
        if (i < offset + length) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fun ipToString(ip: ByteArray): String =
        ip.joinToString(".") { (it.toInt() and 0xFF).toString() }

    fun uint32(n: Long): Long = n and 0xFFFFFFFFL

    fun seqAdd(seq: Long, n: Int): Long = uint32(seq + n)
}
