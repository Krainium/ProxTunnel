package com.krainium.proxtunnel

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View

/**
 * Draws a real-time upload / download speed graph.
 *
 * Call [addSample] once per second with bytes-per-second values.
 * The view keeps the last [MAX_SAMPLES] samples (60 by default) and
 * auto-scales the Y axis to the current maximum speed.
 */
class TrafficGraphView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    companion object {
        private const val MAX_SAMPLES = 60   // seconds of history shown
    }

    // ── Sample ring buffer ────────────────────────────────────────────────────

    private val upSamples   = FloatArray(MAX_SAMPLES)   // bytes/s upload
    private val downSamples = FloatArray(MAX_SAMPLES)   // bytes/s download
    private var count       = 0                         // samples added so far

    fun addSample(uploadBps: Long, downloadBps: Long) {
        if (count < MAX_SAMPLES) {
            upSamples[count]   = uploadBps.toFloat()
            downSamples[count] = downloadBps.toFloat()
            count++
        } else {
            System.arraycopy(upSamples,   1, upSamples,   0, MAX_SAMPLES - 1)
            System.arraycopy(downSamples, 1, downSamples, 0, MAX_SAMPLES - 1)
            upSamples[MAX_SAMPLES - 1]   = uploadBps.toFloat()
            downSamples[MAX_SAMPLES - 1] = downloadBps.toFloat()
        }
        postInvalidate()
    }

    fun reset() {
        upSamples.fill(0f); downSamples.fill(0f); count = 0
        postInvalidate()
    }

    // ── Paints ────────────────────────────────────────────────────────────────

    private val bgPaint = Paint().apply {
        color = Color.parseColor("#0D0D0F"); style = Paint.Style.FILL
    }
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#22FFFFFF"); style = Paint.Style.STROKE; strokeWidth = 1f
    }
    private val upLinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#FFAA44"); style = Paint.Style.STROKE; strokeWidth = 2.5f
        strokeJoin = Paint.Join.ROUND; strokeCap = Paint.Cap.ROUND
    }
    private val downLinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#22DDCC"); style = Paint.Style.STROKE; strokeWidth = 2.5f
        strokeJoin = Paint.Join.ROUND; strokeCap = Paint.Cap.ROUND
    }
    private val upFillPaint   = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val downFillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#66AAAAAA"); textSize = 22f
    }

    // ── Draw ──────────────────────────────────────────────────────────────────

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat(); val h = height.toFloat()
        if (w == 0f || h == 0f || count == 0) return

        val padL = 56f; val padR = 8f; val padT = 12f; val padB = 24f
        val plotW = w - padL - padR
        val plotH = h - padT - padB

        // ── Background ───────────────────────────────────────────────────────
        canvas.drawRect(0f, 0f, w, h, bgPaint)

        // ── Determine Y scale ────────────────────────────────────────────────
        var maxVal = 1024f   // minimum scale: 1 KB/s so graph isn't blank
        for (i in 0 until count) {
            if (upSamples[i]   > maxVal) maxVal = upSamples[i]
            if (downSamples[i] > maxVal) maxVal = downSamples[i]
        }
        // Round up to a "nice" power-of-two-ish boundary
        maxVal = niceMax(maxVal)

        // ── Grid lines (4 horizontal) ────────────────────────────────────────
        val gridDash = DashPathEffect(floatArrayOf(6f, 6f), 0f)
        gridPaint.pathEffect = gridDash
        for (step in 1..4) {
            val y = padT + plotH * (1f - step / 4f)
            canvas.drawLine(padL, y, padL + plotW, y, gridPaint)
        }
        gridPaint.pathEffect = null
        // Bottom border
        canvas.drawLine(padL, padT + plotH, padL + plotW, padT + plotH, gridPaint)
        // Left border
        canvas.drawLine(padL, padT, padL, padT + plotH, gridPaint)

        // ── Y axis labels ────────────────────────────────────────────────────
        for (step in 0..4) {
            val bps = maxVal * step / 4f
            val y   = padT + plotH * (1f - step / 4f)
            canvas.drawText(formatSpeedShort(bps.toLong()), 0f, y + 8f, labelPaint)
        }

        // ── Helper: map value → X,Y ──────────────────────────────────────────
        fun xOf(i: Int): Float = padL + (i.toFloat() / (MAX_SAMPLES - 1).toFloat()) * plotW
        fun yOf(v: Float): Float = padT + plotH * (1f - (v / maxVal).coerceIn(0f, 1f))

        // Only draw the portion we have samples for
        if (count < 2) return

        // ── Download filled area + line ───────────────────────────────────────
        val dnPath = Path()
        dnPath.moveTo(xOf(0), padT + plotH)
        for (i in 0 until count) dnPath.lineTo(xOf(i), yOf(downSamples[i]))
        dnPath.lineTo(xOf(count - 1), padT + plotH); dnPath.close()

        val dnFillShader = LinearGradient(
            0f, padT, 0f, padT + plotH,
            Color.parseColor("#5522DDCC"), Color.TRANSPARENT,
            Shader.TileMode.CLAMP
        )
        downFillPaint.shader = dnFillShader
        canvas.drawPath(dnPath, downFillPaint)

        val dnLinePath = Path()
        dnLinePath.moveTo(xOf(0), yOf(downSamples[0]))
        for (i in 1 until count) dnLinePath.lineTo(xOf(i), yOf(downSamples[i]))
        canvas.drawPath(dnLinePath, downLinePaint)

        // ── Upload filled area + line ─────────────────────────────────────────
        val upPath = Path()
        upPath.moveTo(xOf(0), padT + plotH)
        for (i in 0 until count) upPath.lineTo(xOf(i), yOf(upSamples[i]))
        upPath.lineTo(xOf(count - 1), padT + plotH); upPath.close()

        val upFillShader = LinearGradient(
            0f, padT, 0f, padT + plotH,
            Color.parseColor("#44FFAA44"), Color.TRANSPARENT,
            Shader.TileMode.CLAMP
        )
        upFillPaint.shader = upFillShader
        canvas.drawPath(upPath, upFillPaint)

        val upLinePath = Path()
        upLinePath.moveTo(xOf(0), yOf(upSamples[0]))
        for (i in 1 until count) upLinePath.lineTo(xOf(i), yOf(upSamples[i]))
        canvas.drawPath(upLinePath, upLinePaint)

        // ── Time label ───────────────────────────────────────────────────────
        val elapsed = count - 1
        val timeLabel = if (elapsed < 60) "${elapsed}s" else "${elapsed / 60}m ${elapsed % 60}s"
        labelPaint.textAlign = Paint.Align.RIGHT
        canvas.drawText(timeLabel, padL + plotW, h - 2f, labelPaint)
        labelPaint.textAlign = Paint.Align.LEFT
        canvas.drawText("0s", padL, h - 2f, labelPaint)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun niceMax(v: Float): Float {
        val units = listOf(
            512f, 1024f, 2048f, 4096f, 8192f,
            16384f, 32768f, 65536f, 131072f, 262144f,
            524288f, 1048576f, 2097152f, 4194304f, 8388608f
        )
        return units.firstOrNull { it >= v } ?: (v * 1.5f)
    }

    private fun formatSpeedShort(bps: Long): String = when {
        bps < 1024L             -> "${bps}B"
        bps < 1024L * 1024      -> "${bps / 1024}K"
        else                    -> String.format("%.1fM", bps / 1048576f)
    }
}
