package com.krainium.proxtunnel

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

@SuppressLint("CustomSplashScreen")
class SplashActivity : AppCompatActivity() {

    private val handler   = Handler(Looper.getMainLooper())
    private var pulseAnim: ValueAnimator? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        val glow      = findViewById<View>(R.id.v_glow)
        val title     = findViewById<TextView>(R.id.tv_splash_title)
        val titleLine = findViewById<View>(R.id.v_title_line)
        val sub       = findViewById<TextView>(R.id.tv_splash_sub)
        val poweredBy = findViewById<TextView>(R.id.tv_powered_by)

        // ── Phase 1 (0 ms): Glow expands from nothing ─────────────────────────
        glow.animate()
            .alpha(1f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(900)
            .setInterpolator(DecelerateInterpolator(2f))
            .start()

        // ── Phase 2 (250 ms): Title bursts in with spring overshoot ───────────
        handler.postDelayed({
            title.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .setDuration(700)
                .setInterpolator(OvershootInterpolator(1.8f))
                .start()
        }, 250)

        // ── Phase 3 (750 ms): Underline expands from 0→title width ────────────
        handler.postDelayed({
            title.post {
                val titleW = title.width
                titleLine.layoutParams = titleLine.layoutParams.also {
                    it.width = 0
                }
                titleLine.requestLayout()

                val lineAnim = ValueAnimator.ofInt(0, titleW).apply {
                    duration = 450
                    interpolator = DecelerateInterpolator()
                    addUpdateListener { va ->
                        titleLine.layoutParams = titleLine.layoutParams.also { lp ->
                            lp.width = va.animatedValue as Int
                        }
                        titleLine.requestLayout()
                    }
                }
                titleLine.animate()
                    .alpha(1f)
                    .setDuration(200)
                    .withStartAction { lineAnim.start() }
                    .start()
            }
        }, 750)

        // ── Phase 4 (900 ms): Subtitle slides up + fades in ───────────────────
        handler.postDelayed({
            sub.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(550)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }, 900)

        // ── Phase 5 (1 100 ms): "powered by" floats up + fades in ─────────────
        handler.postDelayed({
            poweredBy.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(500)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }, 1100)

        // ── Phase 6 (1 400 ms): glow begins gentle breathing pulse ────────────
        handler.postDelayed({
            pulseAnim = ValueAnimator.ofFloat(1f, 1.15f, 1f).apply {
                duration       = 1800
                repeatCount    = ValueAnimator.INFINITE
                repeatMode     = ValueAnimator.RESTART
                interpolator   = android.view.animation.AccelerateDecelerateInterpolator()
                addUpdateListener { va ->
                    val s = va.animatedValue as Float
                    glow.scaleX = s
                    glow.scaleY = s
                }
                start()
            }
        }, 1400)

        // ── Phase 7 (2 800 ms): everything fades out → launch MainActivity ────
        handler.postDelayed({
            pulseAnim?.cancel()
            val allViews = listOf(glow, title, titleLine, sub, poweredBy)
            allViews.forEach { v ->
                v.animate()
                    .alpha(0f)
                    .setDuration(400)
                    .setInterpolator(DecelerateInterpolator())
                    .start()
            }
            handler.postDelayed({
                startActivity(Intent(this, MainActivity::class.java))
                finish()
                overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
            }, 420)
        }, 2800)
    }

    override fun onDestroy() {
        pulseAnim?.cancel()
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
