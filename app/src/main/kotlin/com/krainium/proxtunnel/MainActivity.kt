package com.krainium.proxtunnel

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.ChipGroup
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    // ── Views ─────────────────────────────────────────────────────────────────
    private lateinit var statusCard:    MaterialCardView
    private lateinit var statusIcon:    View
    private lateinit var statusLabel:   TextView
    private lateinit var statusSub:     TextView
    private lateinit var chipGroup:     ChipGroup
    private lateinit var tilServer:     TextInputLayout
    private lateinit var etServer:      TextInputEditText
    private lateinit var tilPort:       TextInputLayout
    private lateinit var etPort:        TextInputEditText
    private lateinit var tilUser:       TextInputLayout
    private lateinit var etUser:        TextInputEditText
    private lateinit var tilPass:       TextInputLayout
    private lateinit var etPass:        TextInputEditText
    private lateinit var btnConnect:    MaterialButton
    private lateinit var viewPingDot:   View
    private lateinit var tvPingStatus:  TextView
    private lateinit var tvPingLatency: TextView

    // Traffic card views
    private lateinit var cardTraffic:  MaterialCardView
    private lateinit var tvDownTotal:  TextView
    private lateinit var tvDownSpeed:  TextView
    private lateinit var tvUpTotal:    TextView
    private lateinit var tvUpSpeed:    TextView
    private lateinit var graphTraffic: TrafficGraphView

    // ── State ─────────────────────────────────────────────────────────────────
    private var connected  = false
    private var connecting = false

    // Ping debounce
    private val pingHandler    = Handler(Looper.getMainLooper())
    private val pingExecutor   = Executors.newSingleThreadExecutor()
    private var pingRunnable: Runnable? = null
    private var currentPingHost = ""
    private var currentPingPort = -1

    // Traffic polling (1-second interval while connected)
    private val trafficHandler    = Handler(Looper.getMainLooper())
    private var trafficRunnable: Runnable? = null
    private var lastUpBytes:   Long = 0
    private var lastDownBytes: Long = 0
    private var lastStatTime:  Long = 0

    // ── Activity result launchers ─────────────────────────────────────────────

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startVpnService(ProxyConfig.load(this))
            }
        }

    private val notifPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { _ -> }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        bindViews()
        loadSavedConfig()
        attachListeners()

        ProxyVpnService.onStateChange = { isConnected ->
            runOnUiThread { updateConnectionState(isConnected) }
        }

        if (ProxyVpnService.isRunning) updateConnectionState(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun onDestroy() {
        ProxyVpnService.onStateChange = null
        pingHandler.removeCallbacksAndMessages(null)
        pingExecutor.shutdownNow()
        stopTrafficPolling()
        super.onDestroy()
    }

    // ── View binding ──────────────────────────────────────────────────────────

    private fun bindViews() {
        statusCard     = findViewById(R.id.card_status)
        statusIcon     = findViewById(R.id.view_status_icon)
        statusLabel    = findViewById(R.id.tv_status_label)
        statusSub      = findViewById(R.id.tv_status_sub)
        chipGroup      = findViewById(R.id.chip_group_type)
        tilServer      = findViewById(R.id.til_server)
        etServer       = findViewById(R.id.et_server)
        tilPort        = findViewById(R.id.til_port)
        etPort         = findViewById(R.id.et_port)
        tilUser        = findViewById(R.id.til_username)
        etUser         = findViewById(R.id.et_username)
        tilPass        = findViewById(R.id.til_password)
        etPass         = findViewById(R.id.et_password)
        btnConnect     = findViewById(R.id.btn_connect)
        viewPingDot    = findViewById(R.id.view_ping_dot)
        tvPingStatus   = findViewById(R.id.tv_ping_status)
        tvPingLatency  = findViewById(R.id.tv_ping_latency)

        cardTraffic    = findViewById(R.id.card_traffic)
        tvDownTotal    = findViewById(R.id.tv_down_total)
        tvDownSpeed    = findViewById(R.id.tv_down_speed)
        tvUpTotal      = findViewById(R.id.tv_up_total)
        tvUpSpeed      = findViewById(R.id.tv_up_speed)
        graphTraffic   = findViewById(R.id.graph_traffic)
    }

    private fun loadSavedConfig() {
        val cfg = ProxyConfig.load(this)
        etServer.setText(cfg.host)
        etPort.setText(if (cfg.port > 0) cfg.port.toString() else "")
        etUser.setText(cfg.username)
        etPass.setText(cfg.password)
        val chipId = when (cfg.type) {
            ProxyType.HTTP   -> R.id.chip_http
            ProxyType.SSH_WS -> R.id.chip_ssh_ws
            else             -> R.id.chip_socks5
        }
        chipGroup.check(chipId)
        applyChipHints(cfg.type)
        schedulePing()
    }

    private fun applyChipHints(type: ProxyType) {
        if (type == ProxyType.SSH_WS) {
            tilServer.hint = "WebSocket host"
            tilPort.hint   = "Port (443)"
            tilUser.hint   = "SSH username"
            tilPass.hint   = "SSH password"
            if (etServer.text.isNullOrBlank()) etServer.setText("ws.netfragile.store")
            if (etPort.text.isNullOrBlank())   etPort.setText("443")
        } else {
            tilServer.hint = "Server address"
            tilPort.hint   = "Port"
            tilUser.hint   = "Username (optional)"
            tilPass.hint   = "Password (optional)"
        }
    }

    // ── Listeners ─────────────────────────────────────────────────────────────

    private fun attachListeners() {
        btnConnect.setOnClickListener {
            when {
                connected  -> disconnect()
                connecting -> disconnect()   // cancel mid-connect
                else       -> tryConnect()
            }
        }
        etPass.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) { tryConnect(); true } else false
        }

        chipGroup.setOnCheckedStateChangeListener { _, checkedIds ->
            val type = when (checkedIds.firstOrNull()) {
                R.id.chip_http   -> ProxyType.HTTP
                R.id.chip_ssh_ws -> ProxyType.SSH_WS
                else             -> ProxyType.SOCKS5
            }
            applyChipHints(type)
            schedulePing()
        }

        val pingWatcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) = Unit
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) { schedulePing() }
        }
        etServer.addTextChangedListener(pingWatcher)
        etPort.addTextChangedListener(pingWatcher)
    }

    // ── Auto-ping ─────────────────────────────────────────────────────────────

    private fun schedulePing() {
        pingRunnable?.let { pingHandler.removeCallbacks(it) }
        val host = etServer.text?.toString()?.trim() ?: ""
        val port = etPort.text?.toString()?.trim()?.toIntOrNull()

        if (host.isBlank() || port == null || port !in 1..65535) {
            showPingIdle(); return
        }
        if (host == currentPingHost && port == currentPingPort) return

        showPingChecking()
        pingRunnable = Runnable { runPing(host, port) }.also {
            pingHandler.postDelayed(it, 800)
        }
    }

    private fun runPing(host: String, port: Int) {
        pingExecutor.submit {
            val startMs = System.currentTimeMillis()
            val ok = try {
                Socket().use { s -> s.connect(InetSocketAddress(host, port), 4000); true }
            } catch (_: Exception) { false }
            val latencyMs = System.currentTimeMillis() - startMs
            runOnUiThread {
                currentPingHost = host; currentPingPort = port
                if (ok) showPingSuccess(latencyMs) else showPingFail()
            }
        }
    }

    private fun showPingIdle() {
        viewPingDot.visibility = View.INVISIBLE
        tvPingStatus.text  = ""
        tvPingLatency.text = ""
    }

    private fun showPingChecking() {
        viewPingDot.visibility = View.INVISIBLE
        tvPingStatus.setTextColor(getColor(R.color.text_secondary))
        tvPingStatus.text  = "Checking server\u2026"
        tvPingLatency.text = ""
    }

    private fun showPingSuccess(ms: Long) {
        viewPingDot.visibility = View.VISIBLE
        viewPingDot.backgroundTintList =
            ContextCompat.getColorStateList(this, R.color.status_connected)
        tvPingStatus.setTextColor(getColor(R.color.status_connected))
        tvPingStatus.text  = "Server reachable"
        tvPingLatency.setTextColor(getColor(R.color.text_secondary))
        tvPingLatency.text = "${ms} ms"
    }

    private fun showPingFail() {
        viewPingDot.visibility = View.VISIBLE
        viewPingDot.backgroundTintList =
            ContextCompat.getColorStateList(this, R.color.status_disconnected)
        tvPingStatus.setTextColor(getColor(R.color.status_disconnected))
        tvPingStatus.text  = "Unreachable \u2014 check host / port"
        tvPingLatency.text = ""
    }

    // ── Traffic polling ───────────────────────────────────────────────────────

    private fun startTrafficPolling() {
        lastUpBytes   = ProxyVpnService.bytesUploaded.get()
        lastDownBytes = ProxyVpnService.bytesDownloaded.get()
        lastStatTime  = System.currentTimeMillis()

        graphTraffic.reset()
        tvDownTotal.text = "0 B"; tvDownSpeed.text = "0 B/s"
        tvUpTotal.text   = "0 B"; tvUpSpeed.text   = "0 B/s"
        cardTraffic.visibility = View.VISIBLE

        val tick = object : Runnable {
            override fun run() {
                if (!connected) return
                pollTrafficStats()
                trafficRunnable = this
                trafficHandler.postDelayed(this, 1000)
            }
        }
        trafficRunnable = tick
        trafficHandler.postDelayed(tick, 1000)
    }

    private fun stopTrafficPolling() {
        trafficRunnable?.let { trafficHandler.removeCallbacks(it) }
        trafficRunnable = null
    }

    private fun pollTrafficStats() {
        val now       = System.currentTimeMillis()
        val upBytes   = ProxyVpnService.bytesUploaded.get()
        val downBytes = ProxyVpnService.bytesDownloaded.get()

        val elapsedMs   = (now - lastStatTime).coerceAtLeast(1)
        val upBps       = (upBytes   - lastUpBytes)   * 1000 / elapsedMs
        val downBps     = (downBytes - lastDownBytes) * 1000 / elapsedMs

        lastUpBytes   = upBytes
        lastDownBytes = downBytes
        lastStatTime  = now

        tvDownTotal.text = formatBytes(downBytes)
        tvDownSpeed.text = formatSpeed(downBps)
        tvUpTotal.text   = formatBytes(upBytes)
        tvUpSpeed.text   = formatSpeed(upBps)

        graphTraffic.addSample(upBps, downBps)
    }

    // ── Connect / disconnect ──────────────────────────────────────────────────

    private fun tryConnect() {
        val host = etServer.text.toString().trim()
        val port = etPort.text.toString().trim().toIntOrNull()

        tilServer.error = null; tilPort.error = null
        if (host.isBlank())                     { tilServer.error = "Server address required"; return }
        if (port == null || port !in 1..65535)  { tilPort.error   = "Port must be 1\u201365535";   return }

        val type = when (chipGroup.checkedChipId) {
            R.id.chip_http   -> ProxyType.HTTP
            R.id.chip_ssh_ws -> ProxyType.SSH_WS
            else             -> ProxyType.SOCKS5
        }

        if (type == ProxyType.SSH_WS && etUser.text.isNullOrBlank()) {
            tilUser.error = "SSH username required"; return
        }
        tilUser.error = null

        val cfg = ProxyConfig(
            type     = type,
            host     = host,
            port     = port,
            username = etUser.text.toString(),
            password = etPass.text.toString()
        )
        ProxyConfig.save(this, cfg)

        // Show "Connecting…" immediately so the user knows something is happening
        setConnectingState()

        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) vpnPermissionLauncher.launch(vpnIntent)
        else startVpnService(cfg)
    }

    private fun setConnectingState() {
        connecting = true
        statusLabel.text = "Connecting\u2026"
        statusSub.text   = "Establishing tunnel\u2026"
        statusIcon.backgroundTintList =
            ContextCompat.getColorStateList(this, R.color.accent)
        btnConnect.text  = "Cancel"
        btnConnect.setBackgroundColor(getColor(R.color.btn_disconnect))
        setInputsEnabled(false)
    }

    private fun startVpnService(cfg: ProxyConfig) {
        val intent = Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_START
            putExtra(ProxyVpnService.EXTRA_CONFIG, cfg.type.name)
            putExtra(ProxyVpnService.EXTRA_HOST,   cfg.host)
            putExtra(ProxyVpnService.EXTRA_PORT,   cfg.port)
            putExtra(ProxyVpnService.EXTRA_USER,   cfg.username)
            putExtra(ProxyVpnService.EXTRA_PASS,   cfg.password)
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun disconnect() {
        startService(Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_STOP
        })
    }

    // ── UI state ──────────────────────────────────────────────────────────────

    private fun updateConnectionState(isConnected: Boolean) {
        connected  = isConnected
        connecting = false
        val cfg    = ProxyConfig.load(this)

        if (isConnected) {
            statusLabel.text = "Connected"
            statusSub.text   = "${cfg.type} via ${cfg.host}:${cfg.port}"
            statusIcon.backgroundTintList =
                ContextCompat.getColorStateList(this, R.color.status_connected)
            btnConnect.text = "Disconnect"
            btnConnect.setBackgroundColor(getColor(R.color.btn_disconnect))
            setInputsEnabled(false)
            startTrafficPolling()
        } else {
            statusLabel.text = "Disconnected"
            statusSub.text   = "Tap Connect to start tunnelling"
            statusIcon.backgroundTintList =
                ContextCompat.getColorStateList(this, R.color.status_disconnected)
            btnConnect.text = "Connect"
            btnConnect.setBackgroundColor(getColor(R.color.btn_connect))
            setInputsEnabled(true)
            stopTrafficPolling()
            cardTraffic.visibility = View.GONE
        }
    }

    private fun setInputsEnabled(enabled: Boolean) {
        listOf<View>(chipGroup, etServer, etPort, etUser, etPass).forEach { it.isEnabled = enabled }
        tilServer.isEnabled = enabled; tilPort.isEnabled = enabled
        tilUser.isEnabled   = enabled; tilPass.isEnabled = enabled
        chipGroup.isEnabled = enabled
    }

    // ── Formatters ────────────────────────────────────────────────────────────

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024L             -> "$bytes B"
        bytes < 1024L * 1024      -> "%.1f KB".format(bytes / 1024f)
        bytes < 1024L * 1024 * 1024 -> "%.2f MB".format(bytes / 1048576f)
        else                      -> "%.2f GB".format(bytes / 1073741824f)
    }

    private fun formatSpeed(bps: Long): String = when {
        bps < 1024L             -> "$bps B/s"
        bps < 1024L * 1024      -> "%.1f KB/s".format(bps / 1024f)
        else                    -> "%.2f MB/s".format(bps / 1048576f)
    }
}
