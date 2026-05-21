package com.krainium.proxtunnel

import android.content.Context
import android.content.SharedPreferences

enum class ProxyType { HTTP, SOCKS5, SSH_WS }

data class ProxyConfig(
    val type: ProxyType = ProxyType.SOCKS5,
    val host: String = "",
    val port: Int = 1080,
    val username: String = "",
    val password: String = ""
) {
    val hasAuth: Boolean get() = username.isNotBlank() && password.isNotBlank()
    val isValid: Boolean get() = host.isNotBlank() && port in 1..65535

    companion object {
        private const val PREFS = "proxy_config"
        private const val KEY_TYPE    = "type"
        private const val KEY_HOST    = "host"
        private const val KEY_PORT    = "port"
        private const val KEY_USER    = "username"
        private const val KEY_PASS    = "password"

        fun load(ctx: Context): ProxyConfig {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            return ProxyConfig(
                type     = try { ProxyType.valueOf(p.getString(KEY_TYPE, ProxyType.SOCKS5.name)!!) }
                           catch (_: Exception) { ProxyType.SOCKS5 },
                host     = p.getString(KEY_HOST, "") ?: "",
                port     = p.getInt(KEY_PORT, 1080),
                username = p.getString(KEY_USER, "") ?: "",
                password = p.getString(KEY_PASS, "") ?: ""
            )
        }

        fun save(ctx: Context, config: ProxyConfig) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_TYPE, config.type.name)
                .putString(KEY_HOST, config.host)
                .putInt(KEY_PORT, config.port)
                .putString(KEY_USER, config.username)
                .putString(KEY_PASS, config.password)
                .apply()
        }
    }
}
