package zekke.core.api

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp

internal actual fun defaultHttpClient(): HttpClient = HttpClient(OkHttp)
