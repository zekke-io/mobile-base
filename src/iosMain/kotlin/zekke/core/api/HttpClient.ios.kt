package zekke.core.api

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin

internal actual fun defaultHttpClient(): HttpClient = HttpClient(Darwin)
