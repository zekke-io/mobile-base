package zekke.core.notifications

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import zekke.core.api.Method
import zekke.core.api.ZekkeApi
import zekke.core.api.assertCanonicalUuid

val NOTIFICATION_KINDS: List<String> = listOf(
    "purchase_succeeded",
    "subscription_renewed",
    "payment_failed",
    "refunded",
    "expiring",
    "grace_started",
    "data_loss_countdown",
    "data_deleted",
)

const val MAX_READ_IDS = 200
const val DEFAULT_NOTIFICATION_PAGE = 20

fun isKnownKind(kind: String): Boolean = kind in NOTIFICATION_KINDS

@Serializable
private class NotificationWire(
    val id: String,
    val kind: String,
    val params: JsonElement? = null,
    @SerialName("created_at") val createdAt: String,
    @SerialName("read_at") val readAt: String? = null,
)

@Serializable
private class NotificationListing(
    val notifications: List<NotificationWire> = emptyList(),
    @SerialName("unread_count") val unreadCount: Int = 0,
)

class NotificationRecord(val id: String, val kind: String, val params: JsonObject, val createdAt: String, val readAt: String?) {
    val isKnown: Boolean get() = isKnownKind(kind)
    val isRead: Boolean get() = readAt != null
}

class NotificationPage(val notifications: List<NotificationRecord>, val unreadCount: Int, val nextCursor: String?)

suspend fun listNotifications(api: ZekkeApi, limit: Int = DEFAULT_NOTIFICATION_PAGE, cursor: String? = null): NotificationPage {
    val response = api.request(
        Method.GET,
        "/notifications",
        token = api.tokens.require(),
        query = mapOf("limit" to limit.toString(), "cursor" to cursor),
    )
    val listing = if (response.data == null) NotificationListing() else response.decode(NotificationListing.serializer())
    return NotificationPage(
        listing.notifications.map { NotificationRecord(it.id, it.kind, it.params as? JsonObject ?: JsonObject(emptyMap()), it.createdAt, it.readAt) },
        listing.unreadCount,
        response.page?.takeIf { it.hasMore }?.nextCursor,
    )
}

suspend fun unreadNotificationCount(api: ZekkeApi): Int = listNotifications(api, limit = 1).unreadCount

suspend fun markNotificationsRead(api: ZekkeApi, ids: List<String>) {
    val unique = ids.toSet().map { assertCanonicalUuid(it, "notification id") }
    for (batch in unique.chunked(MAX_READ_IDS)) {
        api.request(
            Method.POST,
            "/notifications/read",
            body = buildJsonObject { putJsonArray("ids") { batch.forEach { add(it) } } },
            token = api.tokens.require(),
        )
    }
}

suspend fun markAllNotificationsRead(api: ZekkeApi) {
    api.request(Method.POST, "/notifications/read", body = buildJsonObject { put("all", true) }, token = api.tokens.require())
}
