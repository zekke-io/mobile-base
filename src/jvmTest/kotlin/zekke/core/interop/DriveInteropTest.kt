package zekke.core.interop

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import zekke.core.account.completeSignUp
import zekke.core.account.draftSignUp
import zekke.core.account.enrolThisDevice
import zekke.core.api.Method
import zekke.core.encoding.base64UrlToBytes
import zekke.core.encoding.bytesToHex
import zekke.core.feed.Feed
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Replica
import zekke.core.feed.replicaSchema
import zekke.core.files.ByteArrayUpload
import zekke.core.files.ByteRange
import zekke.core.files.ByteSource
import zekke.core.files.CHUNK_STRIDE_BYTES
import zekke.core.files.HttpObjectStore
import zekke.core.files.ObjectStore
import zekke.core.files.R2States
import zekke.core.files.UploadOptions
import zekke.core.files.UploadPart
import zekke.core.files.UploadSource
import zekke.core.files.deleteFiles
import zekke.core.files.downloadBytes
import zekke.core.files.downloadFile
import zekke.core.files.driveView
import zekke.core.files.fileRecords
import zekke.core.files.listFiles
import zekke.core.files.openPreview
import zekke.core.files.renameFile
import zekke.core.files.resumeUpload
import zekke.core.files.uploadFile
import zekke.core.files.uploadToDrive
import zekke.core.folders.TreeScope
import zekke.core.folders.createTreeFolder
import zekke.core.folders.treeFoldersFromReplica
import zekke.core.items.ItemContext
import zekke.core.items.newItemId
import zekke.core.trash.listFileTrash
import zekke.core.trash.purgeEntries
import zekke.core.trash.restoreEntries
import zekke.core.users.getMe
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest

class DriveInteropTest {
    private val mib = 1 shl 20
    private val driveBytes: Long = System.getProperty("zekke.interop.driveBytes")?.toLong() ?: (1L shl 30)
    private val dropAfterParts = 40

    private class Generated(override val name: String, override val size: Long, private val seed: Int) : UploadSource {
        override val mime = "application/octet-stream"

        override suspend fun open(): ByteSource = object : ByteSource {
            private var state = seed.toLong() and 0xffffffffL or 1L
            private var at = 0L

            override suspend fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                if (at >= size) return -1
                val take = minOf(length.toLong(), size - at).toInt()
                for (i in 0 until take) {
                    state = state xor (state shl 13) and 0xffffffffL
                    state = state xor (state ushr 17)
                    state = state xor (state shl 5) and 0xffffffffL
                    buffer[offset + i] = state.toByte()
                }
                at += take
                return take
            }

            override fun close() {}
        }
    }

    private suspend fun digestOf(source: UploadSource): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(mib)
        source.open().use { input ->
            while (true) {
                val read = input.read(buffer, 0, buffer.size)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return bytesToHex(digest.digest())
    }

    private class Dropping(private val inner: ObjectStore, private val dropAfter: Int? = null) : ObjectStore {
        var puts = 0

        override suspend fun put(part: UploadPart, body: ByteArray) {
            if (dropAfter != null && puts >= dropAfter) throw java.io.IOException("connection dropped")
            inner.put(part, body)
            puts++
        }

        override suspend fun <T> read(url: String, range: ByteRange?, block: suspend (ByteSource) -> T): T = inner.read(url, range, block)
    }

    private class Account(val words: List<CharArray>, val phone: Phone) {
        val context = ItemContext(phone.api, phone.services.session)
    }

    private suspend fun premiumAccount(): Account {
        val words = newPhrase()
        val phone = Phone()
        patiently { completeSignUp(phone.services, draftSignUp(phraseCopy(words)), "428193".toCharArray(), paranoid = false) }
        grantPremium(phone)
        return Account(words, phone)
    }

    private suspend fun secondDevice(account: Account): ItemContext {
        val other = Phone()
        patiently { enrolThisDevice(other.services, phraseCopy(account.words), "739164".toCharArray()) }
        return ItemContext(other.api, other.services.session)
    }

    @Test
    fun aLargeUploadDroppedMidwayResumesOnlyWhatIsMissingAndDownloadsIdenticalElsewhere() = runBlocking {
        val account = premiumAccount()
        HttpObjectStore().use { http ->
            try {
                val big = Generated("big.bin", driveBytes, 0x5eed)
                val expected = digestOf(big)
                val id = newItemId()

                val dropped = Dropping(http, dropAfterParts)
                assertFailsWith<java.io.IOException> { uploadFile(account.context, big, dropped, id, options = UploadOptions(concurrency = 1)) }
                assertEquals(dropAfterParts, dropped.puts)
                val pending = listFiles(account.context).single { it.id == id }
                assertEquals(R2States.PENDING, pending.r2State)

                val resumed = Dropping(http)
                val stored = resumeUpload(account.context, pending, big, resumed)
                assertEquals(R2States.OK, stored.r2State)
                val totalParts = ((stored.sizeBytes + CHUNK_STRIDE_BYTES - 1) / CHUNK_STRIDE_BYTES).toInt()
                assertEquals(totalParts - dropAfterParts, resumed.puts)

                val second = secondDevice(account)
                val digest = MessageDigest.getInstance("SHA-256")
                var length = 0L
                downloadFile(second, id, http, { bytes, offset, count ->
                    digest.update(bytes, offset, count)
                    length += count
                })
                assertEquals(driveBytes, length)
                assertEquals(expected, bytesToHex(digest.digest()))
            } finally {
                deleteWithPhrase(account.phone, account.words)
            }
        }
    }

    @Test
    fun aFileWithItsThumbnailInAFolderTravelsToTheOtherDeviceAndThroughTheTrash() = runBlocking {
        val account = premiumAccount()
        HttpObjectStore().use { http ->
            try {
                val folder = patiently { createTreeFolder(account.context, TreeScope.FILES, "Férias", null) }
                val photo = ByteArray(300_000) { (it % 253).toByte() }
                val thumbnail = ByteArray(20_000) { (it % 7).toByte() }
                val uploaded = uploadToDrive(account.context, ByteArrayUpload("praia.jpg", "image/jpeg", photo), http, folder.id, thumbnail)
                val thumbnailId = uploaded.thumbnailId!!

                val second = secondDevice(account)
                val replica = Replica(JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY).also { replicaSchema.create(it) }, second.session.userAddress)
                val feed = Feed(replica, second.session, second.api, CoroutineScope(Dispatchers.Default))
                try {
                    patiently { feed.sync(FeedScope.FILES) }
                    val folders = treeFoldersFromReplica(second, TreeScope.FILES, replica.items(FeedScope.FILES, TreeScope.FILES.folderItemType))
                    assertEquals(listOf("Férias"), folders.map { it.name })
                    val view = driveView(second, replica)
                    val file = view.inFolder(folder.id).single()
                    assertEquals("praia.jpg", file.name)
                    assertEquals(thumbnailId, file.thumbnailId)
                    assertTrue(view.live.none { it.id == thumbnailId })
                    assertTrue(downloadBytes(second, file.id, http).bytes.contentEquals(photo))
                    val preview = openPreview(second, fileRecords(replica.items(FeedScope.FILES, ItemTypes.FILE)).single { it.id == thumbnailId }, http)
                    assertTrue(preview.bytes.contentEquals(thumbnail))

                    renameFile(second, file.id, "praia-2026.jpg")
                    assertEquals("praia-2026.jpg", downloadBytes(account.context, file.id, http).manifest.name)

                    assertTrue(getMe(account.phone.api).retentionDays > 0)
                    deleteFiles(account.context, listOf(file.id, thumbnailId))
                    val trashed = listFileTrash(second).single()
                    assertEquals("praia-2026.jpg" to listOf(thumbnailId), trashed.name to trashed.companions)
                    assertEquals(2, restoreEntries(second, listOf(trashed)))
                    assertEquals(setOf(file.id, thumbnailId), listFiles(account.context).map { it.id }.toSet())
                    deleteFiles(account.context, listOf(file.id, thumbnailId))
                    assertEquals(2, purgeEntries(second, listFileTrash(second)))
                    assertTrue(listFileTrash(account.context).isEmpty())
                } finally {
                    feed.close()
                }
            } finally {
                deleteWithPhrase(account.phone, account.words)
            }
        }
    }
}
