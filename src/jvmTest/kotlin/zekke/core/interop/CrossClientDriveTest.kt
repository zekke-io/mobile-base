package zekke.core.interop

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assume.assumeTrue
import zekke.core.account.completeSignUp
import zekke.core.account.draftSignUp
import zekke.core.account.enrolThisDevice
import zekke.core.encoding.bytesToHex
import zekke.core.files.ByteArrayUpload
import zekke.core.files.HttpObjectStore
import zekke.core.files.downloadBytes
import zekke.core.files.getFileDownload
import zekke.core.files.listFiles
import zekke.core.files.openPreview
import zekke.core.folders.TreeScope
import zekke.core.folders.createTreeFolder
import zekke.core.files.uploadToDrive
import zekke.core.items.ItemContext
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals

class CrossClientDriveTest {
    private val directory = System.getProperty("zekke.crossclient.dir").orEmpty()
    private val step = System.getProperty("zekke.crossclient.step").orEmpty()

    private fun sha256(bytes: ByteArray) = bytesToHex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun photo() = ByteArray(500_000) { ((it * 37 + 11) % 256).toByte() }

    private fun thumbnail() = ByteArray(18_000) { ((it * 13 + 5) % 256).toByte() }

    @Test
    fun coreUploadsAFileWithAThumbnailForTheWebApp() = runBlocking<Unit> {
        assumeTrue(directory.isNotEmpty() && step == "core-upload")
        val words = newPhrase()
        val phone = Phone()
        patiently { completeSignUp(phone.services, draftSignUp(phraseCopy(words)), "428193".toCharArray(), paranoid = false) }
        val context = ItemContext(phone.api, phone.services.session)
        HttpObjectStore().use { store ->
            val folder = createTreeFolder(context, TreeScope.FILES, "Do celular", null)
            val uploaded = uploadToDrive(context, ByteArrayUpload("foto do celular.jpg", "image/jpeg", photo()), store, folder.id, thumbnail())
            File(directory, "core.json").writeText(
                buildJsonObject {
                    put("mnemonic", words.joinToString(" ") { String(it) })
                    put("file_id", uploaded.file.id)
                    put("thumbnail_id", uploaded.thumbnailId)
                    put("folder_id", folder.id)
                    put("name", "foto do celular.jpg")
                    put("sha256", sha256(photo()))
                    put("thumbnail_sha256", sha256(thumbnail()))
                }.toString(),
            )
        }
    }

    @Test
    fun coreOpensWhatTheWebAppUploadedAndDeletesTheAccount() = runBlocking<Unit> {
        assumeTrue(directory.isNotEmpty() && step == "core-verify")
        val core = Json.parseToJsonElement(File(directory, "core.json").readText()).jsonObject
        val web = Json.parseToJsonElement(File(directory, "web.json").readText()).jsonObject
        val words = core.getValue("mnemonic").jsonPrimitive.content.split(' ').map { it.toCharArray() }
        val phone = Phone()
        try {
            patiently { enrolThisDevice(phone.services, phraseCopy(words), "615283".toCharArray()) }
            val context = ItemContext(phone.api, phone.services.session)
            HttpObjectStore().use { store ->
                val downloaded = downloadBytes(context, web.getValue("file_id").jsonPrimitive.content, store)
                assertEquals(web.getValue("name").jsonPrimitive.content, downloaded.manifest.name)
                assertEquals(web.getValue("sha256").jsonPrimitive.content, sha256(downloaded.bytes))
                val thumbnailId = web.getValue("thumbnail_id").jsonPrimitive.content
                assertEquals(thumbnailId, downloaded.manifest.thumbnailId)
                val record = listFiles(context).single { it.id == thumbnailId }
                assertEquals(web.getValue("thumbnail_sha256").jsonPrimitive.content, sha256(openPreview(context, record, store).bytes))
                getFileDownload(context, core.getValue("file_id").jsonPrimitive.content)
            }
        } finally {
            deleteWithPhrase(phone, words)
        }
    }
}
