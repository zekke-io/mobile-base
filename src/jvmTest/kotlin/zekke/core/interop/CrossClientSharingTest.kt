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
import zekke.core.files.uploadFile
import zekke.core.items.ItemContext
import zekke.core.scopes.ScopedItemType
import zekke.core.secrets.SecretPayload
import zekke.core.secrets.createSecret
import zekke.core.secrets.encodeSecretPayload
import zekke.core.sharing.SharingService
import zekke.core.sharing.listInbox
import zekke.core.users.getMe
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals

class CrossClientSharingTest {
    private val directory = System.getProperty("zekke.crossclient.dir").orEmpty()
    private val step = System.getProperty("zekke.crossclient.step").orEmpty()

    private fun phrase(words: List<CharArray>) = words.joinToString(" ") { String(it) }

    @Test
    fun coreSharesASecretAndAFileWithAnAccountTheWebAppWillOpen() = runBlocking<Unit> {
        assumeTrue(directory.isNotEmpty() && step == "core-share")
        val anaWords = newPhrase()
        val biaWords = newPhrase()
        val ana = Phone()
        val bia = Phone()
        patiently { completeSignUp(ana.services, draftSignUp(phraseCopy(anaWords)), "428193".toCharArray(), paranoid = false) }
        patiently { completeSignUp(bia.services, draftSignUp(phraseCopy(biaWords)), "739164".toCharArray(), paranoid = false) }
        val anaSharing = SharingService(ItemContext(ana.api, ana.services.session))
        val biaSharing = SharingService(ItemContext(bia.api, bia.services.session))
        anaSharing.inviteByUsername(getMe(bia.api).username)
        biaSharing.acceptInvitation(biaSharing.connections().single())
        val connection = anaSharing.connections().single()
        val anaContext = ItemContext(ana.api, ana.services.session)
        val secretId = createSecret(anaContext, encodeSecretPayload(SecretPayload("Wi-Fi de casa", "zekke-2026"))).secret.id
        val photo = ByteArray(150_000) { ((it * 17 + 3) % 256).toByte() }
        val fileId = HttpObjectStore().use { uploadFile(anaContext, ByteArrayUpload("planta.pdf", "application/pdf", photo), it).id }
        anaSharing.shareItemById(connection, ScopedItemType.SECRET, secretId)
        anaSharing.shareItemById(connection, ScopedItemType.FILE, fileId)
        File(directory, "core.json").writeText(
            buildJsonObject {
                put("ana_mnemonic", phrase(anaWords))
                put("bia_mnemonic", phrase(biaWords))
                put("ana_username", getMe(ana.api).username)
                put("secret_name", "Wi-Fi de casa")
                put("secret_value", "zekke-2026")
                put("file_name", "planta.pdf")
                put("file_sha256", bytesToHex(MessageDigest.getInstance("SHA-256").digest(photo)))
            }.toString(),
        )
    }

    @Test
    fun coreOpensWhatTheWebAppSharedBackAndDeletesBothAccounts() = runBlocking<Unit> {
        assumeTrue(directory.isNotEmpty() && step == "core-verify")
        val core = Json.parseToJsonElement(File(directory, "core.json").readText()).jsonObject
        val web = Json.parseToJsonElement(File(directory, "web.json").readText()).jsonObject
        val anaWords = core.getValue("ana_mnemonic").jsonPrimitive.content.split(' ').map { it.toCharArray() }
        val biaWords = core.getValue("bia_mnemonic").jsonPrimitive.content.split(' ').map { it.toCharArray() }
        val ana = Phone()
        try {
            patiently { enrolThisDevice(ana.services, phraseCopy(anaWords), "615283".toCharArray()) }
            val sharing = SharingService(ItemContext(ana.api, ana.services.session))
            val connection = sharing.connections().single()
            val share = listInbox(ItemContext(ana.api, ana.services.session)).single { it.id == web.getValue("share_id").jsonPrimitive.content }
            val received = sharing.describeReceived(share, connection)
            assertEquals(web.getValue("text").jsonPrimitive.content, received.text)
            assertEquals(web.getValue("title").jsonPrimitive.content, received.name)
        } finally {
            deleteWithPhrase(ana, anaWords)
            val bia = Phone()
            patiently { enrolThisDevice(bia.services, phraseCopy(biaWords), "615284".toCharArray()) }
            deleteWithPhrase(bia, biaWords)
        }
    }

    @Test
    fun coreDeletesWhateverAccountsTheExchangeLeftBehind() = runBlocking<Unit> {
        assumeTrue(directory.isNotEmpty() && step == "core-cleanup")
        val core = Json.parseToJsonElement(File(directory, "core.json").readText()).jsonObject
        for (key in listOf("ana_mnemonic", "bia_mnemonic")) {
            val words = core.getValue(key).jsonPrimitive.content.split(' ').map { it.toCharArray() }
            val phone = Phone()
            val entered = runCatching { patiently { enrolThisDevice(phone.services, phraseCopy(words), "615285".toCharArray()) } }
            if (entered.isSuccess) deleteWithPhrase(phone, words)
        }
    }
}
