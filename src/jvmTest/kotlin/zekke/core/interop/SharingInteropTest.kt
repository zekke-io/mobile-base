package zekke.core.interop

import kotlinx.coroutines.runBlocking
import zekke.core.account.completeSignUp
import zekke.core.account.draftSignUp
import zekke.core.account.enrolThisDevice
import zekke.core.account.removeOtherDevices
import zekke.core.api.ClientIdentity
import zekke.core.api.ClientPlatform
import zekke.core.api.ZekkeApi
import zekke.core.auth.signInDevice
import zekke.core.credentials.CredentialPayload
import zekke.core.credentials.decodeCredentialPayload
import zekke.core.credentials.encodeCredentialPayload
import zekke.core.credentials.listCredentials
import zekke.core.credentials.writeCredential
import zekke.core.device.deviceDeclaration
import zekke.core.device.deviceSecrets
import zekke.core.device.deviceSigner
import zekke.core.device.generateDeviceKeys
import zekke.core.files.ByteArrayUpload
import zekke.core.files.HttpObjectStore
import zekke.core.files.uploadFile
import zekke.core.folders.createFolder
import zekke.core.folders.folderOf
import zekke.core.folders.liveFolders
import zekke.core.folders.placeItem
import zekke.core.items.ItemContext
import zekke.core.keyrings.loadKeyrings
import zekke.core.keyrings.refreshKeyrings
import zekke.core.notes.createNote
import zekke.core.notifications.listNotifications
import zekke.core.pairing.ClaimedDevice
import zekke.core.pairing.PairingParties
import zekke.core.pairing.PairingStatus
import zekke.core.pairing.claimPairing
import zekke.core.pairing.claimStatus
import zekke.core.pairing.claimedDevice
import zekke.core.pairing.getPairing
import zekke.core.pairing.linkClaimedDevice
import zekke.core.pairing.openPairing
import zekke.core.pairing.ownerFingerprint
import zekke.core.pairing.pairingFingerprint
import zekke.core.scopes.Scope
import zekke.core.scopes.ScopedItemType
import zekke.core.secrets.SecretPayload
import zekke.core.secrets.createSecret
import zekke.core.secrets.encodeSecretPayload
import zekke.core.secrets.getSecret
import zekke.core.secrets.openSecret
import zekke.core.sealed.openText
import zekke.core.sharing.ConnectionDirection
import zekke.core.sharing.ConnectionTrust
import zekke.core.sharing.SHARED_FOLDER_RULES
import zekke.core.sharing.SharingService
import zekke.core.sharing.listInbox
import zekke.core.users.getMe
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SharingInteropTest {
    private class Account(val words: List<CharArray>, val phone: Phone) {
        val context = ItemContext(phone.api, phone.services.session)
        val sharing = SharingService(context)
    }

    private suspend fun account(pin: String): Account {
        val words = newPhrase()
        val phone = Phone()
        patiently { completeSignUp(phone.services, draftSignUp(phraseCopy(words)), pin.toCharArray(), paranoid = false) }
        return Account(words, phone)
    }

    @Test
    fun twoAccountsConnectShareBothWaysFileIntoFoldersAndSurviveARotation() = runBlocking {
        val ana = account("428193")
        val bia = account("739164")
        HttpObjectStore().use { store ->
            try {
                val biaName = getMe(bia.phone.api).username
                val draft = patiently { ana.sharing.inviteByUsername(biaName) }
                assertEquals(bia.sharing.ownRootFingerprint(), draft.fingerprint)

                val invitation = bia.sharing.connections().single()
                assertEquals(ConnectionDirection.INBOUND, invitation.direction)
                assertIs<ConnectionTrust.Unpinned>(bia.sharing.verifyConnection(invitation))
                bia.sharing.acceptInvitation(invitation)
                val toBia = ana.sharing.connections().single()
                assertIs<ConnectionTrust.Trusted>(ana.sharing.verifyConnection(toBia))
                val toAna = bia.sharing.connections().single()
                assertIs<ConnectionTrust.Trusted>(bia.sharing.verifyConnection(toAna))

                val secretId = createSecret(ana.context, encodeSecretPayload(SecretPayload("Banco", "senha forte"))).secret.id
                val noteId = createNote(ana.context, "# Viagem\nlevar passaporte").note.id
                val photo = ByteArray(200_000) { (it % 211).toByte() }
                val fileId = uploadFile(ana.context, ByteArrayUpload("mapa.png", "image/png", photo), store).id
                val shares = listOf(
                    ana.sharing.shareItemById(toBia, ScopedItemType.SECRET, secretId),
                    ana.sharing.shareItemById(toBia, ScopedItemType.NOTE, noteId),
                    ana.sharing.shareItemById(toBia, ScopedItemType.FILE, fileId),
                )

                val inbox = listInbox(bia.context)
                assertEquals(shares.map { it.id }.toSet(), inbox.map { it.id }.toSet())
                val described = inbox.associate { it.itemType to bia.sharing.describeReceived(it, toAna) }
                assertEquals("Banco" to "senha forte", described.getValue("secret").name to described.getValue("secret").text)
                assertEquals("Viagem", described.getValue("note").name)
                assertEquals("mapa.png" to 200_000L, described.getValue("file").name to described.getValue("file").sizeBytes)
                val fileShare = inbox.single { it.itemType == "file" }
                assertTrue(bia.sharing.openSharedFileBytes(toAna, fileShare.id, store).bytes.contentEquals(photo))

                val copied = bia.sharing.copySharedItem(toAna, inbox.single { it.itemType == "secret" }, store)
                assertEquals("{\"name\":\"Banco\",\"value\":\"senha forte\"}", openSecret(bia.context, getSecret(bia.context, copied.second)))

                val back = createNote(bia.context, "obrigada!").note.id
                val backShare = bia.sharing.shareItemById(toAna, ScopedItemType.NOTE, back)
                val both = ana.sharing.describeConnection(toBia)
                assertEquals(setOf(ConnectionDirection.OUTBOUND), both.filter { it.shareId in shares.map { s -> s.id } }.map { it.direction }.toSet())
                assertEquals("obrigada!", both.single { it.shareId == backShare.id }.text)
                assertTrue(both.all { it.readable })

                val folder = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
                ana.sharing.editSharedFolders(toBia, createFolder("Viagem 2026", id = folder))
                bia.sharing.editSharedFolders(toAna, placeItem(fileShare.id, folder))
                val seenByAna = ana.sharing.loadSharedFolders(toBia, fresh = true)
                assertEquals(listOf("Viagem 2026"), liveFolders(seenByAna).map { it.name })
                assertEquals(folder, folderOf(seenByAna, fileShare.id, SHARED_FOLDER_RULES))

                val second = Phone()
                patiently { enrolThisDevice(second.services, phraseCopy(bia.words), "615283".toCharArray()) }
                patiently { removeOtherDevices(bia.phone.services, phraseCopy(bia.words), listOf(second.services.session.deviceId)) }
                refreshKeyrings(bia.phone.api, bia.phone.services.session)

                val outcome = ana.sharing.reestablishConnection(toBia)
                assertTrue(outcome.reestablished)
                assertEquals(4, outcome.shares)
                val renewed = SharingService(bia.context)
                val connection = renewed.connections().single()
                assertTrue(listInbox(bia.context).all { renewed.describeReceived(it, connection).readable })
                assertEquals(folder, folderOf(renewed.loadSharedFolders(connection), fileShare.id, SHARED_FOLDER_RULES))
                val later = createNote(ana.context, "# Depois da rotação").note.id
                val after = ana.sharing.shareItemById(ana.sharing.connections().single(), ScopedItemType.NOTE, later)
                assertEquals("Depois da rotação", renewed.describeReceived(listInbox(bia.context).single { it.id == after.id }, connection).name)
            } finally {
                deleteWithPhrase(ana.phone, ana.words)
                deleteWithPhrase(bia.phone, bia.words)
            }
        }
    }

    @Test
    fun thePhoneLinksTheExtensionWhichReadsPasswordsAndNothingElse() = runBlocking {
        val owner = account("428193")
        try {
            val context = owner.context
            writeCredential(context, encodeCredentialPayload(CredentialPayload("example.com", "ana", "s3nha")))
            val opened = openPairing(owner.phone.api)

            val extensionKeys = generateDeviceKeys()
            val declaration = deviceDeclaration(extensionKeys, listOf(Scope.PASSWORDS))
            val extensionApi = ZekkeApi(baseUrl = interopApi, clientIdentity = ClientIdentity(ClientPlatform.EXTENSION, "0.1.0"))
            val claimed = claimPairing(
                extensionApi,
                opened.code,
                ClaimedDevice(declaration.deviceId, declaration.signingPublicKey, declaration.x25519PublicKey, declaration.mlkemPublicKey),
            )
            val extensionSide = pairingFingerprint(
                PairingParties(opened.code, claimed.userAddress, claimed.rootPublicKey, declaration.deviceId, declaration.signingPublicKey, declaration.x25519PublicKey, declaration.mlkemPublicKey),
            )

            val device = claimedDevice(getPairing(owner.phone.api, opened.id))
            assertEquals(extensionSide, ownerFingerprint(context, opened.code, device))
            linkClaimedDevice(context, opened.id, device)
            assertEquals(PairingStatus.LINKED, claimStatus(extensionApi, claimed.claimId))

            val grant = signInDevice(extensionApi, declaration.deviceId, deviceSigner(extensionKeys))
            extensionApi.tokens.set(grant.accessToken)
            val keyrings = loadKeyrings(extensionApi, claimed.userAddress, deviceSecrets(extensionKeys))
            assertEquals(setOf(Scope.PASSWORDS), keyrings.entries.map { it.scope }.toSet())
            val revision = listCredentials(ItemContext(extensionApi, owner.phone.services.session)).single()
            val kek = keyrings.entries.single { it.generation == revision.keyGeneration }.kek
            val plaintext = zekke.core.sealed.openSecretBlob(revision.wrappedDek, kek).use { openText(revision.ciphertext, it) }
            assertEquals("s3nha", decodeCredentialPayload(plaintext).password)
            val refused = runCatching { extensionApi.request(zekke.core.api.Method.GET, "/secrets", token = extensionApi.tokens.require()) }.exceptionOrNull()
            assertEquals(404, (refused as zekke.core.api.ApiError).status)
            assertEquals(0, listNotifications(owner.phone.api).unreadCount)
        } finally {
            deleteWithPhrase(owner.phone, owner.words)
        }
    }
}
