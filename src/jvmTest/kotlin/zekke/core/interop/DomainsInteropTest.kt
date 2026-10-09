package zekke.core.interop

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import zekke.core.account.completeSignUp
import zekke.core.account.draftSignUp
import zekke.core.account.enrolThisDevice
import zekke.core.credentials.CredentialPayload
import zekke.core.credentials.credentialHistory
import zekke.core.credentials.credentialRevisions
import zekke.core.credentials.deleteCredential
import zekke.core.credentials.deletedCredentials
import zekke.core.credentials.syncAllRevisions
import zekke.core.credentials.encodeCredentialPayload
import zekke.core.credentials.passwordsView
import zekke.core.credentials.purgeDeletedCredential
import zekke.core.credentials.restoreCredential
import zekke.core.credentials.writeCredential
import zekke.core.feed.Feed
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Outbox
import zekke.core.feed.OutboxStop
import zekke.core.feed.Replica
import zekke.core.feed.outboxSchema
import zekke.core.feed.replicaSchema
import zekke.core.folders.FolderStore
import zekke.core.folders.HOME_FOLDER_ID
import zekke.core.folders.ManifestScope
import zekke.core.folders.createFolder
import zekke.core.folders.folderOf
import zekke.core.folders.liveFolders
import zekke.core.folders.placeItem
import zekke.core.folders.renameFolder
import zekke.core.items.ItemContext
import zekke.core.notes.deleteNotes
import zekke.core.notes.noteRecords
import zekke.core.notes.noteTiles
import zekke.core.notes.openNote
import zekke.core.notes.queueNewNote
import zekke.core.notes.queueNoteEdit
import zekke.core.notes.saveNote
import zekke.core.notes.updateNote
import zekke.core.secrets.SecretPayload
import zekke.core.secrets.createSecret
import zekke.core.secrets.deleteSecret
import zekke.core.secrets.encodeSecretPayload
import zekke.core.secrets.listDeletedSecrets
import zekke.core.secrets.purgeSecrets
import zekke.core.secrets.restoreSecret
import zekke.core.secrets.vaultView
import zekke.core.items.newItemId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DomainsInteropTest {
    private class Device(val phone: Phone) {
        val context = ItemContext(phone.api, phone.services.session)
        val replica = Replica(JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY).also { replicaSchema.create(it) }, phone.services.session.userAddress)
        val feed = Feed(replica, phone.services.session, phone.api, CoroutineScope(Dispatchers.Default))

        suspend fun sync(scope: FeedScope) {
            patiently { feed.sync(scope) }
        }
    }

    private data class TwoDevices(val words: List<CharArray>, val a: Device, val b: Device)

    private suspend fun account(): TwoDevices {
        val words = newPhrase()
        val first = Phone()
        patiently { completeSignUp(first.services, draftSignUp(phraseCopy(words)), "428193".toCharArray(), paranoid = false) }
        val second = Phone()
        patiently { enrolThisDevice(second.services, phraseCopy(words), "739164".toCharArray()) }
        return TwoDevices(words, Device(first), Device(second))
    }

    private suspend fun withAccount(block: suspend (TwoDevices) -> Unit) {
        val pair = account()
        try {
            block(pair)
        } finally {
            pair.a.feed.close()
            pair.b.feed.close()
            deleteWithPhrase(pair.a.phone, pair.words)
        }
    }

    @Test
    fun aSecretTravelsBothWaysThroughRecentlyDeletedRestoreAndPurge() = runBlocking {
        withAccount { (_, a, b) ->
            val id = patiently { createSecret(b.context, encodeSecretPayload(SecretPayload("Bank", "correct horse"))) }.secret.id
            a.sync(FeedScope.SECRETS)
            val arrived = vaultView(a.context, a.replica)
            assertEquals(listOf("Bank" to "correct horse"), arrived.rows.map { it.name to it.value })

            patiently { deleteSecret(a.context, id) }
            b.sync(FeedScope.SECRETS)
            val deletedOnB = vaultView(b.context, b.replica)
            assertEquals(emptyList(), deletedOnB.rows.map { it.id })
            assertEquals(listOf(id to "Bank"), deletedOnB.deleted.map { it.id to it.name })
            assertEquals(listOf(id), patiently { listDeletedSecrets(b.context) }.map { it.id })

            patiently { restoreSecret(b.context, id) }
            a.sync(FeedScope.SECRETS)
            assertEquals(listOf("Bank"), vaultView(a.context, a.replica).rows.map { it.name })

            patiently { deleteSecret(a.context, id) }
            patiently { purgeSecrets(b.context, listOf(id)) }
            a.sync(FeedScope.SECRETS)
            b.sync(FeedScope.SECRETS)
            for (device in listOf(a, b)) {
                val view = vaultView(device.context, device.replica)
                assertTrue(view.rows.isEmpty() && view.deleted.isEmpty())
            }
        }
    }

    @Test
    fun aNoteWrittenOnOneDeviceIsEditedOnTheOtherAndTheOutboxSendsOne() = runBlocking {
        withAccount { (_, a, b) ->
            val id = newItemId()
            patiently { saveNote(a.context, "# Plans\n- [ ] pack", id) }
            b.sync(FeedScope.NOTES)
            assertEquals(listOf("Plans"), noteTiles(b.context, b.replica).map { it.title })

            val held = noteRecords(b.replica.items(FeedScope.NOTES, ItemTypes.NOTE)).single { it.id == id }
            patiently { updateNote(b.context, held, "# Plans\n- [x] pack") }
            a.sync(FeedScope.NOTES)
            val edited = noteRecords(a.replica.items(FeedScope.NOTES, ItemTypes.NOTE)).single { it.id == id }
            assertEquals("# Plans\n- [x] pack", openNote(a.context, edited))
            assertEquals(held.wrappedDek, edited.wrappedDek)

            val outbox = Outbox(JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY).also { outboxSchema.create(it) }, a.context.session.userAddress)
            val queued = queueNewNote(a.context, outbox, "offline draft")
            queueNoteEdit(a.context, outbox, queued.id, queued.wrappedDek, queued.keyGeneration, "v1", "offline final")
            val flushed = patiently { outbox.flush(a.phone.api) }
            assertEquals(2, flushed.sent)
            assertEquals(OutboxStop.Drained, flushed.stop)
            b.sync(FeedScope.NOTES)
            val tiles = noteTiles(b.context, b.replica)
            assertEquals(1, tiles.count { it.id == queued.id })
            assertEquals("offline final", tiles.single { it.id == queued.id }.title)

            patiently { deleteNotes(b.context, listOf(id, queued.id)) }
            a.sync(FeedScope.NOTES)
            assertTrue(noteTiles(a.context, a.replica).isEmpty())
        }
    }

    @Test
    fun aPasswordIsEditedDeletedRestoredAndPurgedAcrossDevices() = runBlocking {
        withAccount { (_, a, b) ->
            val written = patiently { writeCredential(a.context, encodeCredentialPayload(CredentialPayload("example.com", "ana", "first"))) }
            val credentialId = written.revision.credentialId
            b.sync(FeedScope.PASSWORDS)
            assertEquals(listOf("first"), passwordsView(b.context, b.replica).rows.map { it.password })

            patiently { writeCredential(b.context, encodeCredentialPayload(CredentialPayload("example.com", "ana", "second")), credentialId = credentialId) }
            a.sync(FeedScope.PASSWORDS)
            assertEquals(listOf("second"), passwordsView(a.context, a.replica).rows.map { it.password })
            val revisions = credentialRevisions(a.replica.items(FeedScope.PASSWORDS, ItemTypes.CREDENTIAL))
            assertEquals(2, credentialHistory(revisions, credentialId).size)

            patiently { deleteCredential(a.context, credentialId) }
            b.sync(FeedScope.PASSWORDS)
            val deleted = passwordsView(b.context, b.replica)
            assertTrue(deleted.rows.isEmpty())
            assertEquals(listOf("example.com"), deleted.deleted.map { it.site })

            patiently { restoreCredential(b.context, deleted.deleted.single().deleted) }
            a.sync(FeedScope.PASSWORDS)
            assertEquals(listOf("second"), passwordsView(a.context, a.replica).rows.map { it.password })

            patiently { deleteCredential(a.context, credentialId) }
            b.sync(FeedScope.PASSWORDS)
            patiently { purgeDeletedCredential(b.context, passwordsView(b.context, b.replica).deleted.single().deleted) }
            val remaining = patiently { syncAllRevisions(a.context) }.filter { it.credentialId == credentialId }
            assertTrue(remaining.isNotEmpty() && remaining.all { it.deleted })
            assertTrue(deletedCredentials(remaining).isEmpty())
        }
    }

    @Test
    fun twoDevicesEditingTheTabsAtOnceKeepBothEdits() = runBlocking {
        withAccount { (_, a, b) ->
            val secretId = patiently { createSecret(a.context, encodeSecretPayload(SecretPayload("n", "v"))) }.secret.id
            val storeA = FolderStore(a.context)
            val storeB = FolderStore(b.context)
            try {
                patiently { storeA.edit(ManifestScope.SECRETS, createFolder("Work", id = "8d6b1f7e-2c4a-4f1b-9e3d-5a7c9b1d3f5e")) }
                b.sync(FeedScope.SECRETS)
                val seen = storeB.loadFromReplica(ManifestScope.SECRETS, b.replica)
                assertEquals(listOf(HOME_FOLDER_ID, "Work"), liveFolders(seen).map { if (it.id == HOME_FOLDER_ID) it.id else it.name })

                patiently { storeA.edit(ManifestScope.SECRETS, placeItem(secretId, "8d6b1f7e-2c4a-4f1b-9e3d-5a7c9b1d3f5e")) }
                val merged = patiently { storeB.edit(ManifestScope.SECRETS, renameFolder(HOME_FOLDER_ID, "Personal")) }
                assertEquals("Personal", merged.folders.getValue(HOME_FOLDER_ID).name)
                assertEquals("8d6b1f7e-2c4a-4f1b-9e3d-5a7c9b1d3f5e", folderOf(merged, secretId, ManifestScope.SECRETS.rules))

                val reread = patiently { storeA.load(ManifestScope.SECRETS, fresh = true) }
                assertEquals("Personal", reread.folders.getValue(HOME_FOLDER_ID).name)
            } finally {
                storeA.close()
                storeB.close()
            }
        }
    }
}
