package zekke.core.interop

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.account.completeSignUp
import zekke.core.account.draftSignUp
import zekke.core.account.enrolThisDevice
import zekke.core.account.removeOtherDevices
import zekke.core.api.Method
import zekke.core.credentials.CredentialPayload
import zekke.core.credentials.decodeCredentialPayload
import zekke.core.credentials.encodeCredentialPayload
import zekke.core.credentials.listCredentials
import zekke.core.credentials.openCredential
import zekke.core.credentials.writeCredential
import zekke.core.files.ByteArrayUpload
import zekke.core.files.HttpObjectStore
import zekke.core.files.deleteFile
import zekke.core.files.downloadBytes
import zekke.core.files.uploadFile
import zekke.core.folders.FolderStore
import zekke.core.folders.ManifestScope
import zekke.core.folders.TreeScope
import zekke.core.folders.createFolder
import zekke.core.folders.createTreeFolder
import zekke.core.folders.deleteTreeFolder
import zekke.core.folders.getFolderManifest
import zekke.core.folders.listTreeFolderRecords
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.generateDek
import zekke.core.items.hashReceivedCiphertext
import zekke.core.items.newItemId
import zekke.core.items.signedBody
import zekke.core.notes.createNote
import zekke.core.notes.getNote
import zekke.core.notes.openNote
import zekke.core.rekey.getPreferencesRecord
import zekke.core.rekey.listWraps
import zekke.core.rekey.rewrapAfterRotation
import zekke.core.rekey.rewrapStale
import zekke.core.scopes.DEK_SCOPES
import zekke.core.scopes.Scope
import zekke.core.sealed.sealText
import zekke.core.secrets.createSecret
import zekke.core.secrets.deleteSecret
import zekke.core.secrets.getSecret
import zekke.core.secrets.openSecret
import zekke.core.signing.Action
import zekke.core.trash.getTrashKeys
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RekeyInteropTest {
    private suspend fun createDocument(context: ItemContext): String {
        val id = newItemId()
        generateDek().use { dek ->
            val wrapped = ScopeDeks(context, Scope.DOCUMENTS).wrap(dek)
            val body = buildJsonObject {
                put("id", id)
                put("wrapped_dek", wrapped.wrappedDek)
                put("key_generation", wrapped.keyGeneration)
                put("version", "v1")
            }
            context.api.request(Method.POST, "/documents", body = body, token = context.api.tokens.require())
        }
        return id
    }

    private suspend fun trashDocument(context: ItemContext, id: String) {
        context.api.request(Method.DELETE, "/documents/$id", body = signedBody(context, Action.DOCUMENT_DELETE, listOf(id)), token = context.api.tokens.require())
    }

    private suspend fun storePreferences(context: ItemContext) {
        generateDek().use { dek ->
            val wrapped = ScopeDeks(context, Scope.DOCUMENTS).wrap(dek)
            val ciphertext = sealText("{\"version\":1,\"regional\":{\"country\":\"BR\"}}", dek)
            val body = signedBody(context, Action.PREFERENCES_UPDATE, listOf("0", hashReceivedCiphertext(ciphertext))) {
                put("ciphertext", ciphertext)
                put("wrapped_dek", wrapped.wrappedDek)
                put("key_generation", wrapped.keyGeneration)
                put("expected_revision", 0)
            }
            context.api.request(Method.PUT, "/preferences", body = body, token = context.api.tokens.require())
        }
    }

    private suspend fun generationsLeft(context: ItemContext): Map<String, Set<Int>> {
        val found = linkedMapOf<String, Set<Int>>()
        for (scope in DEK_SCOPES) found[scope.wire] = listWraps(context, scope).map { it.keyGeneration }.toSet()
        for (tree in TreeScope.entries) {
            found["${tree.wire} folders"] = (listTreeFolderRecords(context, tree).map { it.keyGeneration } + getTrashKeys(context, tree).folders.map { it.keyGeneration }).toSet()
        }
        for (manifest in ManifestScope.entries) found["${manifest.wire} tabs"] = setOfNotNull(getFolderManifest(context, manifest)?.keyGeneration)
        found["preferences"] = setOfNotNull(getPreferencesRecord(context)?.keyGeneration)
        return found
    }

    @Test
    fun afterARemovalSignedHereNoItemOfAnyScopeIsLeftUnderTheOldGeneration() = runBlocking {
        val words = newPhrase()
        val phone = Phone()
        patiently { completeSignUp(phone.services, draftSignUp(phraseCopy(words)), "428193".toCharArray(), paranoid = false) }
        grantPremium(phone)
        val context = ItemContext(phone.api, phone.services.session)
        HttpObjectStore().use { store ->
            try {
                val secret = createSecret(context, "{\"name\":\"a\",\"value\":\"b\"}").secret.id
                deleteSecret(context, createSecret(context, "{\"name\":\"gone\",\"value\":\"c\"}").secret.id)
                val note = createNote(context, "# antes da rotação").note.id
                val credential = writeCredential(context, encodeCredentialPayload(CredentialPayload("example.com", "ana", "um"))).revision.credentialId
                writeCredential(context, encodeCredentialPayload(CredentialPayload("example.com", "ana", "dois")), credentialId = credential)
                val photo = ByteArray(70_000) { (it % 199).toByte() }
                val file = uploadFile(context, ByteArrayUpload("a.bin", "application/octet-stream", photo), store).id
                deleteFile(context, uploadFile(context, ByteArrayUpload("b.bin", "application/octet-stream", photo), store).id)
                val keptFolder = createTreeFolder(context, TreeScope.FILES, "Mantida", null).id
                deleteTreeFolder(context, TreeScope.FILES, createTreeFolder(context, TreeScope.FILES, "Apagada", null).id)
                createTreeFolder(context, TreeScope.DOCUMENTS, "Contratos", null)
                createDocument(context)
                trashDocument(context, createDocument(context))
                FolderStore(context).use { tabs ->
                    tabs.edit(ManifestScope.SECRETS, createFolder("Banco"))
                    tabs.edit(ManifestScope.NOTES, createFolder("Viagem"))
                }
                storePreferences(context)
                val before = generationsLeft(context)
                assertTrue(before.values.all { it == setOf(1) }, "every kind of row starts at generation 1: $before")

                val other = Phone()
                patiently { enrolThisDevice(other.services, phraseCopy(words), "739164".toCharArray()) }
                val rotated = patiently { removeOtherDevices(phone.services, phraseCopy(words), listOf(other.services.session.deviceId)) }
                assertTrue(rotated.containsAll(DEK_SCOPES), "the removal rotated $rotated")

                val outcomes = rewrapAfterRotation(context, rotated).associateBy { it.scope }
                assertEquals(2, outcomes.getValue(Scope.SECRETS).rekeyed)
                assertEquals(2, outcomes.getValue(Scope.PASSWORDS).rekeyed)
                assertEquals(1, outcomes.getValue(Scope.DOCUMENTS).preferences)
                assertEquals(1, outcomes.getValue(Scope.NOTES).folders)

                val after = generationsLeft(context)
                assertTrue(after.values.all { it == setOf(2) }, "every row moved to generation 2: $after")
                assertTrue(rewrapStale(context).all { it.requested == 0 })

                assertEquals("{\"name\":\"a\",\"value\":\"b\"}", openSecret(context, getSecret(context, secret)))
                assertEquals("# antes da rotação", openNote(context, getNote(context, note)))
                assertTrue(downloadBytes(context, file, store).bytes.contentEquals(photo))
                assertEquals("dois", decodeCredentialPayload(openCredential(context, listCredentials(context).single())).password)
                assertTrue(listTreeFolderRecords(context, TreeScope.FILES).any { it.id == keptFolder })
            } finally {
                deleteWithPhrase(phone, words)
            }
        }
    }
}
