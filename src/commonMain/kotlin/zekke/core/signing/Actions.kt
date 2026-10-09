package zekke.core.signing

enum class SignerRole { ROOT, DEVICE }

enum class Action(
    val label: String,
    val args: List<String>,
    val signer: SignerRole,
    val pinProof: Boolean,
    val variadic: Boolean = false,
) {
    CHAIN_READ("chain-read", listOf("user_address"), SignerRole.ROOT, pinProof = true),
    DEVICE_ENROL("device-enrol", listOf("user_address", "batch_digest"), SignerRole.ROOT, pinProof = true),
    ACCOUNT_DELETE("account-delete", listOf("user_address"), SignerRole.ROOT, pinProof = true),
    SECOND_FACTOR_BEGIN("second-factor-begin", listOf("user_address", "blinded_element"), SignerRole.ROOT, pinProof = true),
    ENABLE_SECOND_FACTOR("enable-second-factor", listOf("proof_public_key"), SignerRole.ROOT, pinProof = false),
    ROTATE_SECOND_FACTOR("rotate-second-factor", listOf("proof_public_key"), SignerRole.ROOT, pinProof = true),
    PIN_EVALUATE("pin-evaluate", listOf("user_address", "blinded_element"), SignerRole.ROOT, pinProof = false),
    USERNAME_UPDATE("username-update", listOf("username"), SignerRole.DEVICE, pinProof = false),
    SECRET_DELETE("secret-delete", listOf("secret_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    SECRET_PURGE("secret-purge", listOf("secret_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    NOTE_DELETE("note-delete", listOf("note_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    DOCUMENT_DELETE("document-delete", listOf("document_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    FILE_DELETE("file-delete", listOf("file_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    DOCUMENT_PURGE("document-purge", listOf("document_or_folder_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    FILE_PURGE("file-purge", listOf("file_or_folder_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    SECRET_REKEY("secret-rekey", listOf("secret_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    NOTE_REKEY("note-rekey", listOf("note_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    DOCUMENT_REKEY("document-rekey", listOf("document_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    FILE_REKEY("file-rekey", listOf("file_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    DOCUMENT_FOLDER_REKEY("document-folder-rekey", listOf("folder_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    FILE_FOLDER_REKEY("file-folder-rekey", listOf("folder_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    CREDENTIAL_DELETE("credential-delete", listOf("credential_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    CREDENTIAL_PRUNE("credential-prune", listOf("credential_id", "keep_last"), SignerRole.DEVICE, pinProof = false),
    CREDENTIAL_REKEY("credential-rekey", listOf("revision_id"), SignerRole.DEVICE, pinProof = false, variadic = true),
    CONNECTION_INVITE(
        "connection-invite",
        listOf("recipient_username", "pqxdh_blob", "sender_key_generation", "recipient_key_generation"),
        SignerRole.DEVICE,
        pinProof = false,
    ),
    CONNECTION_ACCEPT("connection-accept", listOf("connection_id"), SignerRole.DEVICE, pinProof = false),
    CONNECTION_DELETE("connection-delete", listOf("connection_id"), SignerRole.DEVICE, pinProof = false),
    CONNECTION_KEYS("connection-keys", listOf("connection_id", "keys_digest"), SignerRole.DEVICE, pinProof = false),
    CONNECTION_REESTABLISH(
        "connection-reestablish",
        listOf("connection_id", "pqxdh_blob", "sender_key_generation", "recipient_key_generation"),
        SignerRole.DEVICE,
        pinProof = false,
    ),
    SHARE_CREATE("share-create", listOf("connection_id", "item_type", "item_id"), SignerRole.DEVICE, pinProof = false),
    SHARE_DELETE("share-delete", listOf("share_id"), SignerRole.DEVICE, pinProof = false),
    ADDRESS_BOOK_UPDATE("address-book-update", listOf("expected_revision", "ciphertext_digest"), SignerRole.DEVICE, pinProof = false),
    CONNECTION_FOLDERS_UPDATE(
        "connection-folders-update",
        listOf("connection_id", "expected_revision", "recipient_key_generation", "ciphertext_digest"),
        SignerRole.DEVICE,
        pinProof = false,
    ),
    FOLDER_DELETE("folder-delete", listOf("scope", "folder_id"), SignerRole.DEVICE, pinProof = false),
    FOLDERS_UPDATE("folders-update", listOf("scope", "expected_revision", "ciphertext_digest"), SignerRole.DEVICE, pinProof = false),
    PREFERENCES_UPDATE("preferences-update", listOf("expected_revision", "ciphertext_digest"), SignerRole.DEVICE, pinProof = false),
    ;

    val refusesRepeatedIds: Boolean get() = variadic && label.endsWith("-rekey")
}

class InvalidActionArgumentsException(action: Action, reason: String) : IllegalArgumentException("${action.label}: $reason")

fun normalizeActionArgs(action: Action, args: List<String>): List<String> {
    for (value in args) {
        if (value.isEmpty()) throw InvalidActionArgumentsException(action, "arguments must not be empty")
        if (':' in value) throw InvalidActionArgumentsException(action, "arguments must not contain \":\" — it is the field separator")
    }
    if (action.variadic) {
        if (args.isEmpty()) throw InvalidActionArgumentsException(action, "needs at least one ${action.args[0]}")
        val distinct = args.toSortedSet()
        if (action.refusesRepeatedIds && distinct.size != args.size) {
            throw InvalidActionArgumentsException(action, "a re-key batch names each id once")
        }
        return distinct.toList()
    }
    if (args.size != action.args.size) {
        throw InvalidActionArgumentsException(
            action,
            "expected ${action.args.size} argument(s) (${action.args.joinToString(", ")}), got ${args.size}",
        )
    }
    return args
}
