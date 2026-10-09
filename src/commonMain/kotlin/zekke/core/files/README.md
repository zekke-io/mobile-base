# `zekke.core.files` — the drive

The drive's format and the transport that carries it: the same objects, manifests and routes as
the web app's drive, so a file uploaded on one client opens on the other.

| File               | What                                                                                   |
| ------------------ | -------------------------------------------------------------------------------------- |
| `Layout.kt`        | The arithmetic (padding, chunk counts, stored sizes, byte ranges) and sealing one chunk |
| `FileManifest.kt`  | The sealed manifest, where a file's name lives, and the check against the row           |
| `FilesApi.kt`      | The routes and the wire types                                                           |
| `ObjectStore.kt`   | The bytes: presigned `PUT`s and `GET`s, and the sources and sinks the app provides      |
| `Upload.kt`        | The upload in one pass, and resuming one                                                |
| `Download.kt`      | Opening a file, streaming decryption, the ranged read                                   |
| `Drive.kt`         | Renaming, thumbnails, the upload the drive screen runs, and the drive view              |

## The object

```
chunk_plaintext = u32be(chunk_index) ‖ u32be(chunk_count) ‖ payload
chunk_object    = 0x01 ‖ iv(12) ‖ AES-256-GCM(DEK, iv, chunk_plaintext) ‖ tag(16)
```

The stored object is the chunks concatenated, nothing else.

|                | Value  | Why                                                                     |
| -------------- | ------ | ----------------------------------------------------------------------- |
| Chunk payload  | 8 MiB  | One chunk is one multipart part, and R2's smallest part is 5 MiB        |
| Chunk overhead | 37     | version 1, IV 12, **position header 8**, tag 16. Never 29               |
| Padding bucket | 64 KiB | What hides a file's real length from the server                         |

```
padded      = ceil(true_size / 65536) × 65536       (an empty file is one bucket)
chunk_count = ceil(padded / 8388608)
size_bytes  = padded + chunk_count × 37             (never chunk_count × stride)
```

Sizes are `Long`: a file can pass 2 GiB.

**A chunk is bound to its place.** `openChunk` takes the index and count it was read at and refuses
a header that disagrees (`ChunkPositionException`), so chunks swapped, dropped or taken from another
object fail; a chunk from another file fails its tag, because every file has its own DEK.

**The chunk IV is derived**, `0x00 × 8 ‖ u32be(index)`, so a chunk can be sealed again byte for byte
instead of held. That is safe only because **a drive DEK seals exactly one object**; nothing outside
this package uses a derived IV. The JDK and Android's Conscrypt refuse to encrypt twice with one key
and IV on the same `Cipher`, so on the JVM and Android the AES-GCM primitive builds a fresh `Cipher`
for every call ([`primitives`](../primitives/README.md)).

## The manifest

The name, the type and the **true length** are sealed under the file's DEK in the row's
`ciphertext`, as JSON: `name`, `mime`, `size`, `chunk_size`, `chunk_count`, `first_chunk_sha256`,
`thumbnail_id`, `created_at`. Fields this client does not know are kept, so a rename never drops
them. `assertManifestMatchesRow` refuses a manifest whose layout does not give the row's
`size_bytes` before anything is decrypted (`ManifestLayoutException`): almost always a fault in the
upload that wrote it, never reported as an attack.

## The bytes go to the store, not through the API

`ObjectStore` is the presigned-URL transport: `put(part, bytes)` and `read(url, range) { source }`.
`HttpObjectStore` is it over Ktor; tests use a store in memory. The app hands the core an
`UploadSource` (a name, a type, a size, and a `ByteSource` to read from: on Android a content URI's
stream, on iOS a file) and, for a download, a `PlaintextSink` (where the decrypted bytes go). Neither
needs the file in memory.

## Upload

`uploadFile(context, source, store, id, thumbnailId)`:

1. Seals chunk 0 and records its SHA-256 as `first_chunk_sha256`: the fingerprint a resume checks.
2. `POST /files` with the caller's id, the sealed manifest, the DEK wrapped under `files`, and the
   declared layout. **A replay of the id is the resume call**: an unfinished row is resumed, a
   finished one is checked against the source and returned.
3. Reads, pads, seals and hashes each chunk once, `PUT`ting up to three parts at a time. Memory is
   a function of the chunk size and the concurrency, never of the file.
4. `PATCH` with the SHA-256 of the whole object.

A source that produces fewer or more bytes than it declared is refused (`SourceLengthException`).
`abandonUpload` gives a reservation back; a `404` there is success.

**Resuming**, `resumeUpload(context, row, source, store)`, asks which parts the store already holds
and runs the same pass, sending only the missing ones while still sealing and hashing every chunk,
because the hash describes the whole object. Before sending anything it proves the source is the
same file: size, name, then chunk 0 sealed again against `first_chunk_sha256`
(`SourceMismatchException` with `SIZE`, `NAME`, `CONTENT`, or `NOT_RESUMABLE` for a manifest
without the fingerprint). The app keeps what it needs to reopen the source (a content URI, a file
path) only while the upload is unfinished.

`POST /files` is rate limited per account: `isCreationPaused(error)` gives the seconds to wait, and
the upload waits rather than failing.

## Download

`openFile` resolves the row, unwraps the DEK, opens the manifest and checks the layout. Then
`downloadFile(context, id, store, sink)` streams: **each chunk is verified (tag and position)
before its bytes reach the sink**, the padding is trimmed with the manifest's `size`, an object that
ends early (`TruncatedObjectException`) or runs long (`ObjectTooLongException`) is refused, and the
object's SHA-256 is checked at the end (`ObjectDigestException`). `downloadBytes` is the same into
memory, below `DEFAULT_DOWNLOAD_BUFFER_BYTES`. `readChunk` reads one chunk by range, for seeking in
media. A presigned URL is asked for every time, never kept.

## Thumbnails are files

A preview is an ordinary file, its own row, DEK and object; only the parent's sealed manifest
(`thumbnail_id`) links them, so the server cannot tell a thumbnail from a small file. The app draws
it (320 px on the longest edge, `thumbnailExtent`; JPEG at 0.72), the core uploads it after the
parent completes (`uploadThumbnail`, which never fails the upload), and `thumbnailIdsOf` keeps
thumbnails out of every listing. Deleting a file deletes its thumbnail in the same signed batch.
`openPreview` takes an optional `SealedObjectCache`, which the app implements on disk: it holds
**ciphertext only**, keyed by id, and since a file never changes, the id is its version.

`uploadToDrive` is the whole upload the drive screen runs: the file with its thumbnail id, then the
thumbnail, then both moved into the folder.

## Renaming

`renameFile` opens the manifest, changes `name` and nothing else, seals it again under **the same
DEK**, and `PUT /files/{id}/manifest` with the ciphertext alone.

## The drive view

`driveView(context, replica)` opens every file row the [replica](../feed/README.md) holds:
thumbnails hidden, live files by name, the trashed ones newest first, and `inFolder(folderId)` for a
folder (`null` is the top). A pending upload is listed (`isPending`), as every device sees an
unfinished upload and can resume it. A file whose manifest will not open is `readable = false`.

## Tests

`FilesFormatTest`: the layout, a 1 GiB layout included; a chunk bound to its position, object and
key; **the web app's chunks reproduced byte for byte and its object and manifest opened**, from
`web-drive-object.json`, which the web app's own `lib/files` wrote; unknown manifest fields kept;
the streaming hash; thumbnail sizes. `TransferTest`, against a store in memory: an upload hashes
the object and downloads back; two uploads of one file use two keys; a resume sends only the
missing parts; a different file is refused before anything is sent; a lying source; a truncated,
long or altered object; a rename. The interop suite uploads 1 GiB, drops it after 40 parts, resumes
it and downloads it identical on another device, and carries a file with its thumbnail through a
folder, a rename and the Trash. `CrossClientDriveTest` is one half of an exchange with the web app
(`ZEKKE_CROSSCLIENT_DIR`, `ZEKKE_CROSSCLIENT_STEP`): the core uploads, the web app opens it and
uploads its own, the core opens that.
