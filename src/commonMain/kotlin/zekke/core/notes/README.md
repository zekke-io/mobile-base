# `zekke.core.notes` — notes

The note format, the `/notes` endpoints and the note tiles. The same contract as the web app's
notes and note editor, so a note written on one client reads the same on the other.

## The note format — `NoteFormat.kt`

A note is stored as **one plain string**, a small markdown subset; the user never sees the markers,
because both editors are WYSIWYG:

```
# a title line
- a topic line
- [ ] an open task
- [x] a done task
anything else is a plain line

**bold**, *italic*, ***both***, and {{18}}a size run{{/}} inline
```

- **A note written before formatting existed is already valid**, all `TEXT` lines, and
  `formatBlocks(parseBlocks(note))` gives it back byte for byte.
- **The task markers are matched before the topic marker** they start with, and a marker without
  its trailing space is not a marker.
- **Inline styles pair or they are text.** Only a complete pair on one line is a style, so
  `2 * 3 = 6` survives an edit unchanged. `formatInline` merges neighbouring spans of the same
  style first, so it never writes `**a****b**`.
- **A size is inline formatting**, a wrapper outside the style markers, one per run. The scale is
  `NOTE_FONT_SIZES`, 12 to 24 in steps of 2, and the parser's pattern is built from that list.
  Every size entering the model goes through `snapNoteFontSize`, because an off-scale size would
  serialise to a wrapper the parser does not read back, and the markers would surface as text.
- `cycleBlockType` is the editor's line command: title and topic toggle and replace each other; a
  task goes open, done, off.

| Function        | Gives                                                     |
| --------------- | --------------------------------------------------------- |
| `toPlainText`   | The text alone: the title, the character count            |
| `toDisplayText` | The text with `•`, `☐`, `☑` for structure: the thumbnail   |

Rendering is each app's: the model is blocks of spans, and an editor draws them natively.

## Two limits

`MAX_NOTE_CHARACTERS` (5000) is the product's rule and only a client can apply it: the server never
sees plaintext. It counts **code points of what the user sees** (`noteCharacterCount` over
`toPlainText`), never the markers. `MAX_NOTE_CIPHERTEXT_CHARACTERS` (32 768) is the server's ceiling
on the base64 ciphertext; it is checked too, because a document heavy in markers can approach it
while showing under 5000 characters. Both are checked before any request.

## Calls

| Function       | Endpoint                          | Notes                                                   |
| -------------- | --------------------------------- | ------------------------------------------------------- |
| `createNote`   | `POST /notes`                     | The caller's id; `201` created, `200` already stored    |
| `updateNote`   | `PUT /notes/{id}`                 | **Keeps the DEK**: the same `wrapped_dek`, byte for byte, unless the note was written under an older generation, when the same DEK is wrapped under the current one |
| `saveNote`     | either                            | The autosave entry point: a create answered `200` is followed by an edit, because create-or-return would otherwise drop the newer text |
| `queueNewNote`, `queueNoteEdit` | —                | The same writes, sealed at once and sent through the outbox |
| `listNotesMeta` | `GET /notes`                     | Paginated metadata, followed to the end                  |
| `listNotes`, `getNote` | `GET /notes/{id}`         | Each full note, six at a time                            |
| `openNote`     | —                                 | Unwrap and open                                          |
| `deleteNote(s)` | `DELETE /notes/{id}`, `DELETE /notes` | `note-delete`, one signature for the selection; a delete destroys |

**The id of a new note is minted once, when the editor opens**, not per save; `saveNote` takes it.
Saves of one note must not overlap: the app serialises them.

**An edit never mints a new DEK.** Anything holding a copy of the DEK expects it to keep working.

## The note tiles — `NoteViews.kt`

`noteTiles(context, replica)` opens every note the replica holds and returns `NoteTile`s, newest
`updated_at` first:

- `title` is the **first non-empty line's plain text**, cut at 60 code points; `null` when the
  note has none, so the app writes its own "Untitled".
- `thumbnail` is `toDisplayText`, with runs of blank lines collapsed, cut at 420 code points.
- A note that does not open is a tile with `readable = false`.

`isNoteEmpty`, `isNoteWithinLimit`, `noteCharactersLeft` and `isNoteSavable` are the editor's
autosave rules: a note that looks empty is not saved.

## Tests

`NoteFormatTest` ports the web app's format tests: every line type, the marker order, round trips,
legacy notes, unpaired asterisks, merging, sizes, the cycle. `NotesTest`: the caller's id and the
current generation with no signature; code points of what is seen, both limits before any request;
an edit keeps the wrapped DEK, and re-wraps the same DEK from an older generation; a `200` save is
followed by an edit carrying the newer text; a batch delete signs the sorted distinct ids and not
the submitted order; titles, thumbnails, empty notes; tiles newest first with an unreadable one.
The interop suite writes a note on one device, edits it on the other, and sends an offline note and
its edit through the outbox as one note.
