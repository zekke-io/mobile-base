package zekke.core.notes

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NoteFormatTest {
    private fun plain(text: String) = InlineSpan(text)

    @Test
    fun readsEveryLineTypeBackFromItsMarker() {
        val blocks = parseBlocks("# Plans\n- stamps\n- [ ] pack\n- [x] flights\njust a line")
        assertEquals(
            listOf(NoteLineType.TITLE, NoteLineType.TOPIC, NoteLineType.TASK, NoteLineType.TASK, NoteLineType.TEXT),
            blocks.map { it.type },
        )
        assertEquals(listOf(false, false, false, true, false), blocks.map { it.checked })
        assertEquals(listOf("Plans", "stamps", "pack", "flights", "just a line"), blocks.map(::blockPlainText))
    }

    @Test
    fun checksTheTaskMarkersBeforeTheTopicMarkerAndNeedsTheTrailingSpace() {
        assertEquals(NoteLineType.TASK, parseBlocks("- [ ] x")[0].type)
        assertEquals(NoteLineType.TASK, parseBlocks("- [x] x")[0].type)
        assertEquals(NoteLineType.TEXT, parseBlocks("#")[0].type)
        assertEquals(NoteLineType.TEXT, parseBlocks("-")[0].type)
    }

    @Test
    fun roundTripsADocumentAndLeavesALegacyNoteUntouched() {
        val source = "# Plans\n- [x] **book** flights\n- [ ] pack *light*\n- passport\n\nSee ***you*** {{18}}soon{{/}}."
        assertEquals(source, formatBlocks(parseBlocks(source)))
        val legacy = "shopping\nmilk, 2 * 3 eggs\n\n  indented"
        assertTrue(parseBlocks(legacy).all { it.type == NoteLineType.TEXT })
        assertEquals(legacy, formatBlocks(parseBlocks(legacy)))
        assertEquals(legacy, toPlainText(legacy))
    }

    @Test
    fun splitsALineIntoStyledSpansAndLeavesUnpairedAsterisksAlone() {
        assertEquals(
            listOf(plain("See "), InlineSpan("you", bold = true), plain(" in "), InlineSpan("June", italic = true)),
            parseInline("See **you** in *June*"),
        )
        assertEquals(listOf(InlineSpan("both", bold = true, italic = true)), parseInline("***both***"))
        assertEquals(listOf(plain("2 * 3 = 6")), parseInline("2 * 3 = 6"))
        assertEquals(listOf(plain("trailing *")), parseInline("trailing *"))
    }

    @Test
    fun mergesNeighbouringSpansOfTheSameStyle() {
        val merged = mergeSpans(listOf(InlineSpan("a", bold = true), InlineSpan("", italic = true), InlineSpan("b", bold = true), plain("c")))
        assertEquals(listOf(InlineSpan("ab", bold = true), plain("c")), merged)
        assertEquals("**ab**c", formatInline(merged))
    }

    @Test
    fun carriesASizeOnTheSpansItWrapsAndOneWrapperPerRun() {
        assertEquals(listOf(plain("small "), InlineSpan("big", size = 18), plain(" small")), parseInline("small {{18}}big{{/}} small"))
        assertNull(parseInline("plain")[0].size)
        assertEquals(
            listOf(InlineSpan("bold", bold = true, size = 16), InlineSpan(" and ", size = 16), InlineSpan("italic", italic = true, size = 16)),
            parseInline("{{16}}**bold** and *italic*{{/}}"),
        )
        assertEquals("{{16}}**a***b*{{/}}", formatInline(listOf(InlineSpan("a", bold = true, size = 16), InlineSpan("b", italic = true, size = 16))))
        assertEquals(2, mergeSpans(listOf(InlineSpan("a", size = 16), InlineSpan("b", size = 18))).size)
    }

    @Test
    fun leavesAnUnpairedOrUnknownSizeMarkerAsText() {
        assertEquals(listOf(plain("{{16}}unclosed")), parseInline("{{16}}unclosed"))
        assertEquals(listOf(plain("{{15}}odd size{{/}}")), parseInline("{{15}}odd size{{/}}"))
        assertEquals(listOf(plain("use {{ and }} freely")), parseInline("use {{ and }} freely"))
    }

    @Test
    fun cyclesLineTypesKeepingTheText() {
        val title = NoteBlock(NoteLineType.TITLE, false, listOf(plain("x")))
        assertEquals(NoteLineType.TEXT, cycleBlockType(title, NoteLineCommand.TITLE).type)
        assertEquals(NoteLineType.TOPIC, cycleBlockType(title, NoteLineCommand.TOPIC).type)
        val open = cycleBlockType(title, NoteLineCommand.TASK)
        assertEquals(NoteLineType.TASK to false, open.type to open.checked)
        val done = cycleBlockType(open, NoteLineCommand.TASK)
        assertEquals(NoteLineType.TASK to true, done.type to done.checked)
        assertEquals(NoteLineType.TEXT, cycleBlockType(done, NoteLineCommand.TASK).type)
        assertEquals("x", blockPlainText(cycleBlockType(done, NoteLineCommand.TITLE)))
    }

    @Test
    fun stepsSnapsAndRoundTripsEveryFontSize() {
        assertEquals(NOTE_FONT_MIN_PX, changeNoteFontSize(NOTE_FONT_MIN_PX.toDouble(), -1))
        assertEquals(NOTE_FONT_MAX_PX, changeNoteFontSize(NOTE_FONT_MAX_PX.toDouble(), 1))
        assertEquals(16, changeNoteFontSize(NOTE_FONT_DEFAULT_PX.toDouble(), 1))
        assertEquals(NOTE_FONT_MIN_PX, snapNoteFontSize(2.0))
        assertEquals(NOTE_FONT_MAX_PX, snapNoteFontSize(400.0))
        assertEquals(NOTE_FONT_DEFAULT_PX, snapNoteFontSize(Double.NaN))
        assertEquals(14, snapNoteFontSize(15.0))
        assertEquals(14, snapNoteFontSize(13.4))
        assertFalse(canShrinkNoteFont(NOTE_FONT_MIN_PX.toDouble()))
        assertFalse(canGrowNoteFont(NOTE_FONT_MAX_PX.toDouble()))
        for (size in NOTE_FONT_SIZES) {
            val line = formatInline(listOf(InlineSpan("x", size = size)))
            assertEquals("{{$size}}x{{/}}", line)
            assertEquals(listOf(InlineSpan("x", size = size)), parseInline(line))
        }
        assertEquals("{{12}}x{{/}}", formatInline(listOf(InlineSpan("x", size = 13))))
    }

    @Test
    fun readsANoteBackOutWithoutMarkup() {
        val note = "# Plans\n- [x] book flights\n- [ ] pack\n- passport\nSee **you** in *June*."
        assertEquals("Plans\nbook flights\npack\npassport\nSee you in June.", toPlainText(note))
        assertEquals("Plans\n☑ book flights\n☐ pack\n• passport\nSee you in June.", toDisplayText(note))
        assertEquals("Big title\nsmall task", toPlainText("# {{24}}Big title{{/}}\n- [ ] {{12}}small task{{/}}"))
    }
}
