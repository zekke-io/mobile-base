package zekke.core.notes

import kotlin.math.abs

const val TITLE_MARKER = "# "
const val TOPIC_MARKER = "- "
const val TASK_OPEN_MARKER = "- [ ] "
const val TASK_DONE_MARKER = "- [x] "

const val BOLD_MARK = "**"
const val ITALIC_MARK = "*"
const val BOLD_ITALIC_MARK = "***"

const val TOPIC_BULLET = "•"
const val TASK_OPEN_BULLET = "☐"
const val TASK_DONE_BULLET = "☑"

val NOTE_FONT_SIZES: List<Int> = listOf(12, 14, 16, 18, 20, 22, 24)
val NOTE_FONT_MIN_PX: Int = NOTE_FONT_SIZES.first()
val NOTE_FONT_MAX_PX: Int = NOTE_FONT_SIZES.last()
const val NOTE_FONT_DEFAULT_PX = 14

enum class NoteLineType { TITLE, TOPIC, TASK, TEXT }

enum class NoteLineCommand { TITLE, TOPIC, TASK }

data class InlineSpan(val text: String, val bold: Boolean = false, val italic: Boolean = false, val size: Int? = null)

data class NoteBlock(val type: NoteLineType, val checked: Boolean, val spans: List<InlineSpan>)

private class NoteLine(val type: NoteLineType, val checked: Boolean, val text: String)

private fun parseLine(raw: String): NoteLine = when {
    raw.startsWith(TASK_DONE_MARKER) -> NoteLine(NoteLineType.TASK, true, raw.substring(TASK_DONE_MARKER.length))
    raw.startsWith(TASK_OPEN_MARKER) -> NoteLine(NoteLineType.TASK, false, raw.substring(TASK_OPEN_MARKER.length))
    raw.startsWith(TITLE_MARKER) -> NoteLine(NoteLineType.TITLE, false, raw.substring(TITLE_MARKER.length))
    raw.startsWith(TOPIC_MARKER) -> NoteLine(NoteLineType.TOPIC, false, raw.substring(TOPIC_MARKER.length))
    else -> NoteLine(NoteLineType.TEXT, false, raw)
}

private fun formatLine(type: NoteLineType, checked: Boolean, text: String): String = when (type) {
    NoteLineType.TITLE -> TITLE_MARKER + text
    NoteLineType.TOPIC -> TOPIC_MARKER + text
    NoteLineType.TASK -> (if (checked) TASK_DONE_MARKER else TASK_OPEN_MARKER) + text
    NoteLineType.TEXT -> text
}

private val INLINE_PATTERN = Regex("""\*\*\*([^*\n]+)\*\*\*|\*\*([^*\n]+)\*\*|\*([^*\n]+)\*""")
private val SIZE_PATTERN = Regex("""\{\{(${NOTE_FONT_SIZES.joinToString("|")})\}\}([\s\S]*?)\{\{/\}\}""")

private fun parseStyled(text: String, size: Int?): List<InlineSpan> {
    val spans = mutableListOf<InlineSpan>()
    var at = 0
    for (match in INLINE_PATTERN.findAll(text)) {
        val index = match.range.first
        if (index > at) spans += InlineSpan(text.substring(at, index), size = size)
        val both = match.groups[1]?.value
        val bold = match.groups[2]?.value
        val italic = match.groups[3]?.value
        spans += when {
            both != null -> InlineSpan(both, bold = true, italic = true, size = size)
            bold != null -> InlineSpan(bold, bold = true, size = size)
            else -> InlineSpan(italic ?: "", italic = true, size = size)
        }
        at = match.range.last + 1
    }
    if (at < text.length) spans += InlineSpan(text.substring(at), size = size)
    return spans
}

fun parseInline(text: String): List<InlineSpan> {
    val spans = mutableListOf<InlineSpan>()
    var at = 0
    for (match in SIZE_PATTERN.findAll(text)) {
        val index = match.range.first
        if (index > at) spans += parseStyled(text.substring(at, index), null)
        spans += parseStyled(match.groupValues[2], match.groupValues[1].toInt())
        at = match.range.last + 1
    }
    if (at < text.length) spans += parseStyled(text.substring(at), null)
    return spans
}

fun mergeSpans(spans: List<InlineSpan>): List<InlineSpan> {
    val merged = mutableListOf<InlineSpan>()
    for (span in spans) {
        if (span.text.isEmpty()) continue
        val normalized = if (span.size == null) span else span.copy(size = snapNoteFontSize(span.size.toDouble()))
        val last = merged.lastOrNull()
        if (last != null && last.bold == normalized.bold && last.italic == normalized.italic && last.size == normalized.size) {
            merged[merged.size - 1] = last.copy(text = last.text + normalized.text)
        } else {
            merged += normalized
        }
    }
    return merged
}

private fun styleMarkers(span: InlineSpan): String {
    val mark = when {
        span.bold && span.italic -> BOLD_ITALIC_MARK
        span.bold -> BOLD_MARK
        span.italic -> ITALIC_MARK
        else -> ""
    }
    return mark + span.text + mark
}

fun formatInline(spans: List<InlineSpan>): String {
    val merged = mergeSpans(spans)
    val out = StringBuilder()
    var index = 0
    while (index < merged.size) {
        val size = merged[index].size
        var end = index
        while (end < merged.size && merged[end].size == size) end++
        val run = merged.subList(index, end).joinToString("") { styleMarkers(it) }
        out.append(if (size == null) run else "{{$size}}$run{{/}}")
        index = end
    }
    return out.toString()
}

fun parseBlocks(text: String): List<NoteBlock> = text.split('\n').map { raw ->
    val line = parseLine(raw)
    NoteBlock(line.type, line.checked, parseInline(line.text))
}

fun formatBlocks(blocks: List<NoteBlock>): String =
    blocks.joinToString("\n") { formatLine(it.type, it.checked, formatInline(it.spans)) }

fun blockPlainText(block: NoteBlock): String = block.spans.joinToString("") { it.text }

fun cycleBlockType(block: NoteBlock, command: NoteLineCommand): NoteBlock {
    if (command == NoteLineCommand.TASK) {
        return when {
            block.type != NoteLineType.TASK -> block.copy(type = NoteLineType.TASK, checked = false)
            block.checked -> block.copy(type = NoteLineType.TEXT, checked = false)
            else -> block.copy(type = NoteLineType.TASK, checked = true)
        }
    }
    val target = if (command == NoteLineCommand.TITLE) NoteLineType.TITLE else NoteLineType.TOPIC
    return if (block.type == target) block.copy(type = NoteLineType.TEXT, checked = false) else block.copy(type = target, checked = false)
}

fun toPlainText(text: String): String = parseBlocks(text).joinToString("\n") { blockPlainText(it) }

fun toDisplayText(text: String): String = parseBlocks(text).joinToString("\n") { block ->
    val content = blockPlainText(block)
    when (block.type) {
        NoteLineType.TOPIC -> "$TOPIC_BULLET $content"
        NoteLineType.TASK -> "${if (block.checked) TASK_DONE_BULLET else TASK_OPEN_BULLET} $content"
        else -> content
    }
}

fun snapNoteFontSize(size: Double): Int {
    if (size.isNaN() || size.isInfinite()) return NOTE_FONT_DEFAULT_PX
    return NOTE_FONT_SIZES.reduce { best, stop -> if (abs(stop - size) < abs(best - size)) stop else best }
}

fun changeNoteFontSize(size: Double, direction: Int): Int {
    val at = NOTE_FONT_SIZES.indexOf(snapNoteFontSize(size))
    val next = (at + direction.coerceIn(-1, 1)).coerceIn(0, NOTE_FONT_SIZES.size - 1)
    return NOTE_FONT_SIZES[next]
}

fun canGrowNoteFont(size: Double): Boolean = snapNoteFontSize(size) < NOTE_FONT_MAX_PX

fun canShrinkNoteFont(size: Double): Boolean = snapNoteFontSize(size) > NOTE_FONT_MIN_PX
