package dev.keypass.hardware

/** Validate the standard FIDO application and unnumbered 64-byte HID reports.
 * Unrelated HID interfaces never receive CTAP traffic. No manufacturer checks.
 */
internal fun isFidoReport(descriptor: ByteArray): Boolean {
    if (descriptor.isEmpty() || descriptor.size > 1024) return false
    data class Global(var page: Int = 0, var size: Int = 0, var count: Int = 0, var id: Int = 0)
    var global = Global()
    val saved = mutableListOf<Global>()
    var usage = -1
    var depth = 0
    var applications = 0
    var inputBits = 0
    var outputBits = 0
    var position = 0
    while (position < descriptor.size) {
        val prefix = descriptor[position++].toInt() and 255
        if (prefix == 0xfe) return false
        val length = when (prefix and 3) { 3 -> 4; else -> prefix and 3 }
        if (position + length > descriptor.size) return false
        var value = 0L
        for (i in 0 until length) value = value or ((descriptor[position++].toLong() and 255) shl (8 * i))
        if (value > Int.MAX_VALUE) return false
        val n = value.toInt()
        when ((prefix shr 2) and 3) {
            1 -> when (prefix shr 4) {
                0 -> global.page = n
                7 -> global.size = n
                8 -> global.id = n
                9 -> global.count = n
                10 -> { if (saved.size >= 8) return false; saved.add(global.copy()) }
                11 -> { if (saved.isEmpty()) return false; global = saved.removeAt(saved.lastIndex) }
            }
            2 -> if ((prefix shr 4) == 0) usage = n
            0 -> {
                when (prefix shr 4) {
                    10 -> {
                        if (depth == 0 && (++applications != 1 || n != 1 || global.page != 0xf1d0 || usage != 1)) return false
                        if (++depth > 8) return false
                    }
                    12 -> { if (--depth < 0) return false }
                    8, 9 -> {
                        if (depth == 0 || global.id != 0 || global.size != 8 || global.count !in 1..64 || (n and 1) != 0) return false
                        if ((prefix shr 4) == 8) inputBits += 8 * global.count else outputBits += 8 * global.count
                        if (inputBits > 512 || outputBits > 512) return false
                    }
                }
                usage = -1
            }
        }
    }
    return depth == 0 && saved.isEmpty() && applications == 1 && inputBits == 512 && outputBits == 512
}
