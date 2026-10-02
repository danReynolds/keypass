package dev.keypass

/** Main-thread state for one provider operation; cancellation is not completion. */
internal class CompletionFence {
    private var cancelled = false
    private var finished = false
    fun cancel(): Boolean {
        if (cancelled || finished) return false
        cancelled = true
        return true
    }
    /** True exactly once for an uncancelled completion; a late result has no authority. */
    fun finish(): Boolean {
        if (finished) return false
        finished = true
        return !cancelled
    }
}
