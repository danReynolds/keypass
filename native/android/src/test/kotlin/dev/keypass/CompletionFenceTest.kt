package dev.keypass

import org.junit.Assert.*
import org.junit.Test

class CompletionFenceTest {
    @Test fun cancelledProviderCannotCompleteWithAuthority() {
        val old = CompletionFence()
        assertTrue(old.cancel())
        assertFalse(old.cancel())
        val next = CompletionFence()
        assertFalse(old.finish())
        assertFalse(old.finish())
        assertTrue(next.finish())
    }
    @Test fun completionTransfersAuthorityOnlyOnce() {
        val operation = CompletionFence()
        assertTrue(operation.finish())
        assertFalse(operation.cancel())
        assertFalse(operation.finish())
    }
}
