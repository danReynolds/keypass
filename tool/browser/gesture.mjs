// A cancelled prompt may still resolve later if a provider ignores AbortSignal.
// Own late secret buffers until erased; never deliver them after cancellation.
export function requestGesture(button, label, signal, action) {
  return new Promise((resolve, reject) => {
    let settled = false, started = false;
    const erase = value => { if (value instanceof Uint8Array) value.fill(0); };
    const cleanup = () => {
      button.onclick = null;
      button.disabled = true;
      signal.removeEventListener("abort", cancelled);
    };
    const cancelled = () => {
      if (settled) return;
      settled = true; cleanup();
      reject(signal.reason ?? new DOMException("Cancelled", "AbortError"));
    };
    signal.addEventListener("abort", cancelled, {once: true});
    if (signal.aborted) { cancelled(); return; }
    button.textContent = label;
    button.disabled = false;
    button.onclick = () => {
      if (settled || started) return;
      started = true; button.disabled = true;
      let pending;
      try { pending = action(); } // Preserve the click's user activation.
      catch (error) { settled = true; cleanup(); reject(error); return; }
      Promise.resolve(pending).then(value => {
        if (settled || signal.aborted) { erase(value); cancelled(); return; }
        settled = true; cleanup(); resolve(value);
      }, error => {
        if (settled) return;
        settled = true; cleanup(); reject(error);
      });
    };
  });
}
