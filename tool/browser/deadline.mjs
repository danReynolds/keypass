// The deadline arrives inside the authenticated encrypted request. It is a
// usability bound; the Dart server independently enforces its own deadline.
export function watchDeadline(expiresAt, controller, clock = {
  now: () => Date.now(), set: (f, delay) => setTimeout(f, delay), clear: id => clearTimeout(id),
}) {
  const remaining = expiresAt - clock.now();
  if (!Number.isSafeInteger(expiresAt) || remaining <= 0 || remaining > 600000) {
    controller.abort(new Error("Session expired"));
    return () => {};
  }
  const timer = clock.set(() => controller.abort(new Error("Session expired")), remaining);
  return () => clock.clear(timer);
}
