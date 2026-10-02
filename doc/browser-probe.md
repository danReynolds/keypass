# Browser-to-CLI proof

This is an **experimental tool**, outside the public Keypass library. It explores
one shared backend for Linux desktop consumers and unsigned macOS CLIs.
It does not unlock a Keybay vault or register a public backend. The evidence
below applies only to the specific tested browser, provider and host.

## Run locally

Requires Dart and a browser with WebCrypto X25519, WebAuthn and a PRF-capable
provider. Node 22+ is needed for the development tests, not by the browser helper
or a future consuming application.

From the repository, serve the static helper:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory tool/browser
```

In a second terminal:

```sh
dart run tool/browser_probe.dart \
  --helper http://localhost:8765/probe.html \
  --rp localhost \
  --binding /tmp/keypass-test-binding.json \
  --allow-loopback
```

1. Open the printed URL in a browser. It carries an ephemeral public key,
   session identifier, RP ID and loopback endpoint; no encryption secret.
2. Connect, compare **all eight groups** of the pairing code with the terminal,
   and approve both sides. Never auto-approve pairing in a real provider run.
3. Create a development passkey, then explicitly request its two evaluations.
   These may show separate provider prompts. No passphrase or PRF copy/paste.
4. The browser verifies ES256 assertion signatures and checks fresh challenges,
   exact origin, RP hash, credential/user handle, UP/UV and equal 32-byte PRF
   outputs. It sends a binary result over the encrypted paired channel.
5. Dart independently verifies the raw registration/assertion evidence with its
   [bounded verifier](webauthn-verifier.md). The CLI then saves public credential
   metadata and an encrypted test marker, then
   clears its owned result buffer. The PRF is never printed or saved.
6. Stop/restart the CLI with the same command and file. It selects the existing
   credential, evaluates twice, and decrypts the saved marker. Success proves the
   new result matches the earlier process, not just the second prompt this run.

During assisted testing, finish pairing before handing the browser to the
human tester. Let them click both verification buttons and complete the provider
prompts. Stop automated browser interaction and screen inspection throughout
those steps; the tester reported interference with Touch ID during inspection.
Monitor only CLI output, and resume browser inspection after the tester finishes.

An existing file never triggers replacement enrollment. The marker is a probe
format, not Keypass's public binding format or Keybay's envelope format.
A failed creation can leave a test passkey in the provider; remove it there
when finished. The tool does not delete provider credentials.

For a production-domain experiment, host only `probe.html`, `probe.css`,
`probe.mjs`, `protocol.mjs`, `ceremony.mjs`, `failure.mjs`, `gesture.mjs` and `deadline.mjs` on a controlled HTTPS origin.
Use its compatible RP ID and omit `--allow-loopback`. The native demo now has
a domain and AASA deployment, but this browser helper has not been deployed
there. Localhost credentials are separate from production credentials. See the
[CLI alternatives investigation](research/2026-09-29-cli-passkey-access.md) for
ways to avoid per-CLI helper hosting.

The host should set `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, `Content-Security-Policy` with
`frame-ancestors 'none'` in addition to the page's policy, and
`Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self)`.
Host no third-party scripts/analytics or service worker on this helper origin.
Deployed helper code is a trusted part of the encryption path.

## Channel and boundaries

The probe chooses a static helper plus ephemeral loopback HTTP transport; it has
no relay. The production transport and pairing UX remain subject to qualification.

- Dart listens only on IPv4 loopback and an OS-selected port. Each run has a
  random session ID, fresh X25519 key pair, one peer, and an eight-minute deadline.
- Both public keys, helper origin, RP ID and session ID enter the transcript.
  X25519 plus HKDF-SHA256 derive independent directional AES-256-GCM keys and a
  128-bit comparison code. Full-code comparison binds the two endpoints.
- Both confirmations are required before the request is sent. This confirms the
  user-selected CLI session; it does **not** attest a signed app identity or make
  an arbitrary CLI trustworthy. Origin headers/CORS alone do not authenticate a
  local application and can be forged by a non-browser client.
- Directional keys, sequence-number nonces and authenticated transcript/sequence
  context reject replay, reflection and altered ciphertext. Frames are bounded.
- Exact Host/Origin checks restrict browser traffic. No redirects, cookies,
  plaintext secret responses, URL secrets or clipboard exchange are used.
- The encrypted request carries the CLI deadline. The browser disables waiting
  credential buttons and cancels outstanding provider work when it expires.
- Browser cancellation sends an authenticated abort. Lost tabs or unreachable
  peers expire; Ctrl-C also closes the CLI. Wrong pairing and malformed messages
  fail closed. Owned mutable PRF/plaintext buffers are cleared on completion.
- JavaScript CryptoKeys and managed-runtime copies cannot be promised immediate
  physical erasure. This is not a native secret-memory implementation.
- Dart parses the original CBOR attestation object and COSE key and verifies
  both assertion signatures against the original CLI challenges. Browser checks
  remain as defense in depth. The narrow ES256/none profile and legacy saved-state
  limits are documented in the [verifier contract](webauthn-verifier.md). Client
  PRF bytes remain trusted browser/provider output, not independently covered by
  the authenticator signature. Public backend wiring still requires provider
  qualification, credential-state persistence and transport/identity review.

## Evidence and next work

Local tests cover Node WebCrypto ↔ Dart encryption interoperability, a real HTTP
round trip with synthetic credential material, replay/reflection/tamper rejection,
wrong origin, pairing refusal, cancellation, deadlines and encrypted restart
checks. Browser verifier tests use generated ES256 signatures but synthetic PRF.

Real localhost runs on macOS 26.2 with Chrome and Google Password Manager
created a development passkey and obtained equal 32-byte PRF output twice. A
fresh AOT CLI process subsequently reused that credential, independently verified
both assertion signatures in Dart, and decrypted the marker saved by the earlier
JIT process. Only public metadata and an encrypted marker were persisted. See the
scoped [validation receipts](validation.md).

Still required: a deployed HTTPS helper connecting to loopback, Safari/Firefox
and local network permission prompts, Linux desktop/provider execution, provider
sync/offline behavior, identity/pairing review, real-provider raw registration
verification in Dart, independent security review, credential-state persistence
and public API wiring. Linux ARM64 automated tests and AOT compilation
have passed in Docker; those do not qualify desktop UI/provider behavior.
Do not generalize localhost or Node results into supported browser/provider claims.

## References

- [WebAuthn PRF and ceremony requirements](https://www.w3.org/TR/webauthn-3/#prf-extension)
- [WebCrypto algorithms](https://www.w3.org/TR/WebCryptoAPI/)
- [Chrome local-network access](https://developer.chrome.com/blog/local-network-access)
- [Dart cryptography](https://pub.dev/packages/cryptography/versions/2.9.0)

The protocol is a bounded experiment, not an independently reviewed standard.
