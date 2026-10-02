# CLI passkey access without per-CLI website deployment

Investigated 2026-09-29. This is a design investigation, not a new backend or a
change to enrolled credentials. No passkey UI was opened during this research.

Superseded recommendation: the user selected native OS providers plus physical
FIDO2 keys, with direct hardware access for CLIs. Browser/extension delivery is
deferred; the [implementation plan](../implementation-plan.md) owns current scope.
The alternatives below remain historical research.

Subsequent user decision: no Keypass-operated runtime service. The
[runtime independence constraint](../implementation-plan.md#runtime-independence-constraint)
is authoritative. Shared Keypass hosting below is retained as an examined and
rejected option, not a proposed service.

## Finding

A separate public website operated by every CLI developer is not fundamental to
passkeys. Our previous explanation overstated a property of the proposed hosted
browser route as a universal requirement. Credential/RP scoping and a client that
can reach a PRF-capable authenticator remain necessary; deployment and client
identity differ by route.

The strongest candidate for reducing developer work while reaching existing
browser providers is one optional Keypass browser extension and a local companion
bridge. A bundled localhost helper is the smallest implementation change, and our
probe already establishes limited real-provider feasibility, but it does not
provide a separate authenticated application identity for each CLI. Centralized
hosting also removes per-developer deployment, at the cost of operating and
trusting a shared service. These are different product trade-offs.

## Options

| Route | CLI developer work | User setup | Material limitation |
| --- | --- | --- | --- |
| Packaged localhost helper | SDK bundles and serves its own page | Existing browser/provider, pairing and consent | Shared localhost RP scope; not the product's native Apple/Android RP |
| Keypass extension + local bridge | Integrate SDK and package/register bridge, preferably shared | Install extension and companion once | Extension/browser distribution and caller authorization become our responsibility |
| Keypass-operated HTTPS helper | Configure an allocated product identity | Existing browser/provider and pairing | Shared operator, availability and delivered JavaScript enter encryption trust |
| Shared helper with Related Origin Requests | Publish one delegation file at the product's RP domain | Supported browser/provider | Retains a domain/hosting requirement and adds browser capability limits |
| Direct FIDO2 hardware key | Link native adapter and configure credential namespace | Compatible hardware key and driver/permissions | Does not open Apple Passwords or Google Password Manager |
| Native platform/installed broker | Package platform integration or use one installed broker | Platform-specific host/companion | Windows helps; Apple app identity still needs association; Linux PRF portal is not ready |

The first three can remove per-CLI website deployment. None automatically proves
which unsigned local executable is making a request. Session pairing confirms a
user-selected session; an app label or public app ID is not executable attestation.

## Packaged localhost helper

The CLI can start a short-lived HTTP server on loopback, serve bundled static
assets and open `http://localhost:<port>`. No public DNS, TLS hosting, server account
or remote deployment is necessary for this variant. WebAuthn permits the
localhost HTTP exception. The RP ID excludes paths and ports, so different local
ports do not create isolated passkey namespaces. [WebAuthn RP ID][rp]

Our existing localhost Chrome/Google Password Manager probe recovered equal PRF
material in a fresh CLI process and decrypted the prior process's marker. That
receipt already disproves a blanket claim that a public website is technically
necessary. It does not qualify Firefox/Safari/Linux desktop behavior, offline
provider operation, or a production local application threat model.

Consequences, inferred from RP scoping:

- Unrelated local applications can also serve localhost pages and request
  localhost credentials. They still need successful provider authorization; this
  does not reveal every credential or bypass user verification automatically.
- A name, path, random port or public HKDF context cannot authenticate the CLI's
  identity. An encrypted bridge protects the transfer, not the legitimacy of a
  malicious program that asks the user to approve its own session.
- Explicit credential IDs and per-vault inputs avoid accidental credential
  selection, but those public values do not enforce caller isolation.
- These credentials are distinct from credentials enrolled under a product's
  real RP domain. Do not promise the same credential through native iOS/Android
  clients. Sync between providers/devices is a separate qualification problem.
- Custom `*.localhost` names, DNS aliases, TLS tricks and browser flags are not
  established portable solutions in this investigation.

This remains a useful explicit local-only option. It should not silently replace
an existing domain binding or become an undocumented universal default.

## Shared extension and native messaging

Chrome's implementation permits extension pages to use their own extension RP
identity and, since Chrome 122, domain RP IDs covered by their host permissions.
Mozilla documents corresponding domain-permission support starting with Firefox
150. That removes the need to load an HTTPS helper page from the RP website for
the extension's request. The credential still has an RP ID. Browser-specific
extension origins must be explicitly verified. [Chrome announcement][chrome-ext],
[Mozilla extension guide][mozilla-ext]

Chrome native messaging supplies extension-to-native-host communication over
stdio. It requires a host manifest installed on the machine, with an allowlist of
extension IDs; the browser starts that host. It does not directly attach to an
arbitrary already-running CLI. A shared host can broker requests from CLIs over
local IPC, but that second leg needs its own session and caller policy.
[Native messaging][native-messaging]

Proposed flow (not implemented): CLI contacts the installed companion; the
extension opens its own visible approval page; the user selects/approves the
passkey; the PRF result returns through the companion to the selected CLI.
Extension access should be restricted to the required RP namespace, not broad
permissions over all websites. A shared extension's own RP also shares a
credential namespace across clients; it does not intrinsically isolate tools.
Per-product RP IDs and explicit user approval need deliberate design.

Native messaging replaces the website-to-loopback transfer, not the need to
protect PRF material or obtain consent. Its framing is JSON, so a design that
passes PRF output through it must account for managed/string copies; do not claim
it inherits our native binary ABI's memory-erasure properties.

Bitwarden is concrete product precedent: it supports PRF-backed vault unlock in
its Chromium browser extension and documents a pop-out requirement on Linux.
This establishes feasibility for some combinations, not Keypass compatibility
with every provider. [Bitwarden requirements][bitwarden]

The Keypass verifier currently permits HTTPS, an explicit localhost exception,
and the native Android origin form. It intentionally rejects extension origins.
A new adapter needs an explicit origin policy with pinned extension identity;
simply weakening the existing origin check is not an acceptable integration.

Qualification required before selecting this route: real Google Password Manager
and Apple-provider PRF behavior from an extension page; creation/repeated
evaluation/restart decryption; Linux desktop execution; cancellation and browser
restart; wrong-extension/wrong-client/altered-session rejection; install/update
lifecycle; and provider availability differences. Firefox WebAuthn extension
support alone does not establish PRF support. Safari is not qualified here.

## Shared HTTPS service

We could operate the static helper centrally and give each CLI product a stable
subdomain/RP ID, such as `tool-a.keypass.example` (illustrative reserved name).
Developers would register/configure an identity rather than deploy a website.
The per-product subdomain separation follows normal RP rules; `?app=tool-a` on
one shared RP does not create that separation.

The service would not need to store vaults or receive plaintext PRF output in the
honest protocol. However, it delivers the JavaScript that handles PRF output. A
compromised operator/deployment could change that code and capture material on a
future approved operation. It is consequently part of encryption trust, with
availability, domain-retention and migration responsibilities. Namespacing also
does not authenticate unsigned local callers; pairing/consent remain necessary.

This would be a technically viable managed service, but the user has excluded
Keypass-operated runtime hosting from the product scope. No such service was created in this investigation. The existing
Firebase demo deployment contains only Apple's AASA file.

## Product precedent and its limits

Bitwarden ships PRF-backed vault login/unlock in its Chromium extension. This
supports the extension-as-WebAuthn-client part of the proposal. Its product still
uses an account service and a web enrollment flow, so it is not evidence of a
hosting-free generic CLI broker. Its browser passkey-login implementation was
merged in [clients PR 16385](https://github.com/bitwarden/clients/pull/16385).

[KeePassXC-Browser](https://github.com/keepassxreboot/keepassxc-browser#how-it-works)
uses native messaging to a bundled proxy and Unix sockets/named pipes to the
local KeePassXC app. Its passkey feature makes KeePassXC a credential provider
for websites; it does not obtain another provider's PRF output for arbitrary
CLIs. It is evidence for the installed extension/proxy/local-app architecture,
not a drop-in Keypass backend.

These products establish relevant components. This investigation did not verify
a mature general-purpose SDK implementing our exact extension-to-CLI PRF broker.
Caller authorization, provider compatibility, stable RP/extension identity and
restart recovery remain work for Keypass. No existing provider's authentication-
only or password-export API is being treated as equivalent to PRF encryption.

## Related Origin Requests

A product can keep its RP ID while delegating web requests to a shared helper by
serving `https://<rp-id>/.well-known/webauthn` with an allowed-origin list. This
reduces a consumer deployment to a static declaration rather than maintained
helper JavaScript. It still requires the RP domain and hosted declaration, and it
does not replace native Apple AASA or Android Digital Asset Links.
[Google's Related Origin Requests guide][ror]

The source documents Chrome/Safari and gives a January 2026 Firefox status; that
older browser support note is not sufficient to claim today's Firefox behavior.
Runtime support must be checked. Our verifier/probe currently reject unrelated
origins, so this is also a new explicit policy/adapter, not a working option today.

## Native and hardware routes

Windows' native WebAuthn API does not require an AASA/Asset Links equivalent. Our
adapter still requires an app-owned window; a CLI host/presentation solution and
actual Windows PRF behavior need testing. It does not give a portable direct API
for Chrome's private passkey store. [Microsoft platform setup][windows]

An installed, signed macOS companion could hold its own app/domain association
once and broker CLI requests. That shifts signing, association and local IPC
identity to the companion publisher rather than eliminating them. Apple/Android
native app integration itself continues to use domain association.

The Linux credentialsd project remains a portal proposal, with its PRF feature
request still open when inspected. It is worth tracking but is not evidence of a
widely available PRF-capable native path. [Project][credentialsd], [PRF issue][prf-issue]

For hardware security keys, libfido2/Yubico SDKs can request CTAP `hmac-secret`
directly. The client supplies the RP identifier and must apply appropriate PRF
input domain separation; no website is needed to run the hardware operation.
This path does not retrieve platform/password-manager passkeys. Yubico documents
the building blocks, and age's `age-plugin-fido2prf` provides a real CLI encryption
reference interoperable with browser-created hardware-key credentials.
[Yubico native PRF guide][yubico], [typage CLI plugin][typage]

## Historical recommendation

Prototype one optional Keypass extension plus companion before making every CLI
consumer maintain a hosted helper. It offers a credible route to existing browser
providers without per-CLI websites. The trade is a one-time end-user installation
and a substantial shared component for us to maintain, not zero total complexity.
Use narrow RP permissions and explicit local caller/session approval. Do not
promise support until real PRF/restart tests pass from extension pages.

Keep the developer-owned HTTPS helper as the extension-free path for products
that already operate a domain and need one RP across native apps and CLI. Keep
localhost as an explicitly scoped alternative while its threat model and provider
matrix are qualified. Add direct hardware-key support separately for users who
want that dependency model. A managed Keypass host is excluded by the runtime independence constraint.

This research changes our assessment of deployment choices, not our current
backend selection, stored bindings, native demo configuration or vault format.
No new provider run was performed and no extension was installed.

[rp]: https://www.w3.org/TR/webauthn-3/#rp-id
[chrome-ext]: https://lists.w3.org/Archives/Public/public-webauthn/2023Dec/0078.html
[mozilla-ext]: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Use_the_web_authn_api
[native-messaging]: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
[bitwarden]: https://bitwarden.com/help/login-with-passkeys/
[ror]: https://web.dev/articles/webauthn-related-origin-requests
[windows]: https://learn.microsoft.com/en-us/dotnet/maui/platform-integration/communication/passkeys?view=net-maui-10.0
[credentialsd]: https://github.com/linux-credentials/credentialsd
[prf-issue]: https://github.com/linux-credentials/credentialsd/issues/6
[yubico]: https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html#_beyond_the_browser_hmac_secret_in_native_mobile_apps
[typage]: https://github.com/FiloSottile/typage#webauthn
