# Demo app association hosting

Project/site: `keypass-demo-20260929` (Firebase Hosting, no billing account).
RP domain: `keypass-demo-20260929.web.app`.

Public association files:

- `apple-app-site-association` authorizes Apple app IDs
  `5AHFA9FUZG.dev.keypass.demo` (original AppKit/worker demo) and
  `5AHFA9FUZG.dev.keypass.providerDemo` (in-process FFI demo).
- `assetlinks.json` authorizes Android package `dev.keypass.providerdemo` with
  the explicitly listed SHA-256 development-certificate fingerprint. Both debug
  and release-mode test APKs deliberately use that certificate. No production
  certificate or Play App Signing identity is authorized by this fixture.

Only these two static files under `public/.well-known/` are deployed.
They contain public app metadata, no credentials, SDK source or user data.
The empty ignore list retains `.well-known`; both endpoints return JSON over
HTTPS without redirects. The updated Apple CDN response was verified on
2026-09-29.

Deploy changes from this directory with an authenticated Firebase CLI:

```sh
firebase deploy --only hosting --project keypass-demo-20260929
```

These identities are for disposable demo credentials. Consumers configure their
own domain and app identity. Changing the RP creates a separate namespace.
The native flow requires no browser helper page on this site.

This is an isolated development fixture, not a Keypass runtime service or SDK
default. See the [runtime independence constraint](../../doc/implementation-plan.md#runtime-independence-constraint).
