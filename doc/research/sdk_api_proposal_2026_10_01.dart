// SUPERSEDED by the implemented client in lib/keypass.dart and doc/sdk.md.
// Historical review specimen only; do not use as the consumer contract.
// REVIEW PROPOSAL ONLY — not the implemented or exported Keypass API.
// Factories deliberately throw. This file type-checks the proposed public
// contract and consumer examples; it performs no native/passkey operations.
// Revision 2, 2026-10-01: one RP ID and imperative, explicitly owned sessions.

import 'dart:typed_data';

import 'package:keypass/keypass.dart'
    show PasskeyCancellation, PasskeyErrorCode;

abstract interface class Keypass {
  /// One stable scope for credentials across supported access paths.
  /// rpId is the standard relying-party identifier (e.g. vault.example.com).
  /// OS-provider/browser paths enforce app association/origin rules for it.
  /// Direct CTAP uses it without domain ownership checks or a hosted website.
  /// A hardware-only app may use a local DNS-shaped identifier. Sharing an ID
  /// does not make credentials or their permitted access routes interchangeable.
  /// Deliberately different scopes use separate clients; existing records must
  /// retain their original RP IDs and PRF inputs, with no silent migration.
  /// Construction validates configuration and does not prompt or open resources.
  factory Keypass({required String rpId, String? displayName}) =>
      throw UnsupportedError('API proposal only');

  /// Optional, prompt-free setup/readiness information. Not a PRF guarantee.
  /// Actual operations check again; check() is not a required first step.
  /// A disconnected key does not mean the hardware route is unsupported.
  Future<PasskeyReadiness> check(PasskeySource source);

  /// Create a credential, confirm two matching secret evaluations, then return
  /// an owned session. Keypass generates challenges, PRF input and user identity.
  /// A failure after creation can leave a credential in the external provider.
  /// The caller closes a successful result in finally, including on save failure.
  Future<PasskeySession> create({
    required PasskeySource source,
    required String label,
    SecurityKeyInteraction? interaction,
    PasskeyCancellation? cancellation,
  });

  /// Obtain the secret for exactly this record using its saved access route.
  /// Reject RP/policy mismatches or missing required interaction before prompts.
  /// Never create, replace, retry a PIN, weaken UV or silently switch routes.
  Future<PasskeySession> unlock(
    PasskeyRecord record, {
    SecurityKeyInteraction? interaction,
    PasskeyCancellation? cancellation,
  });
}

/// Access paths, not a claim about sync/storage location. system uses native
/// provider UI; securityKey uses direct FIDO hardware. A browser integration
/// uses the same RP ID rules but is not newly implemented by this API sketch.
enum PasskeySource { system, securityKey }

abstract interface class PasskeyReadiness {
  bool get canAttempt;
  PasskeyErrorCode? get reason;
}

/// Nonsecret, immutable, versioned recovery metadata. Opaque protocol fields.
/// Decoding validates structure, not authenticity. Store as authenticated
/// application metadata. Existing v2/v3 scopes and PRF inputs are preserved.
abstract interface class PasskeyRecord {
  factory PasskeyRecord.fromJson(Map<String, Object?> json) =>
      throw UnsupportedError('API proposal only');

  /// Stable identity, unchanged by verification-state updates.
  String get id;
  String get rpId;
  PasskeySource get source;
  Map<String, Object?> toJson();
}

/// Privately constructed in production. Owns secret memory only: platform UI,
/// workers and connections have already finished before this result is returned.
/// toString() must redact secrets. Both create and unlock return this same type.
abstract interface class PasskeySession {
  /// New record on create; updated verification metadata on unlock.
  /// Remains readable after close(). The caller owns persistence/concurrency.
  PasskeyRecord get record;

  /// Borrowed read-only secret material for the consumer's purpose-bound KDF.
  /// Getter throws after close. Previously obtained views then observe zeros;
  /// caller-created copies remain the caller's responsibility. No promise of
  /// complete VM/native heap erasure. Do not log the bytes.
  Uint8List get secret;

  /// Synchronous, idempotent, nonthrowing cleanup of owned secret memory.
  /// Does not delete the credential, save its record or modify the vault.
  void close();
}

/// Required before starting direct hardware access; system UI owns its own
/// prompts. Operation-scoped: never capture a screen or selected connection in
/// a long-lived Keypass instance. A null PIN/selection means cancellation.
final class SecurityKeyInteraction {
  const SecurityKeyInteraction({
    required this.requestPin,
    required this.selectConnection,
    required this.onStatus,
  });

  /// Return an exclusively owned writable UTF-8 buffer. Keypass clears it,
  /// including after cancellation/late completion. Never automatically retry.
  final Future<Uint8List?> Function(
    SecurityKeyPinRequest request,
    PasskeyCancellation cancellation,
  )
  requestPin;

  /// Return an offered opaque option from this exact prompt, not an index.
  /// A single eligible connection can be selected automatically; a reader
  /// does not prove any credential-bearing key is present.
  final Future<SecurityKeyConnection?> Function(
    List<SecurityKeyConnection> connections,
    PasskeyCancellation cancellation,
  )
  selectConnection;

  /// Status is informational and grants no authentication authority.
  final void Function(SecurityKeyStatus status) onStatus;
}

abstract interface class SecurityKeyPinRequest {
  int get attemptsRemaining;
}

abstract interface class SecurityKeyConnection {
  String get name;
  SecurityKeyTransport get transport;
}

enum SecurityKeyTransport { usb, nfc }

enum SecurityKeyStatus { touchRequired, presentKey }

// Required implementation contract:
// 1. Each ceremony owns native work, connections, prompts and cancellation hooks.
// 2. Drain/close native resources and detach hooks before returning a session;
//    no fallible native cleanup may remain after successful Future completion.
// 3. Check cancellation immediately before transferring ownership to the caller.
//    Cancellation before transfer wipes the output and fails. After transfer,
//    the caller owns the session and late cancellation does not revoke it.
// 4. Native ceremonies share the appropriate busy gate. A returned session does
//    not hold it, so callers can create a replacement while holding an old secret.
// 5. A completed unlock is not a database commit. Keybay owns authenticated
//    transactions/CAS so verification state cannot be committed out of order.
// 6. Consumer interaction exceptions cancel/drain native work then propagate.
// 7. Consumers must await ceremonies to settlement: abandoning the Future or
//    wrapping it in Future.timeout can orphan a later session. Cancel through
//    the operation's cancellation token, await settlement, and close any result.
// 8. No finalizer is relied upon for timely cleanup. Explicit close is the tradeoff
//    for imperative ownership; callbacks are not cryptographically required.
//
// RP ID references:
// https://www.w3.org/TR/webauthn-3/#relying-party-identifier
// https://developer.apple.com/documentation/authenticationservices/supporting-passkeys
// https://developer.android.com/identity/credential-manager/prerequisites
// The current direct adapter also passes its namespace unchanged to libfido2's
// fido_cred_set_rp / fido_assert_set_rp. Renaming this config is not a scope change.

// ---- Type-checked consumer examples ----
// Example* types model Keybay INTERNAL responsibilities, not new public APIs.
// Keybay applications retain open(credential: ...) and session.auth; Keybay owns
// this integration. The public SDK has no use callback or generic result wrapper.

Future<void> exampleAddMethod({
  required Keypass keypass,
  required PasskeySource source,
  required SecurityKeyInteraction hardwareUi,
  required ExampleVaultStore store,
  required ExampleVaultCrypto crypto,
  required String methodId,
  required int revision,
  PasskeyCancellation? cancellation,
}) async {
  final session = await keypass.create(
    source: source,
    label: 'Personal vault',
    interaction: hardwareUi,
    cancellation: cancellation,
  );
  try {
    final envelope = await crypto.wrapVaultKey(
      material: session.secret,
      methodId: methodId,
    );
    await store.insertMethod(
      expectedRevision: revision,
      methodId: methodId,
      record: session.record.toJson(),
      envelope: envelope,
    );
  } finally {
    session.close();
  }
}

Future<ExampleRecoveredKey> exampleUnlock({
  required Keypass keypass,
  required SecurityKeyInteraction hardwareUi,
  required ExampleVaultStore store,
  required ExampleVaultCrypto crypto,
  required ExampleSavedMethod saved,
  PasskeyCancellation? cancellation,
}) async {
  final session = await keypass.unlock(
    PasskeyRecord.fromJson(saved.record),
    interaction: hardwareUi,
    cancellation: cancellation,
  );
  try {
    final key = await crypto.unwrapVaultKey(
      material: session.secret,
      methodId: saved.id,
      envelope: saved.envelope,
    );
    try {
      await store.updateVerifiedState(
        expectedRevision: saved.revision,
        methodId: saved.id,
        record: session.record.toJson(),
      );
      return key; // Ownership passes to Keybay after successful commit.
    } catch (_) {
      key.destroy();
      rethrow;
    }
  } finally {
    session.close();
  }
}

abstract interface class ExampleVaultCrypto {
  // Keybay owns purpose-bound KDF, AEAD and vault-key lifetime. Wrapping context
  // includes stable store/method identity, never the mutable record JSON.
  Future<Uint8List> wrapVaultKey({
    required Uint8List material,
    required String methodId,
  });
  Future<ExampleRecoveredKey> unwrapVaultKey({
    required Uint8List material,
    required String methodId,
    required Uint8List envelope,
  });
}

abstract interface class ExampleVaultStore {
  // Authenticate complete metadata and enforce revision/transaction rules.
  Future<void> insertMethod({
    required int expectedRevision,
    required String methodId,
    required Map<String, Object?> record,
    required Uint8List envelope,
  });
  Future<void> updateVerifiedState({
    required int expectedRevision,
    required String methodId,
    required Map<String, Object?> record,
  });
}

abstract interface class ExampleSavedMethod {
  String get id;
  int get revision;
  Map<String, Object?> get record;
  Uint8List get envelope;
}

abstract interface class ExampleRecoveredKey {
  void destroy();
}
