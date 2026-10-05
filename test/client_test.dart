import 'dart:async';
import 'dart:typed_data';
import 'package:keypass/keypass_backend.dart';
import 'package:test/test.dart';
import 'support/recording_backend.dart';

Matcher fails(PasskeyErrorCode code) =>
    throwsA(isA<PasskeyException>().having((e) => e.code, 'code', code));

void main() {
  late RecordingBackend backend;
  late Keypass client;
  late int factories;
  setUp(() {
    backend = RecordingBackend();
    factories = 0;
    client = keypassWithBackendFactory(
      createBackend: () {
        factories++;
        return backend;
      },
      rpId: 'vault.example.com',
    );
  });

  test(
    'constructors validate scope synchronously without ambient defaults',
    () {
      for (final scope in [
        '',
        'localhost',
        'https://vault.example.com',
        'a..com',
        '127.0.0.1',
      ]) {
        expect(
          () => Keypass.system(rpId: scope),
          fails(PasskeyErrorCode.invalidRequest),
        );
        expect(
          () => Keypass.hardware(rpId: scope),
          fails(PasskeyErrorCode.invalidRequest),
        );
      }
      expect(
        () => Keypass.system(rpId: 'vault.example.com', displayName: ''),
        fails(PasskeyErrorCode.invalidRequest),
      );
      expect(Keypass.system(rpId: 'VAULT.EXAMPLE.COM'), isA<Keypass>());
      expect(Keypass.hardware(rpId: 'dev.example.vault'), isA<Keypass>());
      expect(factories, 0);
    },
  );

  test(
    'check is prompt-free, disposes its backend and reports unavailable',
    () async {
      backend.readiness = const PasskeyAvailability.unavailable(
        PasskeyErrorCode.backendUnavailable,
      );
      final report = await client.check();
      expect(report.canAttempt, isFalse);
      expect(report.reason, PasskeyErrorCode.backendUnavailable);
      expect(backend.registrations, isEmpty);
      expect(backend.evaluations, isEmpty);
      expect(backend.disposed, 1);
      await expectLater(
        client.create(label: 'Vault'),
        fails(PasskeyErrorCode.backendUnavailable),
      );
      expect(backend.registrations, isEmpty);
      expect(backend.disposed, 2);
    },
  );

  test('pre-cancelled check does not create or touch a backend', () async {
    final cancellation = PasskeyCancellation()..cancel();
    await expectLater(
      client.check(cancellation: cancellation),
      fails(PasskeyErrorCode.cancelled),
    );
    expect(factories, 0);
    expect(backend.availabilityCalls, 0);
    expect(backend.disposed, 0);
  });

  test('invalid creation labels fail before backend construction', () async {
    for (final label in ['', '   ', 'x' * 257]) {
      await expectLater(
        client.create(label: label),
        fails(PasskeyErrorCode.invalidRequest),
      );
    }
    expect(factories, 0);
  });

  test(
    'create generates fresh input and three challenges and confirms repeatability',
    () async {
      final result = await client.create(label: 'Personal vault');
      try {
        expect(backend.disposed, 1);
        expect(backend.evaluations, hasLength(2));
        final request = backend.registrations.single;
        expect(request.input.length, 32);
        expect(request.userId.length, 32);
        expect(bindingFromRecord(result.record).input, request.input);
        final challenges = [
          request.challenge,
          ...backend.evaluations.map((e) => e.challenge),
        ];
        expect(challenges.every((v) => v.length == 32), isTrue);
        expect(challenges.map((v) => v.join(',')).toSet(), hasLength(3));
        expect(result.secret, everyElement(7));
        expect(backend.buffers.last, everyElement(0));
        await Future<void>.delayed(Duration.zero);
        expect(result.secret, everyElement(7));
      } finally {
        result.dispose();
      }
      for (final buffer in backend.buffers) {
        expect(buffer, everyElement(0));
      }
    },
  );

  test('each create uses an independent PRF input and user handle', () async {
    final inputs = <String>[];
    final users = <String>[];
    final fresh = keypassWithBackendFactory(
      rpId: 'vault.example.com',
      createBackend: () {
        final b = RecordingBackend();
        b.onRegister = (request) async {
          inputs.add(request.input.join(','));
          users.add(request.userId.join(','));
          return binding(input: request.input, userId: request.userId);
        };
        return b;
      },
    );
    for (var i = 0; i < 3; i++) {
      final result = await fresh.create(label: 'Vault');
      result.dispose();
    }
    expect(inputs.toSet(), hasLength(3));
    expect(users.toSet(), hasLength(3));
  });

  test('different PRFs fail and both owned buffers are erased', () async {
    backend.onEvaluate = (r, _) async =>
        backend.assertion(r.bindings.single, byte: backend.evaluations.length);
    await expectLater(
      client.create(label: 'Vault'),
      fails(PasskeyErrorCode.inconsistentSecret),
    );
    expect(backend.disposed, 1);
    for (final bytes in backend.buffers) {
      expect(bytes, everyElement(0));
    }
  });

  test('second evaluation failure erases the first output', () async {
    backend.onEvaluate = (r, _) async {
      if (backend.evaluations.length == 2) {
        throw const PasskeyException(PasskeyErrorCode.cancelled);
      }
      return backend.assertion(r.bindings.single);
    };
    await expectLater(
      client.create(label: 'Vault'),
      fails(PasskeyErrorCode.cancelled),
    );
    expect(backend.buffers.single, everyElement(0));
    expect(backend.disposed, 1);
  });

  test('registration cannot substitute user handle, RP or PRF input', () async {
    backend.onRegister = (_) async => binding();
    await expectLater(
      client.create(label: 'Vault'),
      fails(PasskeyErrorCode.verificationFailed),
    );
    expect(backend.evaluations, isEmpty);
    expect(backend.disposed, 1);
  });

  test(
    'unlock evaluates exactly one saved credential without registering',
    () async {
      final saved = recordFromBinding(
        binding(id: 2, input: Uint8List.fromList([4, 5])),
      );
      final result = await client.unlock(saved);
      try {
        expect(result.record.toJson(), saved.toJson());
        expect(backend.registrations, isEmpty);
        expect(backend.evaluations, hasLength(1));
        expect(backend.evaluations.single.bindings.single.input, [4, 5]);
        expect(backend.disposed, 1);
      } finally {
        result.dispose();
      }
    },
  );

  test('wrong RP is rejected before constructing the backend', () async {
    await expectLater(
      client.unlock(recordFromBinding(binding(domain: 'other.example.com'))),
      fails(PasskeyErrorCode.invalidBinding),
    );
    expect(factories, 0);
  });

  test('unrelated assertion is rejected and erased', () async {
    backend.onEvaluate = (_, _) async => backend.assertion(binding(id: 99));
    await expectLater(
      client.unlock(recordFromBinding(binding())),
      fails(PasskeyErrorCode.verificationFailed),
    );
    expect(backend.buffers.single, everyElement(0));
  });

  for (final length in [0, 31, 33]) {
    test('malformed secret length $length is rejected and erased', () async {
      backend.onEvaluate = (r, _) async =>
          backend.assertion(r.bindings.single, length: length);
      await expectLater(
        client.unlock(recordFromBinding(binding())),
        fails(PasskeyErrorCode.verificationFailed),
      );
      expect(backend.buffers.single, everyElement(0));
    });
  }

  test(
    'read-only backend output is rejected as a contract violation',
    () async {
      backend.onEvaluate = (r, _) async => PasskeyAssertion(
        credentialId: r.bindings.single.credentialId,
        secret: Uint8List(32).asUnmodifiableView(),
        state: r.bindings.single.authenticatorState,
      );
      await expectLater(
        client.unlock(recordFromBinding(binding())),
        fails(PasskeyErrorCode.backendFailure),
      );
    },
  );

  test(
    'result blocks writable aliases, erases borrowed views and keeps its record',
    () async {
      final result = await client.unlock(recordFromBinding(binding()));
      final view = result.secret;
      final recordJson = result.record.toJson();
      final copy = Uint8List.fromList(view);
      expect(() => view[0] = 8, throwsUnsupportedError);
      expect(() => view.buffer.asUint8List()[0] = 8, throwsUnsupportedError);
      expect(
        () => ByteData.view(view.buffer).setUint8(0, 8),
        throwsUnsupportedError,
      );
      expect(result.toString(), 'PasskeyResult(redacted)');
      result.dispose();
      result.dispose();
      expect(view, everyElement(0));
      expect(backend.buffers.single, everyElement(0));
      expect(() => result.secret, throwsStateError);
      expect(result.record.toJson(), recordJson);
      expect(copy, everyElement(7)); // Consumer copies are outside ownership.
      copy.fillRange(0, copy.length, 0);
    },
  );

  test('native errors are redacted and dispose still runs', () async {
    backend.onEvaluate = (_, _) async =>
        throw StateError('sensitive provider response');
    await expectLater(
      client.unlock(recordFromBinding(binding())),
      fails(PasskeyErrorCode.backendFailure),
    );
    expect(backend.disposed, 1);
  });

  test(
    'disposal failure prevents result transfer and wipes prospective output',
    () async {
      backend.onDispose = () async =>
          throw StateError('private backend details');
      await expectLater(
        client.unlock(recordFromBinding(binding())),
        fails(PasskeyErrorCode.backendFailure),
      );
      expect(backend.disposed, 1);
      expect(backend.buffers.single, everyElement(0));
      // Failed cleanup does not strand the Dart operation gate.
      final other = keypassWithBackendFactory(
        createBackend: RecordingBackend.new,
        rpId: 'vault.example.com',
      );
      final next = await other.unlock(recordFromBinding(binding()));
      next.dispose();
    },
  );

  test('pre-cancellation never constructs a backend', () async {
    final cancellation = PasskeyCancellation()
      ..cancel()
      ..cancel();
    await expectLater(
      client.unlock(recordFromBinding(binding()), cancellation: cancellation),
      fails(PasskeyErrorCode.cancelled),
    );
    expect(factories, 0);
  });

  test('late native success after cancellation is erased', () async {
    final entered = Completer<void>();
    final pending = Completer<PasskeyAssertion>();
    final cancellation = PasskeyCancellation();
    backend.onEvaluate = (_, signal) async {
      entered.complete();
      final result = await pending.future;
      expect(signal.isCancelled, isTrue);
      return result;
    };
    final future = client.unlock(
      recordFromBinding(binding()),
      cancellation: cancellation,
    );
    final expectation = expectLater(future, fails(PasskeyErrorCode.cancelled));
    await entered.future;
    cancellation.cancel();
    pending.complete(backend.assertion(binding()));
    await expectation;
    expect(backend.disposed, 1);
    expect(backend.buffers.single, everyElement(0));
  });

  test(
    'cancellation during backend cleanup wins before result transfer',
    () async {
      final entered = Completer<void>();
      final finish = Completer<void>();
      backend.onDispose = () async {
        entered.complete();
        await finish.future;
      };
      final cancellation = PasskeyCancellation();
      final future = client.unlock(
        recordFromBinding(binding()),
        cancellation: cancellation,
      );
      final expectation = expectLater(
        future,
        fails(PasskeyErrorCode.cancelled),
      );
      await entered.future;
      cancellation.cancel();
      finish.complete();
      await expectation;
      expect(backend.disposed, 1);
      expect(backend.buffers.single, everyElement(0));
    },
  );

  test(
    'late cancellation cannot revoke a successfully transferred result',
    () async {
      final cancellation = PasskeyCancellation();
      final result = await client.unlock(
        recordFromBinding(binding()),
        cancellation: cancellation,
      );
      try {
        cancellation.cancel();
        await Future<void>.delayed(Duration.zero);
        expect(result.secret, everyElement(7));
      } finally {
        result.dispose();
      }
    },
  );

  test('operation gate covers other clients until cleanup finishes', () async {
    final entered = Completer<void>();
    final finish = Completer<void>();
    backend.onDispose = () async {
      entered.complete();
      await finish.future;
    };
    final future = client.unlock(recordFromBinding(binding()));
    await entered.future;
    var called = false;
    final other = keypassWithBackendFactory(
      rpId: 'vault.example.com',
      createBackend: () {
        called = true;
        return RecordingBackend();
      },
    );
    await expectLater(
      other.unlock(recordFromBinding(binding())),
      fails(PasskeyErrorCode.busy),
    );
    expect(called, isFalse);
    finish.complete();
    final result = await future;
    try {
      final next = await other.create(label: 'Replacement');
      try {
        expect(result.secret, everyElement(7));
      } finally {
        next.dispose();
      }
    } finally {
      result.dispose();
    }
  });

  test(
    'success releases native work while caller retains secret across awaits',
    () async {
      final result = await client.unlock(recordFromBinding(binding()));
      try {
        expect(backend.disposed, 1);
        await Future<void>.delayed(Duration.zero);
        expect(result.secret, everyElement(7));
      } finally {
        result.dispose();
      }
    },
  );

  test('fresh operation factories do not retain a previous backend', () async {
    final backends = <RecordingBackend>[];
    final fresh = keypassWithBackendFactory(
      rpId: 'vault.example.com',
      createBackend: () {
        final b = RecordingBackend();
        backends.add(b);
        return b;
      },
    );
    await fresh.check();
    final created = await fresh.create(label: 'Vault');
    try {
      final unlocked = await fresh.unlock(created.record);
      unlocked.dispose();
    } finally {
      created.dispose();
    }
    expect(backends, hasLength(3));
    expect(backends.map((b) => b.disposed), everyElement(1));
  });

  test(
    'counter changes update record but leave saved metadata and identity intact',
    () async {
      final saved = recordFromBinding(binding());
      final oldJson = saved.toJson();
      backend.onEvaluate = (r, _) async {
        final a = backend.assertion(r.bindings.single);
        return PasskeyAssertion(
          credentialId: a.credentialId,
          secret: a.secret,
          state: AuthenticatorState(
            backupEligible: true,
            backupState: false,
            signCount: 42,
          ),
        );
      };
      final result = await client.unlock(saved);
      try {
        expect(result.record.id, saved.id);
        expect(result.record.toJson()['signCount'], 42);
        expect(result.record.toJson()['backupState'], isFalse);
        expect(saved.toJson(), oldJson);
        expect(PasskeyRecord.fromJson(result.record.toJson()).id, saved.id);
      } finally {
        result.dispose();
      }
    },
  );

  test('record identity distinguishes credentials and PRF inputs', () {
    final a = recordFromBinding(binding());
    final b = recordFromBinding(binding(id: 2));
    final c = recordFromBinding(binding(input: Uint8List.fromList([5])));
    expect({a.id, b.id, c.id}, hasLength(3));
    final json = a.toJson();
    json['input'] = 'CQ';
    expect(a.toJson()['input'], isNot(json['input']));
  });
}
