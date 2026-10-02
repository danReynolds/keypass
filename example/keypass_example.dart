import 'package:keypass/keypass.dart';

Future<void> main() async {
  final passkeys = Keypass.system(rpId: 'vault.example.com');
  final readiness = await passkeys.check();
  // A bare CLI has no linked native app host. This check never opens UI.
  print(
    readiness.canAttempt ? 'Ready to attempt creation' : readiness.reason!.name,
  );
}
