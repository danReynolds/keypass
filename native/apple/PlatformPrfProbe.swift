import AuthenticationServices
import Foundation

// Compile-only API probe. This never presents UI or accesses a credential.
@available(macOS 15.0, iOS 18.0, *)
func requests(
    relyingPartyID: String,
    challenge: Data,
    userID: Data,
    credentialID: Data,
    prfInput: Data
) -> (ASAuthorizationRequest, ASAuthorizationRequest) {
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
        relyingPartyIdentifier: relyingPartyID
    )
    let registration = provider.createCredentialRegistrationRequest(
        challenge: challenge, name: "Disposable Keypass research credential", userID: userID
    )
    registration.userVerificationPreference = .required
    registration.prf = .checkForSupport

    let assertion = provider.createCredentialAssertionRequest(challenge: challenge)
    assertion.userVerificationPreference = .required
    assertion.allowedCredentials = [
        ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialID)
    ]
    assertion.prf = .inputValues(.init(saltInput1: prfInput))
    return (registration, assertion)
}

@available(macOS 15.0, iOS 18.0, *)
func hasSecret(_ assertion: ASAuthorizationPlatformPublicKeyCredentialAssertion) -> Bool {
    assertion.prf?.first.bitCount == 256
}
