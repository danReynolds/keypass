import XCTest
@testable import KeypassNative

final class PresentationGateTests: XCTestCase {
    private final class Window {}

    func testConsecutiveCeremonyWaitsForOriginalWindowToReactivate() {
        let original = Window()
        var results: [Window?] = []
        let gate = PresentationGate<Window> { results.append($0) }
        // Completion of registration can precede the scene's reactivation.
        gate.update(.transitioning(original))
        gate.update(.transitioning(original))
        XCTAssertTrue(results.isEmpty)
        gate.update(.active(original))
        XCTAssertEqual(results.count, 1)
        XCTAssertTrue(results[0] === original)
        gate.update(.active(original))
        gate.expire()
        XCTAssertEqual(results.count, 1)
    }

    func testActiveHostCompletesImmediately() {
        let original = Window()
        var selected: Window?
        let gate = PresentationGate<Window> { selected = $0 }
        gate.update(.active(original))
        XCTAssertTrue(selected === original)
    }

    func testWaitingCannotSwitchToAnotherWindow() {
        let original = Window()
        let other = Window()
        var results: [Window?] = []
        let gate = PresentationGate<Window> { results.append($0) }
        gate.update(.transitioning(original))
        gate.update(.active(other))
        XCTAssertEqual(results.count, 1)
        XCTAssertNil(results[0])
        gate.update(.active(original))
        XCTAssertEqual(results.count, 1)
    }

    func testMissingOrAmbiguousHostFailsWithoutWaiting() {
        var results: [Window?] = []
        let gate = PresentationGate<Window> { results.append($0) }
        gate.update(.unavailable)
        XCTAssertEqual(results.count, 1)
        XCTAssertNil(results[0])
    }

    func testBackgroundingOrDisconnectFailsTheWaitingRequest() {
        let original = Window()
        var results: [Window?] = []
        let gate = PresentationGate<Window> { results.append($0) }
        gate.update(.transitioning(original))
        gate.update(.unavailable)
        gate.update(.active(original))
        XCTAssertEqual(results.count, 1)
        XCTAssertNil(results[0])
    }

    func testCancellationCannotProduceALatePrompt() {
        let original = Window()
        var results: [Window?] = []
        let gate = PresentationGate<Window> { results.append($0) }
        gate.update(.transitioning(original))
        gate.cancel()
        gate.update(.active(original))
        gate.expire()
        XCTAssertTrue(results.isEmpty)
    }

    func testTimeoutCannotProduceALatePrompt() {
        let original = Window()
        var results: [Window?] = []
        let gate = PresentationGate<Window> { results.append($0) }
        gate.update(.transitioning(original))
        gate.expire()
        gate.update(.active(original))
        XCTAssertEqual(results.count, 1)
        XCTAssertNil(results[0])
    }
}
