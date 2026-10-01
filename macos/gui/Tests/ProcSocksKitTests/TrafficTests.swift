import Foundation
import XCTest
@testable import ProcSocksKit

final class TrafficTests: XCTestCase {
    private func row(_ downloaded: UInt64, _ uploaded: UInt64 = 0, pid: Int = 7, path: String = "/Applications/Test.app/Contents/MacOS/Test", active: Int = 1) -> ProxyTrafficReading {
        ProxyTrafficReading(pid: pid, executablePath: path, name: "Test", downloaded: downloaded, uploaded: uploaded, activeConnections: active)
    }
    private func sample(_ time: Double, _ rows: [ProxyTrafficReading], session: String = "42-start") -> ProxyTrafficSnapshot {
        ProxyTrafficSnapshot(sessionId: session, sampledAt: time, processes: rows)
    }

    func testBackendSnapshotDecodesWithoutAnInventoryOrSelectionRule() throws {
        let json = #"{"schemaVersion":1,"sessionId":"42-start","sampledAt":100,"processes":[{"pid":7,"executablePath":"/advanced-rule-only","name":"Test","downloaded":123,"uploaded":45,"activeConnections":2}]}"#
        let snapshot = try JSONDecoder().decode(ProxyTrafficSnapshot.self, from: Data(json.utf8))
        XCTAssertEqual(snapshot.processes[0].executablePath, "/advanced-rule-only")
        var tracker = TrafficTracker()
        tracker.ingest(snapshot)
        tracker.ingest(sample(102, [row(223, 65, path: "/advanced-rule-only", active: 2)]))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 100)
        XCTAssertEqual(tracker.processes[7]?.downloadRate, 50)
        XCTAssertEqual(tracker.processes[7]?.uploadRate, 10)
    }

    func testCumulativeCoreCountersAreBaselinedAndRepeatedSnapshotsAreIgnored() {
        var tracker = TrafficTracker()
        tracker.ingest(sample(100, [row(1_000_000, 500_000)]))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 0)
        tracker.ingest(sample(102, [row(1_000_200, 500_100)]))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 200)
        XCTAssertEqual(tracker.processes[7]?.uploadRate, 50)
        tracker.ingest(sample(102, [row(1_000_200, 500_100)]))
        tracker.ingest(sample(101, [row(1_000_200, 500_100)]))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 200)
        XCTAssertEqual(tracker.points.count, 2)
    }

    func testIdleAndStoppedProxyDropToZeroWithoutLosingTotals() {
        var tracker = TrafficTracker()
        tracker.ingest(sample(100, []))
        tracker.ingest(sample(101, [row(50, 10)]))
        tracker.ingest(sample(102, [row(50, 10, active: 0)]))
        XCTAssertEqual(tracker.processes[7]?.downloadRate, 0)
        XCTAssertEqual(tracker.processes[7]?.downloaded, 50)
        XCTAssertEqual(tracker.processes[7]?.active, false)
        tracker.idle(at: Date(timeIntervalSince1970: 103))
        XCTAssertEqual(tracker.points.last?.downloaded, 0)
        XCTAssertEqual(tracker.processes[7]?.downloaded, 50)
    }

    func testResetAndBoundedThirtyMinuteHistoryDoNotRecountTheBackendLifetime() {
        var tracker = TrafficTracker(capacity: 3)
        tracker.ingest(sample(100, []))
        for index in 1...10 {
            tracker.ingest(sample(100 + Double(index), [row(UInt64(index) * 5)]))
        }
        XCTAssertEqual(tracker.points.count, 3)
        XCTAssertEqual(tracker.processes[7]?.points.count, 3)
        tracker.reset()
        tracker.ingest(sample(111, [row(55)]))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 5)

        var thirtyMinutes = TrafficTracker()
        thirtyMinutes.ingest(sample(0, []))
        for second in 1...1805 { thirtyMinutes.ingest(sample(Double(second), [])) }
        XCTAssertEqual(thirtyMinutes.points.count, 1800)
        XCTAssertEqual(thirtyMinutes.points.first?.date.timeIntervalSince1970, 6)
    }

    func testBackendRestartAndReusedPIDCannotInheritPreviousTotals() {
        var tracker = TrafficTracker()
        tracker.ingest(sample(100, []))
        tracker.ingest(sample(101, [row(500)]))
        tracker.ingest(sample(102, [row(5, path: "/new")]))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 5)
        tracker.ingest(sample(103, [row(123)], session: "43-new"))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 0)
        XCTAssertEqual(tracker.points.count, 1)
        tracker.ingest(sample(104, [row(125)], session: "43-new"))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 2)
    }

    func testClosedHistoricalRelaysDoNotAppearInANewGUISession() {
        var tracker = TrafficTracker()
        tracker.ingest(sample(100, [row(500, active: 0)]))
        tracker.ingest(sample(101, [row(500, active: 0)]))
        XCTAssertTrue(tracker.processes.isEmpty)
        tracker.ingest(sample(102, [row(505, active: 0)]))
        XCTAssertEqual(tracker.processes[7]?.downloaded, 5)
    }
}
