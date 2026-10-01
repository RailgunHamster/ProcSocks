import Foundation
import ProcSocksKit

@MainActor
final class TrafficMonitor: ObservableObject {
    @Published private(set) var tracker = TrafficTracker()
    @Published private(set) var failure: String?
    @Published private(set) var updated: Date?
    @Published private(set) var needsBackendUpdate = false
    @Published private(set) var running = false
    private var backendPID: Int?
    private var timer: Timer?
    private let snapshotURL = URL(fileURLWithPath: "/Library/Application Support/ProcSocks/traffic.json")

    var totals: (downloaded: UInt64, uploaded: UInt64, downloadRate: Double, uploadRate: Double) {
        tracker.processes.values.reduce((0, 0, 0, 0)) {
            ($0.0 + $1.downloaded, $0.1 + $1.uploaded, $0.2 + $1.downloadRate, $0.3 + $1.uploadRate)
        }
    }

    func setBackend(_ status: BackendStatus) {
        running = status.running; backendPID = status.pid
        sample()
    }

    func start() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sample() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }
    func reset() { tracker.reset() }

    private func sample() {
        guard running else {
            tracker.idle(at: Date()); failure = nil; needsBackendUpdate = false; return
        }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: snapshotURL.path)
            guard let size = attributes[.size] as? NSNumber, size.intValue <= 8 * 1024 * 1024 else {
                throw ConfigurationError("代理流量快照过大。")
            }
            let snapshot = try JSONDecoder().decode(ProxyTrafficSnapshot.self, from: Data(contentsOf: snapshotURL))
            guard snapshot.schemaVersion == 1, snapshot.sampledAt.isFinite,
                  snapshot.sessionId.hasPrefix("\(backendPID ?? -1)-") else {
                throw ConfigurationError("后台流量快照与当前代理进程不一致，请更新代理后台。")
            }
            guard abs(Date().timeIntervalSince1970 - snapshot.sampledAt) < 5 else {
                tracker.idle(at: Date()); failure = "代理流量统计暂未更新。"; return
            }
            tracker.ingest(snapshot)
            updated = Date(timeIntervalSince1970: snapshot.sampledAt)
            failure = nil; needsBackendUpdate = false
        } catch {
            tracker.idle(at: Date())
            needsBackendUpdate = true
            failure = "当前后台尚未提供代理流量统计，请更新代理后台。"
        }
    }
}
