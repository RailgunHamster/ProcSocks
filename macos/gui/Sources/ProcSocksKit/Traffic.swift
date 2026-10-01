import Foundation

/// Published by the proxy core, exclusively from rule-matched SOCKS relays.
public struct ProxyTrafficSnapshot: Codable {
    public let schemaVersion: Int
    public let sessionId: String
    public let sampledAt: Double
    public let processes: [ProxyTrafficReading]
    public init(sessionId: String, sampledAt: Double, processes: [ProxyTrafficReading]) {
        schemaVersion = 1; self.sessionId = sessionId; self.sampledAt = sampledAt; self.processes = processes
    }
}

public struct ProxyTrafficReading: Codable {
    public let pid: Int
    public let executablePath: String
    public let name: String
    public let downloaded: UInt64
    public let uploaded: UInt64
    public let activeConnections: Int
    public init(pid: Int, executablePath: String, name: String, downloaded: UInt64, uploaded: UInt64, activeConnections: Int = 1) {
        self.pid = pid; self.executablePath = executablePath; self.name = name
        self.downloaded = downloaded; self.uploaded = uploaded; self.activeConnections = activeConnections
    }
}

public struct TrafficPoint: Identifiable {
    public let date: Date
    public let downloaded: Double
    public let uploaded: Double
    public var id: Date { date }
    public init(date: Date, downloaded: Double, uploaded: Double) {
        self.date = date; self.downloaded = downloaded; self.uploaded = uploaded
    }
}

public struct ProcessTraffic: Identifiable {
    public var pid: Int
    public var name: String
    public var executablePath: String
    public var downloaded: UInt64 = 0
    public var uploaded: UInt64 = 0
    public var downloadRate: Double = 0
    public var uploadRate: Double = 0
    public var active = true
    public var points: [TrafficPoint] = []
    public var id: Int { pid }
}

public struct TrafficTracker {
    public private(set) var processes: [Int: ProcessTraffic] = [:]
    public private(set) var points: [TrafficPoint] = []
    private var session: String?
    private var previous: [Int: ProxyTrafficReading] = [:]
    private var previousDate: Date?
    private let capacity: Int
    public init(capacity: Int = 1800) { self.capacity = max(2, capacity) }

    public mutating func ingest(_ snapshot: ProxyTrafficSnapshot) {
        guard snapshot.schemaVersion == 1, snapshot.sampledAt.isFinite else { return }
        let date = Date(timeIntervalSince1970: snapshot.sampledAt)
        if session != snapshot.sessionId {
            reset(); previous = [:]; previousDate = nil; session = snapshot.sessionId
        }
        guard previousDate.map({ date > $0 }) ?? true else { return }
        let interval = previousDate.map { max(date.timeIntervalSince($0), 0.001) } ?? 1
        let baseline = previousDate == nil
        markIdle()
        for reading in snapshot.processes {
            let old = previous[reading.pid]
            let sameProcess = old?.executablePath == reading.executablePath
            let downloaded = baseline ? 0 : difference(reading.downloaded, from: sameProcess ? old?.downloaded : nil)
            let uploaded = baseline ? 0 : difference(reading.uploaded, from: sameProcess ? old?.uploaded : nil)
            // Do not populate a new GUI session with old, already closed relays.
            if processes[reading.pid] == nil && reading.activeConnections == 0 && downloaded == 0 && uploaded == 0 { continue }
            var process = processes[reading.pid] ?? ProcessTraffic(pid: reading.pid, name: reading.name, executablePath: reading.executablePath)
            if process.executablePath != reading.executablePath {
                process = ProcessTraffic(pid: reading.pid, name: reading.name, executablePath: reading.executablePath)
            }
            process.downloaded += downloaded; process.uploaded += uploaded
            process.downloadRate = Double(downloaded) / interval
            process.uploadRate = Double(uploaded) / interval
            process.active = reading.activeConnections > 0
            processes[reading.pid] = process
        }
        previous = Dictionary(snapshot.processes.map { ($0.pid, $0) }, uniquingKeysWith: { _, current in current })
        previousDate = date
        appendPoint(at: date)
    }

    public mutating func idle(at date: Date) {
        markIdle()
        guard points.last.map({ date > $0.date }) ?? true else { return }
        appendPoint(at: date)
    }

    public mutating func reset() { processes.removeAll(); points.removeAll() }

    private func difference(_ current: UInt64, from previous: UInt64?) -> UInt64 {
        guard let previous else { return current }
        return current >= previous ? current - previous : current
    }

    private mutating func markIdle() {
        for pid in Array(processes.keys) {
            processes[pid]?.downloadRate = 0; processes[pid]?.uploadRate = 0; processes[pid]?.active = false
        }
    }

    private mutating func appendPoint(at date: Date) {
        guard points.last.map({ date > $0.date }) ?? true else { return }
        for pid in Array(processes.keys) {
            guard var process = processes[pid] else { continue }
            process.points.append(TrafficPoint(date: date, downloaded: process.downloadRate, uploaded: process.uploadRate))
            if process.points.count > capacity { process.points.removeFirst(process.points.count - capacity) }
            processes[pid] = process
        }
        points.append(TrafficPoint(date: date, downloaded: processes.values.reduce(0) { $0 + $1.downloadRate },
                                  uploaded: processes.values.reduce(0) { $0 + $1.uploadRate }))
        if points.count > capacity { points.removeFirst(points.count - capacity) }
    }
}
