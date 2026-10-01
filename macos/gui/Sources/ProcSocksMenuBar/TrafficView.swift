import Charts
import ProcSocksKit
import SwiftUI

@MainActor
struct TrafficView: View {
    @ObservedObject var traffic: TrafficMonitor
    let selections: [ProcessSelection]
    let updateBackend: () -> Void
    @State private var selectedPID: Int?
    @State private var selectedOnly = false
    @State private var search = ""
    @State private var seconds = 300

    private var rows: [ProcessTraffic] {
        traffic.tracker.processes.values.filter { row in
            let path = row.executablePath
            let name = row.name
            let matchesSelection = selections.contains { target in
                target.kind == .application ? path.hasPrefix(target.path + "/") : path == target.path
            }
            return (!selectedOnly || matchesSelection) && (search.isEmpty || name.localizedCaseInsensitiveContains(search) || String(row.pid).contains(search))
        }.sorted {
            let left = $0.downloadRate + $0.uploadRate, right = $1.downloadRate + $1.uploadRate
            if left != right { return left > right }
            return $0.downloaded + $0.uploaded > $1.downloaded + $1.uploaded
        }
    }

    private var chosen: ProcessTraffic? { selectedPID.flatMap { traffic.tracker.processes[$0] } }
    private var title: String {
        guard let chosen else { return selectedOnly ? "已选应用代理流量" : "代理流量合计" }
        return "\(chosen.name) · PID \(chosen.pid)"
    }
    private var points: [TrafficPoint] {
        let source: [TrafficPoint]
        if let chosen { source = chosen.points }
        else if selectedOnly || !search.isEmpty {
            var totals: [Date: (Double, Double)] = [:]
            for row in rows {
                for point in row.points {
                    let previous = totals[point.date] ?? (0, 0)
                    totals[point.date] = (previous.0 + point.downloaded, previous.1 + point.uploaded)
                }
            }
            source = totals.keys.sorted().map { TrafficPoint(date: $0, downloaded: totals[$0]!.0, uploaded: totals[$0]!.1) }
        } else { source = traffic.tracker.points }
        guard let latest = source.last?.date else { return [] }
        return source.filter { $0.date >= latest.addingTimeInterval(-Double(seconds)) }
    }
    private var summary: (UInt64, UInt64, Double, Double) {
        if let chosen { return (chosen.downloaded, chosen.uploaded, chosen.downloadRate, chosen.uploadRate) }
        return rows.reduce((0, 0, 0, 0)) { ($0.0 + $1.downloaded, $0.1 + $1.uploaded, $0.2 + $1.downloadRate, $0.3 + $1.uploadRate) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Toggle("仅已选应用", isOn: $selectedOnly).toggleStyle(.checkbox)
                TextField("搜索进程或 PID", text: $search).textFieldStyle(.roundedBorder).frame(maxWidth: 200)
                Spacer()
                Picker("时间范围", selection: $seconds) {
                    Text("5 分钟").tag(300); Text("15 分钟").tag(900); Text("30 分钟").tag(1800)
                }.labelsHidden().frame(width: 100)
                Button("重置统计") { selectedPID = nil; traffic.reset() }
            }
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text(title).font(.headline)
                    Spacer()
                    if selectedPID != nil { Button("查看合计") { selectedPID = nil }.buttonStyle(.plain).foregroundStyle(.tint) }
                }
                HStack(spacing: 24) {
                    metric("下载", rate: summary.2, total: summary.0, color: .blue)
                    metric("上传", rate: summary.3, total: summary.1, color: .orange)
                    Spacer()
                    Text("\(rows.count) 个进程").font(.caption).foregroundStyle(.secondary)
                }
                Chart(points) { point in
                    LineMark(x: .value("时间", point.date, unit: .second), y: .value("速度", point.downloaded))
                        .foregroundStyle(by: .value("方向", "下载"))
                    LineMark(x: .value("时间", point.date, unit: .second), y: .value("速度", point.uploaded))
                        .foregroundStyle(by: .value("方向", "上传"))
                }
                .chartForegroundStyleScale(["下载": Color.blue, "上传": Color.orange])
                .chartXScale(domain: (points.last?.date ?? Date()).addingTimeInterval(-Double(seconds))...(points.last?.date ?? Date()))
                .chartYScale(domain: 0...max(1024, points.map { max($0.downloaded, $0.uploaded) }.max() ?? 0))
                .chartYAxis {
                    AxisMarks(position: .leading) { value in
                        AxisGridLine(); AxisValueLabel { if let speed = value.as(Double.self) { Text(TrafficFormat.rate(speed)) } }
                    }
                }
                .chartXAxis { AxisMarks(values: .automatic(desiredCount: 4)) { AxisGridLine(); AxisValueLabel(format: .dateTime.minute().second()) } }
                .frame(height: 145)
                .overlay {
                    if points.count < 2 { Text("正在采样，约 2 秒后显示曲线…").font(.caption).foregroundStyle(.secondary) }
                }
                .accessibilityLabel("\(title) 上传和下载速度曲线")
            }.padding(16).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            HStack {
                Text("进程 / PID").frame(maxWidth: .infinity, alignment: .leading)
                column("下载速度"); column("上传速度"); column("累计下载"); column("累计上传")
            }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 10)
            ScrollView {
                LazyVStack(spacing: 3) {
                    ForEach(rows) { row in
                        Button { selectedPID = row.pid } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(row.name).lineLimit(1)
                                    Text("PID \(row.pid)\(row.active ? "" : " · 无活动连接")").font(.caption2).foregroundStyle(.secondary)
                                }.frame(maxWidth: .infinity, alignment: .leading)
                                column(TrafficFormat.rate(row.downloadRate), color: .blue)
                                column(TrafficFormat.rate(row.uploadRate), color: .orange)
                                column(TrafficFormat.bytes(row.downloaded)); column(TrafficFormat.bytes(row.uploaded))
                            }.font(.system(size: 11, design: .monospaced)).padding(10).contentShape(Rectangle())
                                .background(selectedPID == row.pid ? Color.accentColor.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 7))
                        }.buttonStyle(.plain).help(row.executablePath)
                    }
                    if rows.isEmpty, !traffic.tracker.points.isEmpty {
                        Text(traffic.running ? "当前筛选下没有代理流量。" : "代理已停止，启用后开始统计代理流量。").font(.caption).foregroundStyle(.secondary).padding()
                    }
                }
            }.background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            if let error = traffic.failure { Text(error).font(.caption).foregroundStyle(.red) }
            if traffic.needsBackendUpdate { Button("更新代理后台", action: updateBackend) }
            Text("仅统计经 ProcSocks 上游代理实际转发的 TCP 字节，包含 TLS 数据；不含直连回退、UDP、SOCKS 握手及 TCP/IP 包头。累计从打开界面、重置统计或后台重启后开始。").font(.caption).foregroundStyle(.secondary)
        }.padding(.horizontal, 24).padding(.bottom, 20)
            .onChange(of: selectedOnly) { _ in selectedPID = nil }
            .onChange(of: search) { _ in selectedPID = nil }
    }

    private func column(_ text: String, color: Color = .primary) -> some View {
        Text(text).foregroundStyle(color).frame(width: 82, alignment: .trailing).lineLimit(1)
    }
    private func metric(_ label: String, rate: Double, total: UInt64, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(label) \(TrafficFormat.rate(rate))").font(.title3.monospacedDigit()).foregroundStyle(color)
            Text("累计 \(TrafficFormat.bytes(total))").font(.caption).foregroundStyle(.secondary)
        }
    }
}

enum TrafficFormat {
    static func bytes(_ bytes: UInt64) -> String {
        if bytes == 0 { return "0 B" }
        return ByteCountFormatter.string(fromByteCount: Int64(min(bytes, UInt64(Int64.max))), countStyle: .binary)
    }
    static func rate(_ value: Double) -> String { bytes(UInt64(max(0, min(value, Double(Int64.max - 1024))))) + "/s" }
}

@MainActor
struct TrafficQuickStatus: View {
    @ObservedObject var traffic: TrafficMonitor
    var body: some View {
        HStack {
            Label(TrafficFormat.rate(traffic.totals.downloadRate), systemImage: "arrow.down").foregroundStyle(.blue)
            Spacer()
            Label(TrafficFormat.rate(traffic.totals.uploadRate), systemImage: "arrow.up").foregroundStyle(.orange)
        }.font(.caption.monospacedDigit()).accessibilityLabel("ProcSocks 实际代理流量")
    }
}
