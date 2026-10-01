import AppKit
import Combine
import Foundation
import ProcSocksKit
import ServiceManagement
import UniformTypeIdentifiers

enum SettingsPage: String, CaseIterable, Identifiable {
    case processes = "应用与进程"
    case connection = "代理服务器"
    case traffic = "实时流量"
    case advanced = "高级规则"
    case logs = "运行日志"
    var id: Self { self }
    var symbol: String {
        switch self {
        case .processes: return "square.stack.3d.up"
        case .connection: return "network"
        case .traffic: return "chart.xyaxis.line"
        case .advanced: return "slider.horizontal.3"
        case .logs: return "text.alignleft"
        }
    }
}

struct ProcessRow: Identifiable {
    var target: ProcessSelection
    var pids: [Int]
    var id: String { target.id }
    var running: Bool { !pids.isEmpty }
}

@MainActor
final class AppController: ObservableObject {
    @Published var configuration = UserConfiguration.empty()
    @Published var status = BackendStatus.stopped
    @Published var processes: [RunningProcess] = []
    @Published var installedApplications: [ProcessSelection] = []
    @Published var page: SettingsPage = .processes
    @Published var search = ""
    @Published var showExecutables = false
    @Published var busy = false
    @Published var operation = ""
    @Published var error: String?
    @Published var notice: String?
    @Published var logText = "启用代理后，这里会显示连接归属、规则匹配与代理日志。"
    @Published var loginEnabled = false
    @Published var savedData: Data?

    let core: URL
    let traffic = TrafficMonitor()
    let directory: URL
    let configurationURL: URL
    let logURL = URL(fileURLWithPath: "/Library/Application Support/ProcSocks/core.log")
    var showSettings: ((SettingsPage) -> Void)?
    var requestQuit: (() -> Void)?
    private var timer: Timer?
    private var refreshing = false

    init() {
        let environment = ProcessInfo.processInfo.environment
        let override = environment["PROCSOCKS_GUI_HOME"]
        directory = override.map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/ProcSocks", isDirectory: true)
        configurationURL = directory.appendingPathComponent("procsocks.json")
        core = Bundle.main.resourceURL!.appendingPathComponent("procsocks")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            if FileManager.default.fileExists(atPath: configurationURL.path) {
                configuration = try UserConfiguration(data: Data(contentsOf: configurationURL))
            } else {
                let repoConfig = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("procsocks.local.json")
                let initial = environment["PROCSOCKS_CONFIG"].map { URL(fileURLWithPath: $0) } ?? repoConfig
                let sample = Bundle.main.resourceURL!.appendingPathComponent("config.example.json")
                let source = FileManager.default.fileExists(atPath: initial.path) ? initial : sample
                configuration = try UserConfiguration(data: Data(contentsOf: source))
                try writeProfile(configuration.encoded())
                notice = "已导入现有配置；从列表勾选应用即可添加代理。"
            }
            savedData = try configuration.encoded()
        } catch {
            self.error = "读取配置失败：\(error.localizedDescription)"
        }
        loginEnabled = SMAppService.mainApp.status == .enabled
        installedApplications = Self.findApplications()
        traffic.start()
        Task { await refresh() }
        timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
    }

    var dirty: Bool { (try? configuration.encoded()) != savedData }
    var advancedCount: Int { UserConfiguration.ruleLines(configuration.advancedProcessRules).count }
    var statusTitle: String { busy ? operation : (status.running ? "代理运行中" : (status.loaded ? "正在启动" : "代理已停止")) }
    var targetCount: Int { configuration.selections.count }

    func selected(_ target: ProcessSelection) -> Bool {
        configuration.selections.contains { $0.id == target.id }
    }

    func setSelected(_ target: ProcessSelection, enabled: Bool) {
        if enabled, !selected(target) { configuration.selections.append(target) }
        if !enabled { configuration.selections.removeAll { $0.id == target.id } }
        notice = nil
        error = nil
    }

    func coveredByApplication(_ target: ProcessSelection) -> Bool {
        target.kind == .executable && configuration.selections.contains {
            $0.kind == .application && target.path.hasPrefix($0.path + "/")
        }
    }

    var rows: [ProcessRow] {
        var groups: [String: ProcessRow] = [:]
        if !showExecutables {
            for target in installedApplications { groups[target.id] = ProcessRow(target: target, pids: []) }
        }
        for process in processes where !process.executablePath.hasPrefix(Bundle.main.bundleURL.path + "/") {
            let target: ProcessSelection
            if showExecutables {
                target = ProcessSelection(kind: .executable, path: process.executablePath, name: process.name)
            } else if let path = ProcessSelection.applicationPath(for: process.executablePath) {
                target = Self.appSelection(path)
            } else { continue }
            if groups[target.id] == nil { groups[target.id] = ProcessRow(target: target, pids: []) }
            groups[target.id]?.pids.append(process.pid)
        }
        for target in configuration.selections where (target.kind == .executable) == showExecutables {
            if groups[target.id] == nil { groups[target.id] = ProcessRow(target: target, pids: []) }
        }
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return groups.values.filter { row in
            query.isEmpty || row.target.name.localizedCaseInsensitiveContains(query) || row.target.path.localizedCaseInsensitiveContains(query)
        }.sorted { left, right in
            let a = selected(left.target), b = selected(right.target)
            if a != b { return a }
            if left.running != right.running { return left.running }
            return left.target.name.localizedStandardCompare(right.target.name) == .orderedAscending
        }
    }

    func refresh() async {
        guard !busy, !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do {
            async let stateResult = CoreCommands.run(executable: core, arguments: ["gui", "status"])
            async let processResult = CoreCommands.run(executable: core, arguments: ["processes"])
            let (state, inventory) = try await (stateResult, processResult)
            if state.status != 0 { throw ConfigurationError(state.output) }
            status = try JSONDecoder().decode(BackendStatus.self, from: Data(state.output.utf8))
            traffic.setBackend(status)
            if inventory.status == 0 {
                processes = try JSONDecoder().decode([RunningProcess].self, from: Data(inventory.output.utf8))
            }
            readLog()
        } catch {
            self.error = "无法读取后台状态：\(error.localizedDescription)"
        }
    }

    func save(start: Bool? = nil) {
        guard !busy else { return }
        busy = true
        let snapshot = configuration
        Task {
            error = nil
            notice = nil
            operation = start == true ? "正在启用代理…" : "正在保存配置…"
            var stage: URL?
            defer {
                if let stage { try? FileManager.default.removeItem(at: stage) }
                busy = false
                Task { await refresh() }
            }
            do {
                let data = try snapshot.encoded()
                let shouldRun = start ?? status.running
                if (shouldRun || snapshot.autostart) && snapshot.compiledPatterns.isEmpty {
                    throw ConfigurationError("请先勾选至少一个应用或进程，也可以添加高级代理规则。")
                }
                let staged = directory.appendingPathComponent(".apply-\(UUID().uuidString).json")
                stage = staged
                try Self.privateWrite(data, to: staged)
                let validation = try await CoreCommands.run(executable: core, arguments: ["--config", staged.path, "gui", "validate"])
                guard validation.status == 0 else { throw ConfigurationError(validation.output) }
                if status.installed || shouldRun || snapshot.autostart {
                    operation = "等待系统认证并应用…"
                    var arguments = ["--config", staged.path, "gui", "apply", "--owner", String(getuid())]
                    if snapshot.autostart { arguments.append("--autostart") }
                    if !shouldRun { arguments.append("--stopped") }
                    let result = try await CoreCommands.privileged(executable: core, arguments: arguments)
                    guard result.status == 0 else { throw ConfigurationError(result.output) }
                }
                try writeProfile(data)
                savedData = data
                notice = shouldRun ? "代理已启用，已保存的规则正在生效。" : "配置已保存，下次启用时生效。"
            } catch {
                self.error = Self.friendly(error)
            }
        }
    }

    func stop(after: (() -> Void)? = nil) {
        guard !busy else { return }
        busy = true
        Task {
            operation = "正在停止代理…"
            error = nil
            notice = nil
            defer { busy = false; Task { await refresh() } }
            do {
                let result = try await CoreCommands.privileged(executable: core, arguments: ["gui", "stop"])
                guard result.status == 0 else { throw ConfigurationError(result.output) }
                notice = "代理已停止，系统网络规则已恢复。"
                after?()
            } catch { self.error = Self.friendly(error) }
        }
    }

    func testUpstream() {
        guard !busy else { return }
        busy = true
        let snapshot = configuration
        Task {
            operation = "正在测试 SOCKS5…"
            error = nil
            notice = nil
            let stage = directory.appendingPathComponent(".probe-\(UUID().uuidString).json")
            defer { try? FileManager.default.removeItem(at: stage); busy = false }
            do {
                try Self.privateWrite(snapshot.encoded(), to: stage)
                let result = try await CoreCommands.run(executable: core, arguments: ["--config", stage.path, "gui", "probe"])
                guard result.status == 0 else { throw ConfigurationError(result.output) }
                notice = "SOCKS5 握手和目标连接成功。\n" + result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            } catch { self.error = "上游测试失败：\(Self.friendly(error))" }
        }
    }

    func revert() {
        guard let savedData else { return }
        do { configuration = try UserConfiguration(data: savedData); error = nil; notice = "已撤销未保存的修改。" }
        catch { self.error = error.localizedDescription }
    }

    func addFile() {
        let panel = NSOpenPanel()
        panel.title = "添加应用或可执行文件"
        panel.message = "选择 .app 可覆盖应用包内的辅助进程；也可以单独选择一个可执行文件。"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            let target: ProcessSelection
            if url.pathExtension.lowercased() == "app" { target = Self.appSelection(url.path) }
            else if FileManager.default.isExecutableFile(atPath: url.path) {
                target = ProcessSelection(kind: .executable, path: url.path, name: url.lastPathComponent)
                showExecutables = true
            } else { error = "请选择 .app 应用或可执行文件。"; continue }
            setSelected(target, enabled: true)
        }
        search = ""
    }

    func importConfiguration() {
        let panel = NSOpenPanel()
        panel.title = "导入 ProcSocks 配置"
        panel.message = "现有上游参数和高级正则规则会保留；导入后点击保存才会应用。"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            configuration = try UserConfiguration(data: Data(contentsOf: url))
            notice = "配置已导入，点击保存应用。"
            error = nil
        } catch { self.error = "导入失败：\(error.localizedDescription)" }
    }

    func exportConfiguration() {
        let panel = NSSavePanel()
        panel.title = "导出配置"
        panel.message = "文件包含上游认证信息，请保存到你信任的位置。"
        panel.nameFieldStringValue = "procsocks.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try Self.privateWrite(configuration.encoded(), to: url); notice = "配置已导出。" }
        catch { self.error = error.localizedDescription }
    }

    func setLoginEnabled(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            loginEnabled = SMAppService.mainApp.status == .enabled
            notice = "菜单栏登录设置已更新。"
        } catch { self.error = "无法更新登录设置：\(error.localizedDescription)" }
    }

    func readLog() {
        guard let file = try? FileHandle(forReadingFrom: logURL) else { return }
        defer { try? file.close() }
        do {
            let size = try file.seekToEnd()
            try file.seek(toOffset: size > 96 * 1024 ? size - 96 * 1024 : 0)
            let data = try file.readToEnd() ?? Data()
            if !data.isEmpty { logText = String(decoding: data, as: UTF8.self) }
        } catch { logText = "读取日志失败：\(error.localizedDescription)" }
    }

    private func writeProfile(_ data: Data) throws { try Self.privateWrite(data, to: configurationURL) }

    private static func privateWrite(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private static func friendly(_ error: Error) -> String {
        let text = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.replacingOccurrences(of: "Error: ", with: "")
    }

    private static func appSelection(_ path: String) -> ProcessSelection {
        let bundle = Bundle(path: path)
        let name = bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
        return ProcessSelection(kind: .application, path: path, name: name)
    }

    private static func findApplications() -> [ProcessSelection] {
        let roots = [URL(fileURLWithPath: "/Applications"), FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications")]
        var paths = Set<String>()
        func scan(_ folder: URL, depth: Int) {
            guard let children = try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else { return }
            for child in children {
                if child.pathExtension.lowercased() == "app" {
                    if Bundle(url: child)?.bundleIdentifier != Bundle.main.bundleIdentifier { paths.insert(child.path) }
                } else if depth > 0, (try? child.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
                    scan(child, depth: depth - 1)
                }
            }
        }
        for root in roots { scan(root, depth: 1) }
        return paths.map(appSelection).sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}
