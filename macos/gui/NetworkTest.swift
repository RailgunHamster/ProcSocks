import AppKit
import Foundation
import Network
import Security
import SwiftUI

// Compare direct native TLS sockets (which pf must carry) with URLSession using
// the existing system proxy settings. Never change the machine's proxy settings.
struct ProbeResult: Codable {
    let stack: String
    let url: String
    let pid: Int32
    let status: Int?
    let bytes: Int
    let milliseconds: Int
    let error: String?
    let networkProtocol: String?
    let usedExplicitProxy: Bool?
    let remoteAddress: String?
    var id: String { stack + url }
}

final class DirectTLSProbe: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.procsocks.native-test")
    private let target: String
    private let connection: NWConnection
    private let start = Date()
    private var response = HTTPResponseAccumulator()
    private var usedProxy: Bool?
    private var address: String?
    private var completion: ((ProbeResult) -> Void)?

    init(_ target: String) {
        self.target = target
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.preferNoProxies = true
        connection = NWConnection(host: NWEndpoint.Host(URL(string: target)!.host!), port: 443, using: parameters)
    }

    func run(_ completion: @escaping (ProbeResult) -> Void) {
        queue.async { self.completion = completion }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.connection.requestEstablishmentReport(queue: self.queue) { report in
                    self.usedProxy = report?.usedProxy
                    self.address = report?.resolutions.last?.successfulEndpoint.debugDescription
                }
                let host = URL(string: self.target)!.host!
                let request = "GET / HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
                self.connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
                    if let error { self.finish(error.debugDescription) }
                    else { self.receive() }
                })
            case .failed(let error): self.finish(error.debugDescription)
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 15) { self.finish("TCP/TLS request timed out after 15 seconds") }
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, complete, error in
            if let data { self.response.append(data) }
            if let error = self.response.error { self.finish(error) }
            else if self.response.isComplete { self.finish(nil) }
            else if let error { self.finish(error.debugDescription) }
            else if complete {
                self.response.finishAtEOF()
                self.finish(self.response.error)
            }
            else { self.receive() }
        }
    }

    private func finish(_ error: String?) {
        guard let callback = completion else { return }
        completion = nil
        callback(ProbeResult(stack: "Network.framework · prefer direct TLS", url: target, pid: getpid(), status: response.status,
                             bytes: response.data.count, milliseconds: Int(Date().timeIntervalSince(start) * 1000),
                             error: error ?? (response.isComplete ? nil : "No complete HTTP response received"),
                             networkProtocol: "http/1.1", usedExplicitProxy: usedProxy, remoteAddress: address))
        connection.cancel()
    }
}

final class DirectUDPProbe: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.procsocks.udp-test")
    private let target: String
    private let connection: NWConnection
    private let start = Date()
    private let identifier = UInt16.random(in: 1...UInt16.max)
    private var completion: ((ProbeResult) -> Void)?

    init(_ target: String) {
        self.target = target
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        connection = NWConnection(host: NWEndpoint.Host(target), port: 53, using: parameters)
    }

    func run(_ completion: @escaping (ProbeResult) -> Void) {
        queue.async { self.completion = completion }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                var query = Data([UInt8(self.identifier >> 8), UInt8(self.identifier & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                query.append(contentsOf: [7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1])
                self.connection.send(content: query, completion: .contentProcessed { error in
                    if let error { self.finish(error.debugDescription) }
                    else {
                        self.connection.receiveMessage { data, _, _, error in
                            if let error { self.finish(error.debugDescription); return }
                            guard let data, data.count >= 12,
                                  data[0] == UInt8(self.identifier >> 8), data[1] == UInt8(self.identifier & 255),
                                  data[2] & 0x80 != 0, data[3] & 15 == 0 else {
                                self.finish("UDP DNS 返回数据不正确"); return
                            }
                            self.finish(nil, bytes: data.count)
                        }
                    }
                })
            case .failed(let error): self.finish(error.debugDescription)
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 10) { self.finish("UDP 请求超时；IPv6 还需要上游支持 IPv6 UDP") }
    }

    private func finish(_ error: String?, bytes: Int = 0) {
        guard let callback = completion else { return }
        completion = nil
        callback(ProbeResult(stack: "Network.framework · direct UDP socket", url: "udp://\(target):53 · example.com DNS", pid: getpid(),
                             status: nil, bytes: bytes, milliseconds: Int(Date().timeIntervalSince(start) * 1000), error: error,
                             networkProtocol: "udp", usedExplicitProxy: false, remoteAddress: target))
        connection.cancel()
    }
}

final class Metrics: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var collected: URLSessionTaskMetrics?

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        lock.lock(); collected = metrics; lock.unlock()
    }

    func lastTransaction() -> URLSessionTaskTransactionMetrics? {
        lock.lock(); defer { lock.unlock() }
        return collected?.transactionMetrics.last
    }
}

@MainActor
final class NetworkTester: ObservableObject {
    @Published var results: [ProbeResult] = []
    @Published var running = false
    @Published var reportError: String?
    let targets = ["https://example.com/", "https://www.apple.com/", "https://chatgpt.com/",
                   "https://codex-cloud-backend.chatgpt.com/", "https://ab.chatgpt.com/"]

    func run(report: URL? = nil, finished: (() -> Void)? = nil) {
        guard !running else { return }
        running = true; results = []; reportError = nil
        Task {
            await withTaskGroup(of: ProbeResult.self) { group in
                for target in targets {
                    group.addTask { await Self.fetch(target) }
                    group.addTask {
                        let probe = DirectTLSProbe(target)
                        return await withCheckedContinuation { continuation in
                            probe.run { result in continuation.resume(returning: result) }
                        }
                    }
                }
                for target in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
                    group.addTask {
                        let probe = DirectUDPProbe(target)
                        return await withCheckedContinuation { continuation in
                            probe.run { result in continuation.resume(returning: result) }
                        }
                    }
                }
                for await result in group { results.append(result) }
            }
            results.sort { ($0.stack, $0.url) < ($1.stack, $1.url) }
            if let report {
                do {
                    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                    try encoder.encode(results).write(to: report, options: .atomic)
                } catch { reportError = error.localizedDescription }
            }
            running = false
            finished?()
        }
    }

    nonisolated private static func fetch(_ target: String) async -> ProbeResult {
        let settings = URLSessionConfiguration.ephemeral
        settings.timeoutIntervalForRequest = 12
        settings.timeoutIntervalForResource = 15
        settings.requestCachePolicy = .reloadIgnoringLocalCacheData
        let metrics = Metrics()
        let session = URLSession(configuration: settings, delegate: metrics, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let start = Date()
        var responseStatus: Int?; var count = 0; var failure: String?
        do {
            let (data, response) = try await session.data(from: URL(string: target)!)
            responseStatus = (response as? HTTPURLResponse)?.statusCode; count = data.count
        } catch {
            let value = error as NSError
            failure = "\(value.domain) \(value.code): \(value.localizedDescription)"
        }
        let transaction = metrics.lastTransaction()
        return ProbeResult(stack: "URLSession · system proxy", url: target, pid: getpid(), status: responseStatus, bytes: count,
                           milliseconds: Int(Date().timeIntervalSince(start) * 1000), error: failure,
                           networkProtocol: transaction?.networkProtocolName,
                           usedExplicitProxy: transaction?.isProxyConnection,
                           remoteAddress: transaction?.remoteAddress)
    }
}

struct TestView: View {
    @ObservedObject var tester: NetworkTester
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("原生网络测试").font(.largeTitle.bold())
            Text("先在 ProcSocks 中勾选 ProcSocks Network Test，再启用代理并运行测试。")
            Text("分别测试直接 TCP/TLS、IPv4 / IPv6 UDP 与 URLSession 请求，并显示是否使用了系统代理。403 或 404 表示已收到网站响应；超时或 TLS 错误才是连接失败。")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Button(tester.running ? "正在测试…" : "运行网络测试") { tester.run() }
                    .buttonStyle(.borderedProminent).disabled(tester.running)
                if tester.running { ProgressView().controlSize(.small) }
                Spacer()
                Text("PID \(getpid())").font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(tester.results, id: \.id) { result in
                        VStack(alignment: .leading, spacing: 5) {
                            Text(result.url).font(.headline)
                            Text(result.stack).font(.caption).foregroundStyle(.secondary)
                            if let error = result.error { Text(error).foregroundStyle(.red) }
                            else { Text("\(result.networkProtocol == "udp" ? "UDP 往返成功" : "HTTP \(result.status ?? 0)") · \(result.bytes) 字节 · \(result.milliseconds) ms").foregroundStyle(.green) }
                            Text("协议 \(result.networkProtocol ?? "未知") · 显式代理 \(result.usedExplicitProxy.map { $0 ? "是" : "否" } ?? "未知") · 地址 \(result.remoteAddress ?? "未知")")
                                .font(.caption.monospaced()).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        Divider()
                    }
                }.textSelection(.enabled)
            }
            if let error = tester.reportError { Text(error).foregroundStyle(.red) }
        }.padding(28).frame(minWidth: 720, minHeight: 580)
    }
}

@main
enum NetworkTestApp {
    @MainActor static func main() {
        let application = NSApplication.shared
        let tester = NetworkTester()
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "--report"), arguments.count > index + 1 {
            application.setActivationPolicy(.prohibited)
            tester.run(report: URL(fileURLWithPath: arguments[index + 1])) { application.terminate(nil) }
            application.run()
        } else {
            application.setActivationPolicy(.regular)
            let window = NSWindow(contentViewController: NSHostingController(rootView: TestView(tester: tester)))
            window.title = "ProcSocks Network Test"
            window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            window.setContentSize(NSSize(width: 780, height: 660)); window.center()
            window.isReleasedWhenClosed = false
            let menu = NSMenu(); let appMenu = NSMenu(); let item = NSMenuItem(); item.submenu = appMenu
            menu.addItem(item)
            appMenu.addItem(withTitle: "退出网络测试", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
            application.mainMenu = menu
            window.makeKeyAndOrderFront(nil); application.activate(ignoringOtherApps: true)
            application.run()
            withExtendedLifetime(window) {}
        }
        withExtendedLifetime(tester) {}
    }
}
