import AppKit
import ProcSocksKit
import SwiftUI

@MainActor
struct StatusPopover: View {
    @ObservedObject var model: AppController
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 10) {
                Image(systemName: "arrow.triangle.branch").font(.system(size: 25)).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text("ProcSocks").font(.system(size: 18, weight: .semibold))
                    Text("按进程 TCP / UDP 代理").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
            }
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 7) {
                    Circle().fill(model.status.running ? Color.green : Color.secondary).frame(width: 7, height: 7)
                    Text(model.statusTitle).font(.headline)
                    Spacer()
                }
                Text("\(model.targetCount) 项进程选择 · \(model.advancedCount) 条高级规则").font(.caption).foregroundStyle(.secondary)
                Text("SOCKS5  \(model.configuration.host):\(model.configuration.port)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                TrafficQuickStatus(traffic: model.traffic)
                if model.dirty { Label("有未保存的修改", systemImage: "circle.fill").font(.caption).foregroundStyle(.orange) }
            }
            .padding(14).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))

            Button {
                if model.status.loaded { model.stop() } else { model.save(start: true) }
            } label: {
                Label(model.status.loaded ? "停止代理" : "启用代理", systemImage: model.status.loaded ? "stop.fill" : "play.fill")
                    .frame(maxWidth: .infinity).padding(.vertical, 5)
            }.buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy)

            if let error = model.error {
                Label(error, systemImage: "exclamationmark.circle.fill").font(.caption).foregroundStyle(.red).lineLimit(4)
            } else if let notice = model.notice {
                Text(notice).font(.caption).foregroundStyle(.secondary).lineLimit(3)
            }
            VStack(spacing: 1) {
                navigation("选择应用与进程", symbol: "square.stack.3d.up", page: .processes)
                navigation("代理服务器", symbol: "network", page: .connection)
                navigation("实时流量图表", symbol: "chart.xyaxis.line", page: .traffic)
                navigation("高级规则与日志", symbol: "slider.horizontal.3", page: .advanced)
            }
            Divider()
            HStack {
                Text("TCP\(model.configuration.redirectUDP ? " / UDP" : "") · IPv4\(model.configuration.redirectIPv6 ? " / IPv6" : "")").font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Button("退出") { model.requestQuit?() }.buttonStyle(.plain).font(.caption).disabled(model.busy)
            }
        }
        .padding(20).frame(width: 340)
    }
    private func navigation(_ title: String, symbol: String, page: SettingsPage) -> some View {
        Button { model.showSettings?(page) } label: {
            HStack {
                Label(title, systemImage: symbol)
                Spacer()
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }.padding(.vertical, 7).contentShape(Rectangle())
        }.buttonStyle(.plain)
    }
}

@MainActor
struct SettingsView: View {
    @ObservedObject var model: AppController
    @State private var showPreview = false
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Label("ProcSocks", systemImage: "arrow.triangle.branch").font(.system(size: 20, weight: .semibold)).padding(.bottom, 24)
                ForEach(SettingsPage.allCases) { page in
                    Button { model.page = page } label: {
                        Label(page.rawValue, systemImage: page.symbol)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 12).padding(.vertical, 10)
                            .foregroundStyle(model.page == page ? Color.accentColor : Color.primary)
                            .background(model.page == page ? Color.accentColor.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain)
                }
                Spacer()
                VStack(alignment: .leading, spacing: 7) {
                    Label(model.status.running ? "代理运行中" : "代理已停止", systemImage: model.status.running ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(model.status.running ? .green : .secondary)
                    Text("\(model.targetCount) 项进程选择").foregroundStyle(.secondary)
                    if let pid = model.status.pid { Text("PID \(pid)").foregroundStyle(.tertiary) }
                }.font(.caption).padding(12)
            }.padding(20).frame(width: 180).background(.ultraThinMaterial)
            Divider()
            VStack(spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(model.page.rawValue).font(.system(size: 25, weight: .semibold))
                        Text(subtitle).font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.busy { ProgressView().controlSize(.small).help(model.operation) }
                    Button(model.status.loaded ? "停止代理" : "启用代理") {
                        if model.status.loaded { model.stop() } else { model.save(start: true) }
                    }.buttonStyle(.borderedProminent).disabled(model.busy)
                }.padding(24)

                if let error = model.error { message(error, error: true) }
                else if let notice = model.notice { message(notice, error: false) }

                Group {
                    switch model.page {
                    case .processes: processPage
                    case .connection: connectionPage
                    case .traffic: TrafficView(traffic: model.traffic, selections: model.configuration.selections, updateBackend: { model.save(start: true) })
                    case .advanced: advancedPage
                    case .logs: logsPage
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity).disabled(model.busy)

                Divider()
                HStack(spacing: 12) {
                    Menu {
                        Button("导入配置…", action: model.importConfiguration)
                        Button("导出配置…", action: model.exportConfiguration)
                        Button("查看最终配置") { showPreview = true }
                    } label: { Label("配置", systemImage: "ellipsis.circle") }.fixedSize().disabled(model.busy)
                    Text(model.busy ? model.operation : (model.dirty ? "有未保存的修改" : "配置已保存"))
                        .font(.caption).foregroundStyle(model.dirty ? .orange : .secondary)
                    Spacer()
                    Button("撤销修改", action: model.revert).disabled(!model.dirty || model.busy)
                    Button(model.status.running ? "保存并应用" : "保存配置") { model.save() }
                        .keyboardShortcut("s", modifiers: .command).buttonStyle(.borderedProminent).disabled(!model.dirty || model.busy)
                }.padding(.horizontal, 24).padding(.vertical, 15)
            }.background(Color(nsColor: .windowBackgroundColor))
        }
        .frame(minWidth: 840, minHeight: 620)
        .sheet(isPresented: $showPreview) {
            VStack(alignment: .leading, spacing: 16) {
                Text("最终生效配置").font(.title2.bold())
                Text("列表选择与高级规则已合并，密码已隐藏。").foregroundStyle(.secondary)
                ScrollView {
                    Text(preview).font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }.padding(14).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                HStack { Spacer(); Button("完成") { showPreview = false }.keyboardShortcut(.defaultAction) }
            }.padding(24).frame(width: 660, height: 520)
        }
    }

    private var subtitle: String {
        switch model.page {
        case .processes: return "勾选需要代理的项目，其他进程继续直连。"
        case .connection: return "连接你已有的 SOCKS5 代理服务器。"
        case .traffic: return "按进程观察上传、下载速度和累计流量。"
        case .advanced: return "高级正则继续生效，与列表选择自动合并。"
        case .logs: return "查看实际发起连接的进程和路由结果。"
        }
    }

    private var preview: String {
        guard let data = try? model.configuration.encoded(redactPassword: true) else { return "请先修正输入后查看。" }
        return String(decoding: data, as: UTF8.self)
    }

    private func message(_ text: String, error: Bool) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: error ? "exclamationmark.circle.fill" : "checkmark.circle.fill").foregroundStyle(error ? Color.red : Color.accentColor)
            Text(text).font(.callout).textSelection(.enabled).lineLimit(5)
                .frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            Button { model.error = nil; model.notice = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).foregroundStyle(.secondary)
        }.padding(12).background((error ? Color.red : Color.accentColor).opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
        .padding(.horizontal, 24).padding(.bottom, 12)
    }

    private var processPage: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Picker("列表类型", selection: $model.showExecutables) {
                    Text("应用").tag(false)
                    Text("全部进程").tag(true)
                }.pickerStyle(.segmented).labelsHidden().frame(width: 170)
                TextField("搜索名称或路径", text: $model.search).textFieldStyle(.roundedBorder)
                Button { Task { await model.refresh() } } label: { Image(systemName: "arrow.clockwise") }.help("刷新进程列表")
                Button("添加…", action: model.addFile)
            }
            if model.rows.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "magnifyingglass").font(.system(size: 30)).foregroundStyle(.tertiary)
                    Text("没有匹配的项目").foregroundStyle(.secondary)
                    Text("清空搜索，或点击“添加…”选择应用与可执行文件。").font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.rows) { row in
                    HStack(spacing: 12) {
                        Toggle("代理 \(row.target.name)", isOn: Binding(
                            get: { model.selected(row.target) },
                            set: { model.setSelected(row.target, enabled: $0) }
                        )).toggleStyle(.checkbox).labelsHidden().accessibilityLabel("代理 \(row.target.name)")
                        Image(nsImage: Icons.image(for: row.target.path)).resizable().frame(width: 32, height: 32)
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 7) {
                                Text(row.target.name).fontWeight(.medium)
                                if model.coveredByApplication(row.target) {
                                    Text("应用已覆盖").font(.caption2).foregroundStyle(.tint)
                                }
                            }
                            Text(row.target.path).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer(minLength: 5)
                        VStack(alignment: .trailing, spacing: 4) {
                            Text(row.running ? (row.target.kind == .application ? "\(row.pids.count) 个进程" : "运行中") : "未运行")
                                .font(.caption).foregroundStyle(row.running ? .green : .secondary)
                            if model.showExecutables && row.running {
                                Text(row.pids.map(String.init).joined(separator: ", ")).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                            }
                        }.frame(width: 90, alignment: .trailing)
                    }.padding(.vertical, 7).help(row.target.path)
                }.listStyle(.inset).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            }
            HStack(alignment: .top, spacing: 7) {
                Image(systemName: "info.circle")
                Text(model.showExecutables ? "按可执行路径保存选择，重启进程后仍然生效。root 进程不在此列表中。" : "选择应用会包含应用包内的辅助进程，也可提前选择尚未运行的应用。")
            }.font(.caption).foregroundStyle(.secondary)
            if model.advancedCount > 0 {
                Button("另有 \(model.advancedCount) 条高级代理规则正在参与匹配 →") { model.page = .advanced }.buttonStyle(.plain).font(.caption).foregroundStyle(.tint)
            }
        }.padding(.horizontal, 24).padding(.bottom, 20)
    }

    private var connectionPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                card("SOCKS5 服务器", symbol: "network") {
                    HStack(spacing: 16) {
                        field("服务器地址", text: $model.configuration.host, placeholder: "127.0.0.1")
                        field("端口", text: $model.configuration.port, placeholder: "7890").frame(width: 110)
                    }
                    Toggle("服务器需要用户名和密码", isOn: $model.configuration.authentication)
                    if model.configuration.authentication {
                        HStack(spacing: 16) {
                            field("用户名", text: $model.configuration.username, placeholder: "用户名")
                            VStack(alignment: .leading, spacing: 6) {
                                Text("密码").font(.caption).foregroundStyle(.secondary)
                                SecureField("密码", text: $model.configuration.password).textFieldStyle(.roundedBorder)
                            }
                        }
                    }
                    HStack {
                        Text("本机代理通常是 127.0.0.1，端口以代理客户端为准。").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("测试上游", action: model.testUpstream)
                    }
                }
                card("本地监听", symbol: "point.3.connected.trianglepath.dotted") {
                    field("监听端口", text: $model.configuration.listenPort, placeholder: "7891").frame(width: 150)
                    Toggle("代理 UDP（含 QUIC）", isOn: $model.configuration.redirectUDP)
                    Text("上游必须支持 SOCKS5 UDP。启用时若上游拒绝 UDP，后台启动会失败，已接管的数据不会自动改为直连。").font(.caption).foregroundStyle(.secondary)
                    Toggle("同时代理 IPv6", isOn: $model.configuration.redirectIPv6)
                    Text("监听地址保持在本机回环网络。关闭 IPv6 后，IPv6 请求将走系统直连。").font(.caption).foregroundStyle(.secondary)
                }
                card("启动选项", symbol: "power") {
                    Toggle("开机自动启用代理", isOn: $model.configuration.autostart)
                    Toggle("登录时打开菜单栏应用", isOn: Binding(get: { model.loginEnabled }, set: { model.setLoginEnabled($0) }))
                    Text("开机代理与菜单栏独立运行；设置开机代理后，手动停止仍会在下次开机重新启用。").font(.caption).foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 24).padding(.bottom, 24)
        }
    }

    private var advancedPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                card("额外代理规则", symbol: "curlybraces") {
                    Text("一行一条正则，匹配完整可执行路径。列表勾选生成的规则会自动合并。").font(.caption).foregroundStyle(.secondary)
                    editor($model.configuration.advancedProcessRules).accessibilityLabel("高级代理规则")
                }
                card("直接绕过规则", symbol: "arrow.turn.up.right") {
                    Text("一行一条正则，优先于所有代理规则。未命中代理规则的进程也会直连。").font(.caption).foregroundStyle(.secondary)
                    editor($model.configuration.bypassRules).accessibilityLabel("高级绕过规则")
                }
                card("连接选项", symbol: "slider.horizontal.3") {
                    Picker("接管端口", selection: Binding(
                        get: { ["all", "80,443"].contains(model.configuration.redirectPorts) ? model.configuration.redirectPorts : "custom" },
                        set: { model.configuration.redirectPorts = $0 == "custom" ? "80,443,8080" : $0 }
                    )) {
                        Text("所有 TCP / UDP 端口").tag("all")
                        Text("仅 80 / 443").tag("80,443")
                        Text("自定义").tag("custom")
                    }
                    if !["all", "80,443"].contains(model.configuration.redirectPorts) {
                        field("目标端口，以逗号分隔", text: $model.configuration.redirectPorts, placeholder: "80,443,8080")
                    }
                    Toggle("TCP 要求恢复域名（TLS SNI / HTTP Host）", isOn: $model.configuration.requireHostname)
                    Text("此选项仅作用于 TCP。UDP 按原始目标 IP 转发，不做 TLS SNI 嗅探。").font(.caption).foregroundStyle(.secondary)
                    HStack(spacing: 16) {
                        field("连接超时（毫秒）", text: $model.configuration.connectTimeout, placeholder: "15000")
                        field("嗅探超时（毫秒）", text: $model.configuration.sniffTimeout, placeholder: "2000")
                        field("最大嗅探字节", text: $model.configuration.maxSniffBytes, placeholder: "65536")
                    }
                }
            }.padding(.horizontal, 24).padding(.bottom, 24)
        }
    }

    private var logsPage: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("后台连接日志", systemImage: "doc.text").font(.headline)
                Spacer()
                Button("刷新", action: model.readLog)
                Button("在 Finder 中显示") { NSWorkspace.shared.activateFileViewerSelecting([model.logURL]) }
            }
            ScrollView([.vertical, .horizontal]) {
                Text(model.logText).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .topLeading).padding(14)
            }.background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            Text("executable 是实际发起连接的程序；decision=proxy 表示走上游，direct 表示直连。").font(.caption).foregroundStyle(.secondary)
        }.padding(.horizontal, 24).padding(.bottom, 20)
    }

    private func field(_ title: String, text: Binding<String>, placeholder: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            TextField(placeholder, text: text).textFieldStyle(.roundedBorder).accessibilityLabel(title)
        }
    }

    private func editor(_ binding: Binding<String>) -> some View {
        TextEditor(text: binding).font(.system(size: 12, design: .monospaced)).scrollContentBackground(.hidden)
            .padding(6).frame(height: 105).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.secondary.opacity(0.15)))
    }

    private func card<Content: View>(_ title: String, symbol: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: symbol).font(.headline)
            content()
        }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }
}

@MainActor
private enum Icons {
    static var cache: [String: NSImage] = [:]
    static func image(for path: String) -> NSImage {
        if let image = cache[path] { return image }
        let image = NSWorkspace.shared.icon(forFile: path)
        cache[path] = image
        return image
    }
}
