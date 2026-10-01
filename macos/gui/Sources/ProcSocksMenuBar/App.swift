import AppKit
import Combine
import SwiftUI

@main
enum ProcSocksMenuBar {
    @MainActor static func main() {
        let application = NSApplication.shared
        let delegate = AppDelegate()
        application.delegate = delegate
        application.setActivationPolicy(.accessory)
        application.run()
        withExtendedLifetime(delegate) {}
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var model: AppController!
    private var item: NSStatusItem!
    private let popover = NSPopover()
    private var window: NSWindow?
    private var observation: AnyCancellable?

    func applicationDidFinishLaunching(_ notification: Notification) {
        model = AppController()
        model.showSettings = { [weak self] page in self?.openSettings(page) }
        model.requestQuit = { [weak self] in self?.quit() }
        // Seed AppKit's autosaved position once, near the system controls. Its
        // default leftmost placement can disappear behind a MacBook's notch.
        // Preserve subsequent positions chosen by the user with Command-drag.
        let positionKey = "NSStatusItem Preferred Position ProcSocksStatus"
        if UserDefaults.standard.object(forKey: positionKey) == nil {
            UserDefaults.standard.set(220, forKey: positionKey)
        }
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.autosaveName = "ProcSocksStatus"
        item.isVisible = true
        if let button = item.button {
            let symbol = NSImage(systemSymbolName: "arrow.triangle.branch", accessibilityDescription: "ProcSocks")?
                .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 16, weight: .semibold))
            symbol?.isTemplate = true
            button.image = symbol
            button.imagePosition = .imageOnly
            button.title = ""
            button.setAccessibilityLabel("ProcSocks 菜单栏")
            button.target = self
            button.action = #selector(togglePopover)
            button.toolTip = "ProcSocks · 代理已停止"
        }
        popover.behavior = .transient
        popover.animates = true
        popover.contentViewController = NSHostingController(rootView: StatusPopover(model: model))
        observation = model.$status.sink { [weak self] status in
            self?.item.button?.toolTip = "ProcSocks · \(status.running ? "代理运行中" : "代理已停止")"
            self?.recordMenuBarDiagnostics()
        }
        installMenu()
        let firstLaunch = !UserDefaults.standard.bool(forKey: "hasShownWelcome")
        if firstLaunch || ProcessInfo.processInfo.arguments.contains("--show-settings") || model.error != nil {
            openSettings(.processes)
            UserDefaults.standard.set(true, forKey: "hasShownWelcome")
        }
        DispatchQueue.main.async { [weak self] in self?.recordMenuBarDiagnostics() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) { model?.traffic.stop() }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openSettings(model.page)
        return true
    }

    @objc private func togglePopover() {
        guard let button = item.button else { return }
        if popover.isShown { popover.performClose(nil) }
        else {
            NSApp.activate(ignoringOtherApps: true)
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
        recordMenuBarDiagnostics()
    }

    private func recordMenuBarDiagnostics() {
        guard ProcessInfo.processInfo.arguments.contains("--diagnose-menu-bar") else { return }
        let data: [String: Any] = [
            "visible": item.isVisible, "length": item.length,
            "buttonTitle": item.button?.title ?? "", "buttonBounds": NSStringFromRect(item.button?.bounds ?? .zero),
            "buttonHasImage": item.button?.image != nil, "buttonImageIsTemplate": item.button?.image?.isTemplate ?? false,
            "windowVisible": item.button?.window?.isVisible ?? false,
            "windowFrame": NSStringFromRect(item.button?.window?.frame ?? .zero),
            "popoverShown": popover.isShown,
            "trafficSampleCount": model.traffic.tracker.points.count,
            "trafficSampleTimes": model.traffic.tracker.points.suffix(5).map { $0.date.timeIntervalSince1970 },
            "screens": NSScreen.screens.map { ["frame": NSStringFromRect($0.frame), "visibleFrame": NSStringFromRect($0.visibleFrame),
                                               "leftMenuBarArea": NSStringFromRect($0.auxiliaryTopLeftArea ?? .zero),
                                               "rightMenuBarArea": NSStringFromRect($0.auxiliaryTopRightArea ?? .zero),
                                               "safeAreaTop": $0.safeAreaInsets.top] }
        ]
        if let encoded = try? JSONSerialization.data(withJSONObject: data, options: [.prettyPrinted, .sortedKeys]) {
            let path = model.directory.appendingPathComponent("menu-bar-diagnostics.json")
            try? encoded.write(to: path, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        }
    }

    private func openSettings(_ page: SettingsPage) {
        model.page = page
        popover.performClose(nil)
        if window == nil {
            let controller = NSHostingController(rootView: SettingsView(model: model))
            let created = NSWindow(contentViewController: controller)
            created.title = "ProcSocks"
            created.setContentSize(NSSize(width: 960, height: 720))
            created.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            created.minSize = NSSize(width: 850, height: 650)
            created.isReleasedWhenClosed = false
            created.center()
            window = created
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    @objc private func preferences() { openSettings(.processes) }

    @objc private func quit() {
        guard !model.busy else { return }
        if !model.status.loaded { NSApp.terminate(nil); return }
        popover.performClose(nil)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "退出 ProcSocks"
        alert.informativeText = "代理正在后台运行。你可以停止代理后退出，也可以只关闭菜单栏界面。"
        alert.addButton(withTitle: "停止代理并退出")
        alert.addButton(withTitle: "仅退出菜单栏")
        alert.addButton(withTitle: "取消")
        switch alert.runModal() {
        case .alertFirstButtonReturn: model.stop { NSApp.terminate(nil) }
        case .alertSecondButtonReturn: NSApp.terminate(nil)
        default: break
        }
    }

    private func installMenu() {
        let main = NSMenu()
        let app = NSMenu()
        let appItem = NSMenuItem()
        appItem.submenu = app
        main.addItem(appItem)
        let about = app.addItem(withTitle: "关于 ProcSocks", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        about.target = NSApp
        app.addItem(.separator())
        let settings = app.addItem(withTitle: "ProcSocks 设置…", action: #selector(preferences), keyEquivalent: ",")
        settings.target = self
        let panel = app.addItem(withTitle: "打开菜单栏面板", action: #selector(togglePopover), keyEquivalent: "p")
        panel.keyEquivalentModifierMask = [.command, .shift]
        panel.target = self
        app.addItem(.separator())
        let exit = app.addItem(withTitle: "退出 ProcSocks", action: #selector(quit), keyEquivalent: "q")
        exit.target = self
        let editItem = NSMenuItem(title: "编辑", action: nil, keyEquivalent: "")
        let edit = NSMenu(title: "编辑")
        for (title, selector, key) in [("撤销", "undo:", "z"), ("剪切", "cut:", "x"), ("复制", "copy:", "c"), ("粘贴", "paste:", "v"), ("全选", "selectAll:", "a")] {
            edit.addItem(withTitle: title, action: Selector(selector), keyEquivalent: key)
        }
        editItem.submenu = edit
        main.addItem(editItem)
        NSApp.mainMenu = main
    }
}
