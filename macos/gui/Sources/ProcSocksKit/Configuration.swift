import Foundation

public enum SelectionKind: String, Codable {
    case application, executable
}

public struct ProcessSelection: Codable, Hashable, Identifiable {
    public var kind: SelectionKind
    public var path: String
    public var name: String
    // Retain a migrated literal-path rule's original semantics until deselected.
    public var importedPattern: String?
    public var id: String { "\(kind.rawValue):\(path)" }

    public init(kind: SelectionKind, path: String, name: String, importedPattern: String? = nil) {
        self.kind = kind
        self.path = path
        self.name = name
        self.importedPattern = importedPattern
    }

    public var pattern: String {
        if let importedPattern { return importedPattern }
        let escaped = Self.escapeRegex(path)
        return kind == .application ? "^\(escaped)/" : "^\(escaped)$"
    }

    public static func escapeRegex(_ text: String) -> String {
        let special = Set("\\.+*?()|[]{}^$".unicodeScalars)
        return text.unicodeScalars.map { special.contains($0) ? "\\\($0)" : String($0) }.joined()
    }

    public static func applicationPath(for executable: String) -> String? {
        guard let range = executable.range(of: ".app/", options: .caseInsensitive) else { return nil }
        return String(executable[..<executable.index(range.lowerBound, offsetBy: 4)])
    }
}

private struct MenuBarMetadata: Codable {
    var version: Int = 1
    var selections: [ProcessSelection]
    var advancedProcessPatterns: [String]
    var autostart: Bool
}

public struct UserConfiguration {
    private var original: [String: Any]
    public var host: String
    public var port: String
    public var authentication: Bool
    public var username: String
    public var password: String
    public var listenHost: String
    public var listenPort: String
    public var redirectPorts: String
    public var redirectIPv6: Bool
    public var requireHostname: Bool
    public var connectTimeout: String
    public var sniffTimeout: String
    public var maxSniffBytes: String
    public var selections: [ProcessSelection]
    public var advancedProcessRules: String
    public var bypassRules: String
    public var autostart: Bool

    public init(data: Data) throws {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let upstream = object["upstream"] as? [String: Any] else {
            throw ConfigurationError("配置需要一个 upstream 对象。")
        }
        original = object
        host = upstream["host"] as? String ?? "127.0.0.1"
        port = Self.number(upstream["port"], fallback: "7890")
        username = upstream["username"] as? String ?? ""
        password = upstream["password"] as? String ?? ""
        authentication = upstream["username"] is String || upstream["password"] is String
        let listen = object["listen"] as? String ?? "127.0.0.1:7891"
        if let colon = listen.lastIndex(of: ":") {
            listenHost = String(listen[..<colon])
            listenPort = String(listen[listen.index(after: colon)...])
        } else {
            listenHost = "127.0.0.1"
            listenPort = "7891"
        }
        redirectPorts = object["redirectPorts"] as? String ?? "all"
        redirectIPv6 = object["redirectIpv6"] as? Bool ?? true
        requireHostname = object["requireHostname"] as? Bool ?? true
        connectTimeout = Self.number(object["connectTimeoutMs"], fallback: "15000")
        sniffTimeout = Self.number(object["sniffTimeoutMs"], fallback: "2000")
        maxSniffBytes = Self.number(object["maxSniffBytes"], fallback: "65536")
        bypassRules = (object["bypassPatterns"] as? [String] ?? ["(^|/)procsocks$", "^/usr/bin/ssh$", "^/usr/sbin/sshd$"]).joined(separator: "\n")
        selections = []
        autostart = false
        let patterns = object["processPatterns"] as? [String] ?? []
        if let metadataObject = object["_menuBar"] {
            let metadataData = try JSONSerialization.data(withJSONObject: metadataObject)
            let metadata = try JSONDecoder().decode(MenuBarMetadata.self, from: metadataData)
            guard metadata.version == 1 else { throw ConfigurationError("此配置的菜单栏版本较新，请更新应用。") }
            let compiled = Set(patterns)
            selections = metadata.selections.filter { compiled.contains($0.pattern) }
            autostart = metadata.autostart
            // An externally edited compiled pattern must never silently disappear.
            let known = Set(selections.map(\.pattern) + metadata.advancedProcessPatterns)
            let extra = patterns.filter { !known.contains($0) }
            advancedProcessRules = (metadata.advancedProcessPatterns.filter { compiled.contains($0) } + extra).joined(separator: "\n")
        } else {
            var advanced: [String] = []
            for pattern in patterns {
                var directory: ObjCBool = false
                if pattern.hasPrefix("/"), FileManager.default.fileExists(atPath: pattern, isDirectory: &directory),
                   !directory.boolValue || pattern.lowercased().hasSuffix(".app") {
                    let kind: SelectionKind = directory.boolValue ? .application : .executable
                    let name = URL(fileURLWithPath: pattern).deletingPathExtension().lastPathComponent
                    selections.append(ProcessSelection(kind: kind, path: pattern, name: name, importedPattern: pattern))
                } else {
                    advanced.append(pattern)
                }
            }
            advancedProcessRules = advanced.joined(separator: "\n")
        }
        selections = selections.reduce(into: []) { result, selection in
            if !result.contains(where: { $0.id == selection.id }) { result.append(selection) }
        }
    }

    public static func empty() -> UserConfiguration {
        // This literal has no credentials and is shared by fresh profiles/tests.
        try! UserConfiguration(data: Data("{\"upstream\":{\"host\":\"127.0.0.1\",\"port\":7890},\"processPatterns\":[],\"redirectPorts\":\"all\"}".utf8))
    }

    public var compiledPatterns: [String] {
        var seen = Set<String>()
        return (selections.map(\.pattern) + Self.ruleLines(advancedProcessRules)).filter { seen.insert($0).inserted }
    }

    public func encoded(includeMetadata: Bool = true, redactPassword: Bool = false) throws -> Data {
        let upstreamPort = try Self.validPort(port, label: "上游端口")
        let localPort = try Self.validPort(listenPort, label: "监听端口")
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHost.isEmpty else { throw ConfigurationError("请填写 SOCKS5 服务器地址。") }
        if authentication && (username.isEmpty || password.isEmpty) {
            throw ConfigurationError("启用认证时，需要同时填写用户名和密码。")
        }
        var object = original
        var upstream = object["upstream"] as? [String: Any] ?? [:]
        upstream["host"] = trimmedHost
        upstream["port"] = upstreamPort
        upstream.removeValue(forKey: "username")
        upstream.removeValue(forKey: "password")
        if authentication {
            upstream["username"] = username
            upstream["password"] = redactPassword ? "••••••" : password
        }
        object["upstream"] = upstream
        object["listen"] = "\(listenHost):\(localPort)"
        object["processPatterns"] = compiledPatterns
        object["bypassPatterns"] = Self.ruleLines(bypassRules)
        object["redirectPorts"] = redirectPorts.trimmingCharacters(in: .whitespacesAndNewlines)
        object["redirectIpv6"] = redirectIPv6
        object["requireHostname"] = requireHostname
        object["connectTimeoutMs"] = try Self.positiveInteger(connectTimeout, label: "连接超时")
        object["sniffTimeoutMs"] = try Self.positiveInteger(sniffTimeout, label: "嗅探超时")
        object["maxSniffBytes"] = try Self.positiveInteger(maxSniffBytes, label: "嗅探字节数")
        object.removeValue(forKey: "_menuBar")
        if includeMetadata {
            let metadata = MenuBarMetadata(selections: selections, advancedProcessPatterns: Self.ruleLines(advancedProcessRules), autostart: autostart)
            object["_menuBar"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(metadata))
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }

    public static func ruleLines(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    private static func number(_ value: Any?, fallback: String) -> String {
        (value as? NSNumber)?.stringValue ?? fallback
    }

    private static func validPort(_ value: String, label: String) throws -> Int {
        guard let port = Int(value), (1...65535).contains(port) else { throw ConfigurationError("\(label)应为 1–65535。") }
        return port
    }

    private static func positiveInteger(_ value: String, label: String) throws -> Int {
        guard let number = Int(value), number > 0 else { throw ConfigurationError("\(label)应为正整数。") }
        return number
    }
}

public struct ConfigurationError: LocalizedError {
    public var message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public struct RunningProcess: Decodable {
    public var pid: Int
    public var uid: UInt32
    public var name: String
    public var executablePath: String
}

public struct BackendStatus: Decodable {
    public var installed: Bool
    public var loaded: Bool
    public var running: Bool
    public var autostart: Bool
    public var state: String
    public var pid: Int?
    public var lastExitCode: Int?
    public static let stopped = BackendStatus(installed: false, loaded: false, running: false, autostart: false, state: "stopped", pid: nil, lastExitCode: nil)
}
