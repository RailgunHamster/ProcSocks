import Foundation

public struct CommandResult {
    public var status: Int32
    public var output: String
}

public enum CoreCommands {
    public static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    public static func run(executable: URL, arguments: [String]) async throws -> CommandResult {
        try await Task.detached(priority: .userInitiated) {
            try execute(executable: executable, arguments: arguments)
        }.value
    }

    public static func privileged(executable: URL, arguments: [String]) async throws -> CommandResult {
        let command = ([executable.path] + arguments).map(shellQuote).joined(separator: " ")
        // Preserve Unicode and the core's exit status through AppleScript, which
        // otherwise loses stdout when an administrator command fails.
        let shell = "(\(command); procsocks_result=$?; /usr/bin/printf '\\n__PROCSOCKS_STATUS__=%d\\n' \"$procsocks_result\") 2>&1 | /usr/bin/base64"
        let literal = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(literal)\" with administrator privileges"
        let result = try await run(executable: URL(fileURLWithPath: "/usr/bin/osascript"), arguments: ["-e", script])
        guard result.status == 0 else {
            if result.output.contains("(-128)") { throw ConfigurationError("已取消管理员认证，代理设置未应用。") }
            throw ConfigurationError(result.output.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        guard let data = Data(base64Encoded: result.output, options: .ignoreUnknownCharacters),
              let decoded = String(data: data, encoding: .utf8),
              let range = decoded.range(of: "\n__PROCSOCKS_STATUS__=", options: .backwards),
              let status = Int32(decoded[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw ConfigurationError("系统认证未返回有效的执行结果，请重试。")
        }
        return CommandResult(status: status, output: String(decoded[..<range.lowerBound]))
    }

    private static func execute(executable: URL, arguments: [String]) throws -> CommandResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        environment["RUST_LOG"] = ""
        process.environment = environment
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
    }
}
