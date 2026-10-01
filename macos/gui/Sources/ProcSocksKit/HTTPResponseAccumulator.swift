import Foundation

/// Bounded HTTP/1 response framing for the native HTTPS diagnostic (GET only).
/// A framed response completes without waiting for the server to close TLS.
public struct HTTPResponseAccumulator {
    public private(set) var data = Data()
    public private(set) var status: Int?
    public private(set) var isComplete = false
    public private(set) var error: String?
    private let limit: Int
    private let separator = Data("\r\n\r\n".utf8)
    private let lineEnd = Data("\r\n".utf8)

    public init(limit: Int = 2 * 1024 * 1024) { self.limit = limit }

    public mutating func append(_ bytes: Data) {
        guard !isComplete, error == nil else { return }
        guard bytes.count <= limit - data.count else {
            error = "Response exceeded test size limit"; return
        }
        data.append(bytes)
        parse(eof: false)
    }

    public mutating func finishAtEOF() {
        guard !isComplete, error == nil else { return }
        parse(eof: true)
        if !isComplete, error == nil { error = "HTTP response ended before the complete message was received" }
    }

    private mutating func parse(eof: Bool) {
        var start = 0
        while true {
            guard let end = data.range(of: separator, in: start..<data.count) else {
                if data.count - start > 64 * 1024 { error = "HTTP headers exceeded test size limit" }
                return
            }
            guard end.lowerBound - start <= 64 * 1024,
                  let header = String(data: data[start..<end.lowerBound], encoding: .isoLatin1) else {
                error = "Invalid HTTP response headers"; return
            }
            let lines = header.components(separatedBy: "\r\n")
            let fields = (lines.first ?? "").split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(fields[0])),
                  let code = Int(fields[1]), (100...599).contains(code) else {
                error = "Invalid HTTP status line"; return
            }
            if (100..<200).contains(code) {
                guard code != 101 else { error = "HTTP protocol upgrades are unsupported by this diagnostic"; return }
                start = end.upperBound
                continue
            }
            status = code
            if code == 204 || code == 304 { isComplete = true; return }
            var headers: [String: [String]] = [:]
            for line in lines.dropFirst() {
                guard let colon = line.firstIndex(of: ":") else { error = "Invalid HTTP header"; return }
                let key = String(line[..<colon]).lowercased()
                let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                headers[key, default: []].append(value)
            }
            let body = end.upperBound
            if let encodings = headers["transfer-encoding"] {
                let tokens = encodings.flatMap { $0.lowercased().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
                guard tokens.last == "chunked" else { error = "Unsupported HTTP transfer encoding"; return }
                parseChunks(from: body)
            } else if let values = headers["content-length"] {
                let lengths = values.flatMap { $0.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) } }
                guard let first = lengths.first, !first.isEmpty, first.allSatisfy({ $0.isASCII && $0.isNumber }),
                      let count = Int(first), lengths.allSatisfy({ $0 == first }), count <= limit else {
                    error = "Invalid HTTP Content-Length"; return
                }
                isComplete = data.count - body >= count
            } else { isComplete = eof }
            return
        }
    }

    private mutating func parseChunks(from body: Int) {
        var cursor = body
        while cursor < data.count {
            guard let end = data.range(of: lineEnd, in: cursor..<data.count) else { return }
            let line = String(decoding: data[cursor..<end.lowerBound], as: UTF8.self)
            let size = line.split(separator: ";", omittingEmptySubsequences: false).first.map(String.init) ?? ""
            guard !size.isEmpty, size.allSatisfy({ $0.isASCII && $0.isHexDigit }), let count = Int(size, radix: 16), count <= limit else {
                error = "Invalid HTTP chunk size"; return
            }
            cursor = end.upperBound
            if count == 0 {
                if data.count - cursor >= 2, data[cursor..<(cursor + 2)] == lineEnd { isComplete = true }
                else if data.range(of: separator, in: cursor..<data.count) != nil { isComplete = true }
                return
            }
            guard data.count - cursor >= count + 2 else { return }
            guard data[(cursor + count)..<(cursor + count + 2)] == lineEnd else {
                error = "Invalid HTTP chunk terminator"; return
            }
            cursor += count + 2
        }
    }
}
