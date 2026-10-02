import Foundation
import XCTest
@testable import ProcSocksKit

final class ConfigurationTests: XCTestCase {
    func testUDPDefaultsOnAndCanBeDisabledWithoutLosingAdvancedRules() throws {
        let data = Data(#"{"upstream":{"host":"127.0.0.1","port":7890},"processPatterns":["complex.*rule"],"custom":42}"#.utf8)
        var configuration = try UserConfiguration(data: data)
        XCTAssertTrue(configuration.redirectUDP)
        configuration.redirectUDP = false
        let encoded = try configuration.encoded()
        let restored = try UserConfiguration(data: encoded)
        XCTAssertFalse(restored.redirectUDP)
        XCTAssertEqual(restored.advancedProcessRules, "complex.*rule")
    }

    func testApplicationRuleIncludesHelpersAndEscapesRegexCharacters() throws {
        let target = ProcessSelection(kind: .application, path: "/Applications/Foo [Work]+.app", name: "Foo")
        let regex = try NSRegularExpression(pattern: target.pattern)
        let helper = "/Applications/Foo [Work]+.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
        XCTAssertNotNil(regex.firstMatch(in: helper, range: NSRange(helper.startIndex..., in: helper)))
        let other = "/Applications/Foo WWorkkXapp/Contents/MacOS/Foo"
        XCTAssertNil(regex.firstMatch(in: other, range: NSRange(other.startIndex..., in: other)))
        XCTAssertEqual(ProcessSelection.applicationPath(for: helper), target.path)
    }

    func testExecutableSelectionDoesNotMatchANeighboringName() throws {
        let target = ProcessSelection(kind: .executable, path: "/usr/bin/curl", name: "curl")
        let regex = try NSRegularExpression(pattern: target.pattern)
        let other = "/usr/bin/curl-extra"
        XCTAssertNil(regex.firstMatch(in: other, range: NSRange(other.startIndex..., in: other)))
    }

    func testExistingConfigurationRetainsComplexRulesUnknownFieldsAndCredentials() throws {
        let source = Data(#"{"upstream":{"host":"127.0.0.1","port":1080,"username":"名字","password":"p$a'ss","extension":true},"processPatterns":["(?i)ChatGPT|codex","^/opt/(foo|bar)$"],"bypassPatterns":["(?i)ssh"],"extension":{"enabled":true}}"#.utf8)
        let configuration = try UserConfiguration(data: source)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: configuration.encoded()) as? [String: Any])
        let upstream = try XCTUnwrap(object["upstream"] as? [String: Any])
        XCTAssertEqual(upstream["password"] as? String, "p$a'ss")
        XCTAssertEqual(upstream["extension"] as? Bool, true)
        XCTAssertEqual((object["extension"] as? [String: Any])?["enabled"] as? Bool, true)
        XCTAssertEqual(configuration.compiledPatterns, ["(?i)ChatGPT|codex", "^/opt/(foo|bar)$"])
    }

    func testLiteralPathMigrationRetainsItsOriginalRegex() throws {
        let source = Data(#"{"upstream":{"host":"127.0.0.1","port":7890},"processPatterns":["/usr/bin/curl","(?i)codex"]}"#.utf8)
        var configuration = try UserConfiguration(data: source)
        XCTAssertEqual(configuration.selections.first?.path, "/usr/bin/curl")
        XCTAssertEqual(configuration.compiledPatterns, ["/usr/bin/curl", "(?i)codex"])
        configuration.selections.removeAll()
        XCTAssertEqual(configuration.compiledPatterns, ["(?i)codex"])
    }

    func testRoundTripKeepsGeneratedAndAdvancedRulesSeparate() throws {
        var configuration = UserConfiguration.empty()
        configuration.selections = [ProcessSelection(kind: .application, path: "/Applications/Example.app", name: "Example")]
        configuration.advancedProcessRules = "(?i)codex\n^/opt/custom$"
        configuration.autostart = true
        let reloaded = try UserConfiguration(data: configuration.encoded())
        XCTAssertEqual(reloaded.selections, configuration.selections)
        XCTAssertEqual(reloaded.advancedProcessRules, configuration.advancedProcessRules)
        XCTAssertEqual(reloaded.compiledPatterns, configuration.compiledPatterns)
        XCTAssertTrue(reloaded.autostart)
    }

    func testExternallyEditedCoreRulesAreRespected() throws {
        var configuration = UserConfiguration.empty()
        configuration.selections = [ProcessSelection(kind: .executable, path: "/usr/bin/curl", name: "curl")]
        configuration.advancedProcessRules = "oldrule"
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: configuration.encoded()) as? [String: Any])
        object["processPatterns"] = ["newrule"]
        let reloaded = try UserConfiguration(data: JSONSerialization.data(withJSONObject: object))
        XCTAssertTrue(reloaded.selections.isEmpty)
        XCTAssertEqual(reloaded.compiledPatterns, ["newrule"])
    }

    func testPreviewRedactsOnlyThePassword() throws {
        var configuration = UserConfiguration.empty()
        configuration.authentication = true
        configuration.username = "user"
        configuration.password = "secret"
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: configuration.encoded(redactPassword: true)) as? [String: Any])
        let upstream = try XCTUnwrap(object["upstream"] as? [String: Any])
        XCTAssertEqual(upstream["password"] as? String, "••••••")
        XCTAssertEqual(upstream["username"] as? String, "user")
    }

    func testInvalidPortAndPartialCredentialsAreRejected() throws {
        var configuration = UserConfiguration.empty()
        configuration.port = "70000"
        XCTAssertThrowsError(try configuration.encoded())
        configuration.port = "7890"
        configuration.authentication = true
        configuration.username = "user"
        XCTAssertThrowsError(try configuration.encoded())
    }

    func testShellQuotingPreservesMetacharactersWithoutExecutingThem() async throws {
        let input = "path with 'quotes', $HOME, $(printf injected), `printf injected` and\n换行"
        let command = "printf %s " + CoreCommands.shellQuote(input)
        let result = try await CoreCommands.run(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", command])
        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(result.output, input)
    }
}
