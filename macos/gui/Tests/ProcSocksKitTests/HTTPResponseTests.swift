import Foundation
import XCTest
@testable import ProcSocksKit

final class HTTPResponseTests: XCTestCase {
    func testContentLengthCompletesWithoutWaitingForTLSClosure() {
        var response = HTTPResponseAccumulator()
        response.append(Data("HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\nnope".utf8))
        XCTAssertEqual(response.status, 403)
        XCTAssertTrue(response.isComplete)
        XCTAssertNil(response.error)
    }

    func testFragmentedChunkedResponseWithExtensionsAndTrailers() {
        var response = HTTPResponseAccumulator()
        let message = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\ntest\r\n0\r\nX-Test: yes\r\n\r\n"
        for byte in message.utf8.dropLast() {
            response.append(Data([byte]))
            XCTAssertFalse(response.isComplete)
            XCTAssertNil(response.error)
        }
        response.append(Data([10]))
        XCTAssertTrue(response.isComplete)
        XCTAssertEqual(response.status, 200)
    }

    func testInformationalResponsesDoNotCompleteBeforeTheFinalBody() {
        var response = HTTPResponseAccumulator()
        response.append(Data("HTTP/1.1 103 Early Hints\r\nLink: </foo>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na".utf8))
        XCTAssertEqual(response.status, 200)
        XCTAssertFalse(response.isComplete)
        response.append(Data("bc".utf8))
        XCTAssertTrue(response.isComplete)
    }

    func testTruncatedBodyAndMissingChunkTrailerRemainFailures() {
        for message in ["HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"] {
            var response = HTTPResponseAccumulator()
            response.append(Data(message.utf8))
            response.finishAtEOF()
            XCTAssertFalse(response.isComplete)
            XCTAssertNotNil(response.error)
        }
    }

    func testCloseDelimitedResponseRequiresEOF() {
        var response = HTTPResponseAccumulator()
        response.append(Data("HTTP/1.0 200 OK\r\n\r\nbody".utf8))
        XCTAssertFalse(response.isComplete)
        response.finishAtEOF()
        XCTAssertTrue(response.isComplete)
        XCTAssertNil(response.error)
    }

    func testEmptyChunkedAndBodylessResponses() {
        for message in ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                        "HTTP/1.1 204 No Content\r\n\r\n", "HTTP/1.1 304 Not Modified\r\n\r\n"] {
            var response = HTTPResponseAccumulator()
            response.append(Data(message.utf8))
            XCTAssertTrue(response.isComplete)
            XCTAssertNil(response.error)
        }
    }

    func testMalformedAndOversizedResponsesAreRejected() {
        for message in ["HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
                        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naXX"] {
            var response = HTTPResponseAccumulator()
            response.append(Data(message.utf8))
            XCTAssertNotNil(response.error)
        }
        var response = HTTPResponseAccumulator(limit: 8)
        response.append(Data(repeating: 65, count: 9))
        XCTAssertNotNil(response.error)
    }
}
