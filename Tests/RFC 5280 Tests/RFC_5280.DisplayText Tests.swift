// RFC_5280.DisplayText Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.DisplayText Tests` {}

extension `RFC_5280.DisplayText Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.DisplayText Tests`.Test.Unit {

    // RFC 5280 §4.2.1.4: DisplayText is a four-arm CHOICE
    @Test
    func `Every arm round-trips`() throws {
        #expect(try roundTrips(RFC_5280.DisplayText.utf8String(ISO_8824.UTF8String("Notice"))))
        #expect(try roundTrips(RFC_5280.DisplayText.ia5String(try ISO_8824.IA5String("Notice"))))
        #expect(try roundTrips(RFC_5280.DisplayText.visibleString(try ISO_8824.VisibleString("Notice"))))
    }

    // §4.2.1.4: conforming CAs SHOULD use UTF8String
    @Test
    func `UTF8String is the preferred arm`() throws {
        #expect(RFC_5280.DisplayText.utf8String(ISO_8824.UTF8String("Notice")).isRFC5280Preferred)
        #expect(!(try RFC_5280.DisplayText.ia5String(try ISO_8824.IA5String("Notice")).isRFC5280Preferred))
    }

    // §4.2.1.4: UserNotice tells its two optional untagged fields apart by type
    @Test
    func `A UserNotice with both fields round-trips`() throws {
        let notice = RFC_5280.UserNotice(
            noticeRef: RFC_5280.NoticeReference(
                organization: .utf8String(ISO_8824.UTF8String("Example Org")),
                noticeNumbers: [1, 2, 3]
            ),
            explicitText: .utf8String(ISO_8824.UTF8String("See the CPS"))
        )
        #expect(try roundTrips(notice))

        let reparsed = try RFC_5280.UserNotice(derEncoded: try derBytes(of: notice))
        #expect(reparsed.noticeRef?.noticeNumbers == [1, 2, 3])
        #expect(reparsed.explicitText == .utf8String(ISO_8824.UTF8String("See the CPS")))
    }

    @Test
    func `A UserNotice with only explicit text round-trips`() throws {
        let notice = RFC_5280.UserNotice(explicitText: .utf8String(ISO_8824.UTF8String("Text only")))
        #expect(try roundTrips(notice))
        let reparsed = try RFC_5280.UserNotice(derEncoded: try derBytes(of: notice))
        #expect(reparsed.noticeRef == nil)
        #expect(reparsed.explicitText != nil)
    }

    @Test
    func `A UserNotice with only a notice reference round-trips`() throws {
        let notice = RFC_5280.UserNotice(
            noticeRef: RFC_5280.NoticeReference(
                organization: .utf8String(ISO_8824.UTF8String("Example Org")),
                noticeNumbers: [7]
            )
        )
        #expect(try roundTrips(notice))
        let reparsed = try RFC_5280.UserNotice(derEncoded: try derBytes(of: notice))
        #expect(reparsed.noticeRef != nil)
        #expect(reparsed.explicitText == nil)
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.DisplayText Tests`.Test.`Edge Case` {

    // §4.2.1.4: SIZE (1..200)
    @Test
    func `The 200-character bound is reported, not enforced on parse`() throws {
        let long = RFC_5280.DisplayText.utf8String(ISO_8824.UTF8String(String(repeating: "a", count: 201)))
        #expect(!long.isRFC5280Conformant)
        // Wire fidelity: an over-long value still round-trips.
        #expect(try roundTrips(long))

        let bounded = RFC_5280.DisplayText.utf8String(ISO_8824.UTF8String(String(repeating: "a", count: 200)))
        #expect(bounded.isRFC5280Conformant)
    }

    @Test
    func `An empty display text is non-conformant`() {
        #expect(!RFC_5280.DisplayText.utf8String(ISO_8824.UTF8String("")).isRFC5280Conformant)
    }

    @Test
    func `A non-string node is rejected`() {
        #expect(throws: ISO_8824.Error.self) {
            // An INTEGER is not one of the four DisplayText arms.
            _ = try RFC_5280.DisplayText(derEncoded: [0x02, 0x01, 0x01])
        }
    }

    // §4.2.1.4: conforming CAs SHOULD NOT use the noticeRef option
    @Test
    func `The noticeRef option is reported non-conformant`() {
        let withRef = RFC_5280.UserNotice(
            noticeRef: RFC_5280.NoticeReference(
                organization: .utf8String(ISO_8824.UTF8String("Org")),
                noticeNumbers: [1]
            )
        )
        #expect(!withRef.isRFC5280Conformant)
        #expect(RFC_5280.UserNotice(explicitText: .utf8String(ISO_8824.UTF8String("Fine"))).isRFC5280Conformant)
    }
}
