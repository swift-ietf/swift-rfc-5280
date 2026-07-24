// RFC_5280.DirectoryString Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.DirectoryString {
    @Suite
    struct Test {
        @Suite struct Unit {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.DirectoryString.Test.Unit {

    @Test
    func `Parses each CHOICE arm by identifier`() throws {
        // PrintableString "A"
        let printable = try RFC_5280.DirectoryString(derEncoded: [0x13, 0x01, 0x41])
        guard case .printableString = printable else {
            Issue.record("Expected the printableString arm")
            return
        }

        // UTF8String "A"
        let utf8 = try RFC_5280.DirectoryString(derEncoded: [0x0c, 0x01, 0x41])
        guard case .utf8String = utf8 else {
            Issue.record("Expected the utf8String arm")
            return
        }

        // TeletexString "A" (legacy, tolerated on parse)
        let teletex = try RFC_5280.DirectoryString(derEncoded: [0x14, 0x01, 0x41])
        guard case .teletexString = teletex else {
            Issue.record("Expected the teletexString arm")
            return
        }

        // BMPString "A" (UCS-2 big-endian)
        let bmp = try RFC_5280.DirectoryString(derEncoded: [0x1e, 0x02, 0x00, 0x41])
        guard case .bmpString = bmp else {
            Issue.record("Expected the bmpString arm")
            return
        }

        // UniversalString "A" (UCS-4 big-endian)
        let universal = try RFC_5280.DirectoryString(derEncoded: [0x1c, 0x04, 0x00, 0x00, 0x00, 0x41])
        guard case .universalString = universal else {
            Issue.record("Expected the universalString arm")
            return
        }
    }

    // RFC 5280 §4.1.2.4: CAs MUST use PrintableString or UTF8String
    @Test
    func `Only the profile's preferred arms are flagged preferred`() throws {
        #expect(try RFC_5280.DirectoryString(derEncoded: [0x13, 0x01, 0x41]).isRFC5280Preferred)
        #expect(try RFC_5280.DirectoryString(derEncoded: [0x0c, 0x01, 0x41]).isRFC5280Preferred)
        #expect(try !RFC_5280.DirectoryString(derEncoded: [0x14, 0x01, 0x41]).isRFC5280Preferred)
        #expect(try !RFC_5280.DirectoryString(derEncoded: [0x1e, 0x02, 0x00, 0x41]).isRFC5280Preferred)
        #expect(try !RFC_5280.DirectoryString(derEncoded: [0x1c, 0x04, 0x00, 0x00, 0x00, 0x41]).isRFC5280Preferred)
    }

    @Test
    func `Rejects a non-DirectoryString field`() {
        #expect(throws: ISO_8824.Error.self) {
            // IA5String is not a DirectoryString arm.
            _ = try RFC_5280.DirectoryString(derEncoded: [0x16, 0x01, 0x41])
        }
    }

    @Test
    func `Round-trips`() throws {
        #expect(try roundTrips(RFC_5280.DirectoryString.utf8String(ISO_8824.UTF8String("Zürich"))))
        #expect(try roundTrips(RFC_5280.DirectoryString.printableString(try ISO_8824.PrintableString("Zurich"))))
    }
}
