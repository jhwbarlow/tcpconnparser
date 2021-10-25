package tcpconnparser

import (
	"fmt"
	"net"
)

const (
	bytesInIPv6Address   = 16
	nibblesIn32BitWord   = 8
	wordsInIPv6Address   = 4
	nibblesInIPv6Address = bytesInIPv6Address * 2
)

// IPv6Parser is a parser for IP addresses in the format provided by the
// /proc/net/tcp6 pseudo-file.
type ipv6Parser struct{}

// ParseAddress parses IP addresses in the format provided by the
// /proc/net/tcp6 pseudo-file into net.IP objects.
func (*ipv6Parser) parseAddress(str string) (addr net.IP, err error) {
	// IP Address is 128-bit hex string.
	// On amd64 it is displayed as a big-endian "array" of little endian
	// 32-bit words, so flip the bytes in each word, but do not flip the
	// ordering of the words. e.g. ::1 is displayed as:
	// 00000000000000000000000001000000
	// As 32-bit words:
	// 00000000 00000000 00000000 01000000
	// TODO: Does the endianess change depending on the arch?
	// For now the package will panic if used on non-amd64.
	if len(str) != nibblesInIPv6Address {
		return nil, fmt.Errorf("incorrect string length for IPv6 address: %d", len(str))
	}

	addrBytes := make([]byte, 0, bytesInIPv6Address)
	startIndex := 0
	endIndex := startIndex + nibblesIn32BitWord

	for i := 0; i < wordsInIPv6Address; i++ {
		// TODO: Bad slicing can panic - recover and return an error
		wordBytes, err := reverseBytesInHexWord(str[startIndex:endIndex])
		if err != nil {
			return nil, fmt.Errorf("reversing bytes in word: %w", err)
		}

		addrBytes = append(addrBytes, wordBytes...)
		startIndex += nibblesIn32BitWord
		endIndex += nibblesIn32BitWord
	}

	return net.IP(addrBytes), nil
}
