package tcpconnparser

import (
	"fmt"
	"net"
)

const (
	nibblesInIPv4Address = 8
)

// IPv4Parser is a parser for IP addresses in the format provided by the
// /proc/net/tcp pseudo-file.
type ipv4Parser struct{}

// ParseAddress parses IP addresses in the format provided by the
// /proc/net/tcp pseudo-file into net.IP objects.
func (*ipv4Parser) parseAddress(str string) (addr net.IP, err error) {
	// IP Address is 32-bit hex string.
	// On amd64 it is displayed as little endian, so flip the bytes.
	// TODO: Does the endianess change depending on the arch?
	// For now the package will panic if used on non-amd64.
	if len(str) != nibblesInIPv4Address {
		return nil, fmt.Errorf("incorrect string length for IPv4 address: %d", len(str))
	}

	addrBytes, err := reverseBytesInHexWord(str)
	if err != nil {
		return nil, fmt.Errorf("reversing bytes in address: %w", err)
	}

	return net.IP(addrBytes), nil
}
