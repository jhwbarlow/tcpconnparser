package tcpconnparser

import "fmt"

const (
	tcpv4FilePath = "/proc/net/tcp"
	tcpv6FilePath = "/proc/net/tcp6"
)

// ProtocolVersion represents the an IP protocol version - currently IPv4 and IPv6
type ProtocolVersion int

const (
	ProtocolVersionIPv4 ProtocolVersion = 4
	ProtocolVersionIPv6 ProtocolVersion = 6
)

// String returns a human-readable string representing this ProtocolVersion.
func (pv ProtocolVersion) String() string {
	switch pv {
	case ProtocolVersionIPv4:
		return "IPv4"
	case ProtocolVersionIPv6:
		return "IPv6"
	default:
		panic(fmt.Errorf("illegal protocol version: %d", pv))
	}
}

// Path returns the path to the procfs file used to obtain a list of TCP connections
// of this ProtocolVersion.
func (pv ProtocolVersion) path() (string, error) {
	switch pv {
	case ProtocolVersionIPv4:
		return tcpv4FilePath, nil
	case ProtocolVersionIPv6:
		return tcpv6FilePath, nil
	default:
		return "", fmt.Errorf("illegal protocol version: %d", pv)
	}
}

// Parser returns the ipParser used to parse an entry from the file path retuned by
// the path method for this ProtocolVersion.
func (pv ProtocolVersion) parser() (ipParser, error) {
	switch pv {
	case ProtocolVersionIPv4:
		return new(ipv4Parser), nil
	case ProtocolVersionIPv6:
		return new(ipv6Parser), nil
	default:
		return nil, fmt.Errorf("illegal protocol version: %d", pv)
	}
}
