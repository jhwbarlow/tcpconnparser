package tcpconnparser

import "net"

// IPParser is an interface which describes objects which parse
// IP addresses encoded in a string representation into net.IP objects.
type ipParser interface {
	parseAddress(str string) (addr net.IP, err error)
}
