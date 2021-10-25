// package tcpconnparser implements a parser for the Linux kernel procfs
// /proc/net/tcp and /proc/net/tcp6 files, returning a list of IPv4
// and IPv6 connections.
package tcpconnparser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Indices of interesting fields within the space-separated fields of a
// /proc/net/tcp* pseudo-file.
const (
	indexLocalAddress = 1
	indexRemAddress   = 2
	indexState        = 3
	indexQueues       = 4
	indexUID          = 7
	indexINode        = 9

	minNoOfFields = 10
)

// Indices of subfields within the colon-seperated address fields of a
// /proc/net/tcp* pseudo-file.
const (
	subIndexIP = iota
	subIndexPort

	minNoOfAddressSubfields
)

// Indices of subfields within the colon-seperated queue field of a
// /proc/net/tcp* pseudo-file.
const (
	subIndexTXQueue = iota
	subIndexRXQueue

	minNoOfQueuesSubfields
)

// Init will panic if this package is used on a non-x86 family architecture.
func init() {
	if !(runtime.GOARCH == "amd64" || runtime.GOARCH == "386") {
		panic(errors.New("some parsing may depend on processor endianess - currently only tested on amd64"))
	}
}

// GetConnections returns a slice of Connections which is the union of all connections
// using the provided protocolVersions.
func GetConnections(protocolVersions ...ProtocolVersion) ([]*Connection, error) {
	allConns := make([]*Connection, 0, 4096)

	for _, protocolVersion := range protocolVersions {
		path, err := protocolVersion.path()
		if err != nil {
			return nil, fmt.Errorf("getting path: %w", err)
		}

		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening %q: %w", path, err)
		}
		defer file.Close()

		conns, err := GetConnectionsFromReader(file, protocolVersion)
		if err != nil {
			return nil, fmt.Errorf("getting connections from file %q: %w", path, err)
		}

		allConns = append(allConns, conns...)
	}

	return allConns, nil
}

// GetConnectionsFromReader returns a slice of Connections read from the provided Reader.
// It is expected that the reader provides connections in a format which matches that given
// by the IP protocol version given in protocolVersion, otherwise parsing errors will result.
func GetConnectionsFromReader(reader io.Reader, protocolVersion ProtocolVersion) ([]*Connection, error) {
	ipParser, err := protocolVersion.parser()
	if err != nil {
		return nil, fmt.Errorf("getting parser: %w", err)
	}

	scanner := bufio.NewScanner(reader)
	conns := make([]*Connection, 0, 2048)
	firstLine := true

	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("scanning for connection line: %w", err)
			}

			return conns, nil
		}

		if firstLine {
			firstLine = false
			continue
		}

		str := scanner.Text()
		if len(str) == 0 {
			continue
		}

		conn, err := toConn(str, ipParser, protocolVersion)
		if err != nil {
			return nil, fmt.Errorf("parsing event: %w", err)
		}

		conns = append(conns, conn)
	}
}

// ToConn converts the given string into a Connection, using the provided ipParser to convert
// the IP Address into a net.IP object. The ProtocolVersion of the connection is given by the
// that provided in protocolVersion.
func toConn(str string, ipParser ipParser, protocolVersion ProtocolVersion) (*Connection, error) {
	fields := strings.Fields(str)
	if len(fields) < minNoOfFields {
		return nil, fmt.Errorf("invalid format: line contained less than %d fields: %d",
			minNoOfFields,
			len(fields))
	}

	localAddr, localPort, err := parseAddress(fields[indexLocalAddress], ipParser)
	if err != nil {
		return nil, fmt.Errorf("parsing local address: %w", err)
	}

	remoteAddr, remotePort, err := parseAddress(fields[indexRemAddress], ipParser)
	if err != nil {
		return nil, fmt.Errorf("parsing remote address: %w", err)
	}

	txQueue, rxQueue, err := parseQueues(fields[indexQueues])
	if err != nil {
		return nil, fmt.Errorf("parsing queue lengths: %w", err)
	}

	state, err := parseState(fields[indexState])
	if err != nil {
		return nil, fmt.Errorf("parsing connection state: %w", err)
	}

	iNode, err := parseINode(fields[indexINode])
	if err != nil {
		return nil, fmt.Errorf("parsing connection inode: %w", err)
	}

	uid, err := parseUID(fields[indexUID])
	if err != nil {
		return nil, fmt.Errorf("parsing UID: %w", err)
	}

	if state == StateListen {
		return NewListeningConnection(protocolVersion,
			rxQueue,
			localAddr,
			localPort,
			uid,
			iNode), nil
	}

	return NewConnection(state,
		protocolVersion,
		rxQueue,
		txQueue,
		localAddr,
		localPort,
		remoteAddr,
		remotePort,
		uid,
		iNode), nil
}

// ParseAddress returns the IP address and port encoded in the provided string.
// The IP is parsed using the given ipParser.
func parseAddress(str string, ipParser ipParser) (addr net.IP, port uint16, err error) {
	subFields := strings.Split(str, ":")

	if len(subFields) < minNoOfAddressSubfields {
		return nil, 0, fmt.Errorf("invalid format: address field contained less than %d subfields: %d",
			minNoOfAddressSubfields,
			len(subFields))
	}

	addr, err = ipParser.parseAddress(subFields[subIndexIP])
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse %q as IP address: %w", subFields[subIndexIP], err)
	}

	// Port is 16-bit hex string.
	// On amd64, displayed big endian, in contrast to the IP address.
	// TODO: Does the endianess change depending on the arch?
	// For now the package will panic if used on non-amd64.
	uint64Port, err := strconv.ParseUint(subFields[subIndexPort], 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse port %q as integer: %w",
			subFields[subIndexPort],
			err)
	}

	return addr, uint16(uint64Port), nil
}

// ParseQueues returns the size of the TX and RX queues (otherwise known as the send and receive
// buffers, respectively) encoded in the provided string.
func parseQueues(str string) (tx, rx uint32, err error) {
	subFields := strings.Split(str, ":")

	if len(subFields) < minNoOfQueuesSubfields {
		return 0, 0, fmt.Errorf("invalid format: queue field contained less than %d subfields: %d",
			minNoOfQueuesSubfields,
			len(subFields))
	}

	txUint64, err := strconv.ParseUint(subFields[subIndexTXQueue], 16, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("unable to parse TX queue length %q as integer: %w",
			subFields[subIndexTXQueue],
			err)
	}

	rxUint64, err := strconv.ParseUint(subFields[subIndexRXQueue], 16, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("unable to parse RX queue length %q as integer: %w",
			subFields[subIndexRXQueue],
			err)
	}

	return uint32(txUint64), uint32(rxUint64), nil
}

// ParseState returns the TCP connection state encoded in the provided string.
func parseState(str string) (State, error) {
	state, err := convertState(str)
	if err != nil {
		return StateNone, fmt.Errorf("unable to parse state %q: %w", str, err)
	}

	return state, nil
}

// ParseUID returns the UID encoded in the provided string.
func parseUID(str string) (uint32, error) {
	uidUint64, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unable to parse UID %q as integer: %w", str, err)
	}

	return uint32(uidUint64), nil
}

// ParseInode returns the inode encoded in the provided string.
func parseINode(str string) (uint32, error) {
	iNodeUint64, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unable to parse inode %q as integer: %w", str, err)
	}

	return uint32(iNodeUint64), nil
}
