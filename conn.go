package tcpconnparser

import (
	"fmt"
	"net"
)

// Connection represents a TCP connection within the kernel.
type Connection struct {
	State                             State
	ReceiveBufferSize, SendBufferSize uint32 // Zero-valued for listening conns
	AcceptBacklog                     uint32 // Zero-valued for non-listening conns
	ProtocolVersion                   ProtocolVersion
	LocalAddr, RemoteAddr             net.IP // RemoteAddr zero-valued for listening conns
	LocalPort, RemotePort             uint16 // RemotePort zero-valued for listening conns
	UID                               uint32
	INode                             uint32
}

// NewListeningConnection constructs a new listening Connection.
func NewListeningConnection(protocolVersion ProtocolVersion,
	acceptBacklog uint32,
	localAddr net.IP,
	localPort uint16,
	uid uint32,
	iNode uint32) *Connection {
	return &Connection{
		State:           StateListen,
		ProtocolVersion: protocolVersion,
		AcceptBacklog:   acceptBacklog,
		LocalAddr:       localAddr,
		LocalPort:       localPort,
		UID:             uid,
		INode:           iNode,
	}
}

// NewConnection constructs a new Connection in a non-listening state.
func NewConnection(state State,
	protocolVersion ProtocolVersion,
	receiveBufferSize uint32,
	SendBufferSize uint32,
	localAddr net.IP,
	localPort uint16,
	remoteAddr net.IP,
	remotePort uint16,
	uid uint32,
	iNode uint32) *Connection {
	return &Connection{
		State:             state,
		ProtocolVersion:   protocolVersion,
		ReceiveBufferSize: receiveBufferSize,
		SendBufferSize:    SendBufferSize,
		LocalAddr:         localAddr,
		LocalPort:         localPort,
		RemoteAddr:        remoteAddr,
		RemotePort:        remotePort,
		UID:               uid,
		INode:             iNode,
	}

}

// String returns a human-readable string representation of this Connection.
func (c *Connection) String() string {
	if c.State == StateListen {
		return fmt.Sprintf("State: %s, Protocol Version: %s, Accept Backlog: %d, "+
			"Local Address: %s:%d, UID: %d, INode: %d",
			c.State,
			c.ProtocolVersion,
			c.AcceptBacklog,
			c.LocalAddr,
			c.LocalPort,
			c.UID,
			c.INode)
	}

	return fmt.Sprintf("State: %s, Protocol Version: %s, "+
		"Receive Buffer Size: %d, Send Buffer Size: %d, "+
		"Local Address: %s:%d, Remote Address: %s:%d, UID: %d, INode: %d",
		c.State,
		c.ProtocolVersion,
		c.ReceiveBufferSize,
		c.SendBufferSize,
		c.LocalAddr,
		c.LocalPort,
		c.RemoteAddr,
		c.RemotePort,
		c.UID,
		c.INode)
}

// Equal compares this Connection for equality with another.
func (c *Connection) Equal(conn *Connection) bool {
	if c == conn {
		return true
	}

	return c.State == conn.State &&
		c.ReceiveBufferSize == conn.ReceiveBufferSize &&
		c.SendBufferSize == conn.SendBufferSize &&
		c.AcceptBacklog == conn.AcceptBacklog &&
		c.ProtocolVersion == conn.ProtocolVersion &&
		c.LocalAddr.Equal(conn.LocalAddr) &&
		c.RemoteAddr.Equal(conn.RemoteAddr) &&
		c.LocalPort == conn.LocalPort &&
		c.RemotePort == conn.RemotePort &&
		c.UID == conn.UID &&
		c.INode == conn.INode
}
