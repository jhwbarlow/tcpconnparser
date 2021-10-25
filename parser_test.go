package tcpconnparser

import (
	"net"
	"strings"
	"testing"
)

func TestGetConnectionsListeningConnIPv4(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0100007F:1A85 00000000:0000 0A 00000000:00000032 00:00000000 00000000  1000        0 789829 51 0000000000000000 100 0 0 10 0`
	mockConn := NewListeningConnection(ProtocolVersionIPv4,
		50,
		net.IPv4(127, 0, 0, 1),
		6789,
		1000,
		789829)

	conns, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if len(conns) == 0 {
		t.Error("expected conns slice to include connection, but was empty")
	}

	if len(conns) != 1 {
		t.Errorf("expected conns slice to include 1 connection, but contained %d", len(conns))
	}

	conn := conns[0]

	if !conn.Equal(mockConn) {
		t.Errorf("expected connection to be equal to %q, but was %q", mockConn, conn)
	}

	t.Logf("got conn %q", conn)
}

func TestGetConnectionsNonListeningConnIPv4(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:01BB 01 00000000:00000000 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`
	mockConn := NewConnection(StateEstablished,
		ProtocolVersionIPv4,
		0,
		0,
		net.IPv4(192, 168, 1, 3),
		54176,
		net.IPv4(88, 221, 16, 125),
		443,
		1000,
		380687)

	conns, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if len(conns) == 0 {
		t.Error("expected conns slice to include connection, but was empty")
	}

	if len(conns) != 1 {
		t.Errorf("expected conns slice to include 1 connection, but contained %d", len(conns))
	}

	conn := conns[0]

	if !conn.Equal(mockConn) {
		t.Errorf("expected connection to be equal to %q, but was %q", mockConn, conn)
	}

	t.Logf("got conn %q", conn)
}

func TestGetConnectionsListeningConnIPv6(t *testing.T) {
	mockFile := `sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
2: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31267 1 0000000000000000 100 0 0 10 0`
	mockConn := NewListeningConnection(ProtocolVersionIPv6,
		0,
		net.ParseIP("::1"),
		631,
		0,
		31267)

	conns, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv6)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if len(conns) == 0 {
		t.Error("expected conns slice to include connection, but was empty")
	}

	if len(conns) != 1 {
		t.Errorf("expected conns slice to include 1 connection, but contained %d", len(conns))
	}

	conn := conns[0]

	if !conn.Equal(mockConn) {
		t.Errorf("expected connection to be equal to %q, but was %q", mockConn, conn)
	}

	t.Logf("got conn %q", conn)
}

func TestGetConnectionsNonListeningConnIPv6(t *testing.T) {
	mockFile := `sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
5: 00000000000000000000000001000000:1A85 00000000000000000000000001000000:BF7A 01 00000000:00000000 00:00000000 00000000  1000        0 394269 1 0000000000000000 20 0 0 10 -1`
	mockConn := NewConnection(StateEstablished,
		ProtocolVersionIPv6,
		0,
		0,
		net.ParseIP("::1"),
		6789,
		net.ParseIP("::1"),
		49018,
		1000,
		394269)

	conns, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv6)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if len(conns) == 0 {
		t.Error("expected conns slice to include connection, but was empty")
	}

	if len(conns) != 1 {
		t.Errorf("expected conns slice to include 1 connection, but contained %d", len(conns))
	}

	conn := conns[0]

	if !conn.Equal(mockConn) {
		t.Errorf("expected connection to be equal to %q, but was %q", mockConn, conn)
	}

	t.Logf("got conn %q", conn)
}

func TestGetConnectionsLowFieldCountError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:01BB`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadLocalIPv4AddressError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: BADADDRESS:D3A0 7D10DD58:01BB 01 00000000:00000000 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadRemoteIPv4AddressError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 7D10DD58:01BB BADADDRESS:D3A0 01 00000000:00000000 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadLocalIPv6AddressError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
5: BADIPV6ADDRESS:1A85 00000000000000000000000001000000:BF7A 01 00000000:00000000 00:00000000 00000000  1000        0 394269 1 0000000000000000 20 0 0 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv6)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadRemoteIPv6AddressError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
	5: 00000000000000000000000001000000:BF7A BADIPV6ADDRESS:1A85 01 00000000:00000000 00:00000000 00000000  1000        0 394269 1 0000000000000000 20 0 0 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv6)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadLocalPortError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:BADPORT 7D10DD58:D3A0 01 00000000:00000000 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadRemotePortError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:BADPORT 01 00000000:00000000 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadTxQueueError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:D3A0 01 BADQUEUE:00000000 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadRxQueueError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:D3A0 01 00000000:BADQUEUE 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadStateError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:D3A0 BADSTATE 00000000:00000000 02:0000009A 00000000  1000        0 380687 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadInodeError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:D3A0 01 00000000:00000000 02:0000009A 00000000  1000        0 BADINODE 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadUIDError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:D3A0 01 00000000:00000000 02:0000009A 00000000  BADUID        0 12345 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsNoLocalAddressSubfieldsError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0 7D10DD58:D3A0 01 00000000:00000000 02:0000009A 00000000  1000        0 12345 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsNoRemoteAddressSubfieldsError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58 01 00000000:00000000 02:0000009A 00000000  1000        0 12345 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsNoQueueSubfieldsError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0301A8C0:D3A0 7D10DD58:D3A0 01 00000000 02:0000009A 00000000  1000        0 12345 2 0000000000000000 22 4 2 10 -1`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersionIPv4)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetConnectionsBadProtocolVersionError(t *testing.T) {
	mockFile := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0100007F:1A85 00000000:0000 0A 00000000:00000032 00:00000000 00000000  1000        0 789829 51 0000000000000000 100 0 0 10 0`

	_, err := GetConnectionsFromReader(strings.NewReader(mockFile), ProtocolVersion(999))
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}
