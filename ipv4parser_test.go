package tcpconnparser

import (
	"net"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	input := "0100007F"
	expected := net.IPv4(127, 0, 0, 1)

	output, err := new(ipv4Parser).parseAddress(input)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !output.Equal(expected) {
		t.Errorf("expected %q, got %q for input %q", expected, output, input)
	}

	t.Logf("got output %q for input %q", output, input)
}
