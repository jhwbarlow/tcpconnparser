package tcpconnparser

import (
	"net"
	"testing"
)

func TestParseIPv6(t *testing.T) {
	input := "00000000000000000000000001000000"
	expected := net.ParseIP("::1")

	output, err := new(ipv6Parser).parseAddress(input)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !output.Equal(expected) {
		t.Errorf("expected %q, got %q for input %q", expected, output, input)
	}

	t.Logf("got output %q for input %q", output, input)
}
