package tcpconnparser

import (
	"bytes"
	"testing"
)

func TestReverseBytesInHexWord(t *testing.T) {
	input := "0DF0FECA"
	expected := []byte{0xCA, 0xFE, 0xF0, 0x0D}

	output, err := reverseBytesInHexWord(input)
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !bytes.Equal(output, expected) {
		t.Errorf("expected %X, got %X for input %q", expected, output, input)
	}

	t.Logf("got output %X for input %q", output, input)
}

func TestReverseBytesInHexWordOddNibblesError(t *testing.T) {
	input := "DF0FECA"

	_, err := reverseBytesInHexWord(input)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestReverseBytesInHexWordNonIntegerNibbleError(t *testing.T) {
	input := "GDF0FECA"

	_, err := reverseBytesInHexWord(input)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}
