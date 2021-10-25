package tcpconnparser

import (
	"fmt"
	"strconv"
)

// ReverseBytesInHexWord reverses the bytes given in the hexadecimal encoded string
// representing a slice of bytes, and returns the result as a slice of bytes.
// This can be used to convert from little-endian to big-endian or vice-versa.
func reverseBytesInHexWord(hexWord string) ([]byte, error) {
	// Is this a valid hex-string representation of a word?
	if len(hexWord)%2 != 0 {
		return nil, fmt.Errorf("hex string %q has odd number of nibbles", hexWord)
	}

	src := []rune(hexWord)
	dst := make([]byte, len(src)/2)

	for i, j := 0, len(dst)-1; i < len(src); {
		buf := make([]rune, 2)
		buf[0] = src[i]
		buf[1] = src[i+1]

		octetUint64, err := strconv.ParseUint(string(buf), 16, 8)
		if err != nil {
			return nil, fmt.Errorf("unable to parse hex octet %q as integer: %w", string(buf), err)
		}

		dst[j] = byte(octetUint64)

		i += 2
		j--
	}

	return dst, nil
}
