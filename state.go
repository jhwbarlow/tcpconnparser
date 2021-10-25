package tcpconnparser

import "fmt"

// Kernel TCP states defined in kernel <net/tcp_states.h>.
// Formatted as hexadecimal one-byte strings
const (
	kernelTCPEstablished = "01"
	kernelTCPSynSent     = "02"
	kernelTCPSynRecv     = "03"
	kernelTCPFinWait1    = "04"
	kernelTCPFinWait2    = "05"
	kernelTCPTimeWait    = "06"
	kernelTCPClose       = "07"
	kernelTCPCloseWait   = "08"
	kernelTCPLastAck     = "09"
	kernelTCPListen      = "0A"
	kernelTCPClosing     = "0B"
	kernelTCPNewSynRecv  = "0C"
)

// State represents the state of a TCP connection
type State string

// TCP states per RFC 793
const (
	StateListen      State = "LISTEN"
	StateSynSent     State = "SYN-SENT"
	StateSynReceived State = "SYN-RECEIVED"
	StateEstablished State = "ESTABLISHED"
	StateFinWait1    State = "FIN-WAIT-1"
	StateFinWait2    State = "FIN-WAIT-2"
	StateCloseWait   State = "CLOSE-WAIT"
	StateClosing     State = "CLOSING"
	StateLastAck     State = "LAST-ACK"
	StateTimeWait    State = "TIME-WAIT"
	StateClosed      State = "CLOSED"

	// A nil state
	StateNone State = ""
)

// ConvertState converts the internal kernel state representation (as a string)
// into a State.
func convertState(kernelState string) (State, error) {
	switch kernelState {
	case kernelTCPEstablished:
		return StateEstablished, nil
	case kernelTCPSynSent:
		return StateSynSent, nil
	case kernelTCPSynRecv:
		return StateSynReceived, nil
	case kernelTCPFinWait1:
		return StateFinWait1, nil
	case kernelTCPFinWait2:
		return StateFinWait2, nil
	case kernelTCPTimeWait:
		return StateTimeWait, nil
	case kernelTCPClose:
		return StateClosed, nil
	case kernelTCPCloseWait:
		return StateCloseWait, nil
	case kernelTCPLastAck:
		return StateLastAck, nil
	case kernelTCPListen:
		return StateListen, nil
	case kernelTCPClosing:
		return StateClosing, nil
	case kernelTCPNewSynRecv:
		return StateSynReceived, nil
	default:
		return StateNone, fmt.Errorf("illegal kernel TCP state: %q", kernelState)
	}
}
