package protocol

import "fmt"

type NotEnoughBytesError struct {
	BytesNeeded    int
	BytesAvailable int
}

func (e *NotEnoughBytesError) Error() string {
	return fmt.Sprintf("not enough bytes, needed: %d, available: %d", e.BytesNeeded,
		e.BytesAvailable)
}

type VarintMinimumSizeError struct{}

func (e *VarintMinimumSizeError) Error() string {
	return "varint not encoded with minimum size"
}
