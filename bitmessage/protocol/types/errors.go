package types

import "fmt"

// Deserialization of an object failed. Used by Deserialize and DeserializeReader
// methods of the NetworkSerializer interface.
type DeserializeFailedError string

func (e DeserializeFailedError) Error() string {
	return "failed to deserialize " + string(e)
}

// Number encoded as varint does not use minimum bytes for representation.
type VarintMinimumSizeError struct{}

func (e VarintMinimumSizeError) Error() string {
	return "varint not encoded with minimum size"
}

// Read failed because of not enough bytes.
type NotEnoughBytesError int

func (e NotEnoughBytesError) Error() string {
	return fmt.Sprintf("not enough bytes, needed: %d", int(e))
}
