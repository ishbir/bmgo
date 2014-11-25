package protocol

import (
	"fmt"
	"io"
)

// Interface defined for every message and serializable type.
type NetworkSerializer interface {
	// Serialize the object into bytes
	Serialize() []byte
	// Deserialize the object from byte array
	Deserialize([]byte) error
	// Deserialize the object from io.Reader
	DeserializeReader(io.Reader) error
}

// Version 2, 3 and 4 public keys
type PubkeyObject interface {
	// What version of the pubkey is it?
	Version() int
	// Is the pubkey encrypted?
	IsEncrypted() bool
}

// Version 4 and 5 broadcasts
type BroadcastObject interface {
	// What version of the broadcast is it?
	Version() int
	// Is the broadcast encrypted?
	IsEncrypted() bool
}

// Version 2 and 3 messages
type MsgUnencryptedObject interface {
	// What version of the msg is it?
	Version() int
}

// Read failed because of not enough bytes.
type NotEnoughBytesError int

func (e NotEnoughBytesError) Error() string {
	return fmt.Sprintf("not enough bytes, needed: %d", int(e))
}

// Number encoded as varint does not use minimum bytes for representation.
type VarintMinimumSizeError struct{}

func (e VarintMinimumSizeError) Error() string {
	return "varint not encoded with minimum size"
}

// Deserialization of an object failed. Used by Deserialize and DeserializeReader
// methods of the NetworkSerializer interface.
type DeserializeFailedError string

func (e DeserializeFailedError) Error() string {
	return "failed to deserialize " + string(e)
}
