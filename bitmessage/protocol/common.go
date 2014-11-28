package protocol

import "io"

// Interface defined for every message and serializable type.
type NetworkSerializer interface {
	// Serialize the object into bytes
	Serialize() []byte
	// Deserialize the object from byte array
	Deserialize([]byte) error
	// Deserialize the object from io.Reader
	DeserializeReader(io.Reader) error
}