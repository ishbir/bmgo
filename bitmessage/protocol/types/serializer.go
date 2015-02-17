package types

import "io"

// Interface defined for every message and serializable type.
type Serializer interface {
	// Serialize the object into bytes
	Serialize() []byte
	// Deserialize the object from io.Reader
	DeserializeReader(io.Reader) error
}
