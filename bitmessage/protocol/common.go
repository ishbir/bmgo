package protocol

import (
	"bytes"
	"crypto/sha512"
	"io"
)

// Interface defined for every message and serializable type.
type Serializer interface {
	// Serialize the object into bytes
	Serialize() []byte
	// Deserialize the object from io.Reader
	DeserializeReader(io.Reader) error
}

// A common function for deserializing a byte array into an instance of the
// object using the defined DeserializeReader method.
func DeserializeTo(to Serializer, raw []byte) error {
	b := bytes.NewReader(raw)
	return to.DeserializeReader(b)
}
