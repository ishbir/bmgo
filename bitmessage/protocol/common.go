package protocol

import (
	"bytes"

	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// A common function for deserializing a byte array into an instance of the
// object using the defined DeserializeReader method.
func DeserializeTo(to types.Serializer, raw []byte) error {
	b := bytes.NewReader(raw)
	return to.DeserializeReader(b)
}
