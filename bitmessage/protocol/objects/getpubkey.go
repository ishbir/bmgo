package objects

import (
	"io"

	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// When a node has the hash of a public key (from a version <= 3 address) but
// not the public key itself, it must send out a request for the public key.
type GetpubkeyV3 struct {
	// The ripemd hash of the public key. This field is only included when the
	// address version is <= 3.
	Ripe [20]byte
}

func (obj *GetpubkeyV3) Serialize() []byte {
	return obj.Ripe[:]
}

func (obj *GetpubkeyV3) DeserializeReader(b io.Reader) error {
	if c, err := b.Read(obj.Ripe[:]); err != nil || c != 20 {
		return types.DeserializeFailedError("ripe")
	}
	return nil
}

// When a node has the hash of a public key (from a version >= 4 address) but
// not the public key itself, it must send out a request for the public key.
type GetpubkeyV4 struct {
	// The tag derived from the address version, stream number, and ripe. This
	// field is only included when the address version is >= 4.
	Tag [32]byte
}

func (obj *GetpubkeyV4) Serialize() []byte {
	return obj.Tag[:]
}

func (obj *GetpubkeyV4) DeserializeReader(b io.Reader) error {
	if c, err := b.Read(obj.Tag[:]); err != nil || c != 32 {
		return types.DeserializeFailedError("tag")
	}
	return nil
}
