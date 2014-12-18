package objects

import (
	"io"
	"io/ioutil"

	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// Unrecognized represents an unidentified object type.
type Unrecognized struct {
	Data []byte
}

func (obj *Unrecognized) DeserializeReader(b io.Reader) error {
	var err error
	obj.Data, err = ioutil.ReadAll(b)
	if err != nil {
		return types.DeserializeFailedError("unrecognized data")
	}
	return nil
}

func (obj *Unrecognized) Serialize() []byte {
	return obj.Data
}

// Corrupt represents an object that is corrupt.
type Corrupt struct{}

func (obj *Corrupt) DeserializeReader(b io.Reader) error {
	return types.DeserializeFailedError("corrupt object")
}

func (obj *Corrupt) Serialize() []byte {
	return []byte{}
}
