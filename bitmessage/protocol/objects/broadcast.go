package objects

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// Version 4 and 5 broadcasts
type Broadcast interface {
	// What version of the broadcast is it?
	Version() int
	// Is the broadcast encrypted?
	IsEncrypted() bool
}

// Having a broadcast version of 5 indicates that a tag is used which, in turn,
// is used when the sender's address version is >=4.
type BroadcastEncryptedV5 struct {
	// The tag. This field is new and only included when the broadcast version
	// is >= 5.
	Tag [32]byte
	// Encrypted broadcast data.
	EncryptedData []byte
}

func (obj *BroadcastEncryptedV5) Serialize() []byte {
	var b bytes.Buffer

	b.Write(obj.Tag[:])
	b.Write(obj.EncryptedData[:])

	return b.Bytes()
}

func (obj *BroadcastEncryptedV5) DeserializeReader(b io.Reader) error {
	err := binary.Read(b, binary.BigEndian, obj.Tag[:])
	if err != nil {
		return types.DeserializeFailedError("tag")
	}
	obj.EncryptedData, err = ioutil.ReadAll(b)
	if err != nil {
		return types.DeserializeFailedError("encryptedData")
	}

	return nil
}

// Broadcast originating from an address version <= 3.
type BroadcastEncryptedV4 struct {
	// Encrypted broadcast data.
	EncryptedData []byte
}

func (obj *BroadcastEncryptedV4) Serialize() []byte {
	return obj.EncryptedData
}

func (obj *BroadcastEncryptedV4) DeserializeReader(b io.Reader) error {
	var err error
	obj.EncryptedData, err = ioutil.ReadAll(b)
	if err != nil {
		return types.DeserializeFailedError("encryptedData")
	}
	return nil
}

// Broadcast version == 4 and address version == 3.
type BroadcastUnencryptedV4AddressV3 struct {
	MsgUnencryptedV3
}

// Broadcast version == 4 and address version == 2.
type BroadcastUnencryptedV4AddressV2 struct {
	MsgUnencryptedV2
}

// Broadcast version == 5 and address version == 4.
type BroadcastUnencryptedV5 struct {
	MsgUnencryptedV3
}
