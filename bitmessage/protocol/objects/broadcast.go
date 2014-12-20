package objects

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/ishbir/elliptic"

	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

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

func (obj *BroadcastEncryptedV5) SetTag(tag []byte) {
	if len(tag) != 32 {
		panic("invalid tag length")
	}
	copy(obj.Tag[:], tag)
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

// Broadcast version == 4 and address version == 2.
type BroadcastUnencryptedV4AddressV2 struct {
	MsgUnencryptedV2
}

func (obj *BroadcastUnencryptedV4AddressV2) Encrypt(key *elliptic.PublicKey) (
	*BroadcastEncryptedV4, error) {
	return encryptBroadcastV4(obj.Serialize(), key)
}

func encryptBroadcastV4(payload []byte, key *elliptic.PublicKey) (
	*BroadcastEncryptedV4, error) {
	encData, err := elliptic.RandomPrivateKeyEncrypt(payload, key)
	if err != nil {
		return nil, err
	}
	encBroadcast := new(BroadcastEncryptedV4)
	encBroadcast.EncryptedData = encData
	return encBroadcast, nil
}

// Broadcast version == 4 and address version == 3.
type BroadcastUnencryptedV4AddressV3 struct {
	MsgUnencryptedV3
}

func (obj *BroadcastUnencryptedV4AddressV3) Encrypt(key *elliptic.PublicKey) (
	*BroadcastEncryptedV4, error) {
	return encryptBroadcastV4(obj.Serialize(), key)
}

// Broadcast version == 5 and address version == 4.
type BroadcastUnencryptedV5 struct {
	MsgUnencryptedV3
}

func (obj *BroadcastUnencryptedV5) Encrypt(key *elliptic.PublicKey) (
	*BroadcastEncryptedV5, error) {
	encData, err := elliptic.RandomPrivateKeyEncrypt(obj.Serialize(), key)
	if err != nil {
		return nil, err
	}
	encBroadcast := new(BroadcastEncryptedV5)
	encBroadcast.EncryptedData = encData
	return encBroadcast, nil
}
