package objects

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/ishbir/elliptic"

	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// Define how the message is to be encoded.
type EncodingType types.Varint

const (
	// Any data with this number may be ignored. The sending node might simply
	// be sharing its public key with you.
	Encoding_IGNORE = EncodingType(iota)
	// UTF-8. No 'Subject' or 'Body' sections. Useful for simple strings of
	// data, like URIs or magnet links.
	Encoding_TRIVIAL
	// UTF-8. Uses 'Subject' and 'Body' sections. No MIME is used.
	// messageToTransmit = 'Subject:' + subject + '\n' + 'Body:' + message
	Encoding_SIMPLE
)

// Used for person-to-person messages.
type MsgEncrypted struct {
	EncryptedData []byte
}

func (obj *MsgEncrypted) Serialize() []byte {
	return obj.EncryptedData
}

func (obj *MsgEncrypted) DeserializeReader(b io.Reader) error {
	var err error
	obj.EncryptedData, err = ioutil.ReadAll(b)
	if err != nil {
		return types.DeserializeFailedError("EncryptedData")
	}
	return nil
}

// Used for person-to-person messages when the sender's address version <= 2.
type MsgUnencryptedV2 struct {
	// Sender's address version number. This is needed in order to calculate the
	// sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	AddressVersion types.Varint
	// The sender's stream number
	Stream types.Varint
	// A bitfield of optional behaviors and features that can be expected from
	// the node with this pubkey included in this message (the sender's pubkey).
	Behaviour uint32
	// The ECC public key used for signing (uncompressed format; normally
	// prepended with \x04 )
	PubSigningKey [64]byte
	// The ECC public key used for encryption (uncompressed format; normally
	// prepended with \x04 )
	PubEncryptionKey [64]byte
	// The ripe hash of the public key of the receiver of the message.
	DestinationRipe [20]byte
	// Message Encoding type
	Encoding EncodingType
	// The message
	Message []byte
	// The acknowledgement data to be transmitted. This takes the form of a
	// Bitmessage protocol message, like another msg message. The POW therein
	// must already be completed.
	AckData []byte
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	Signature []byte
}

// Code taken from line 743 onwards on class_singleWorker.py
func (obj *MsgUnencryptedV2) SignatureSerialize() []byte {
	var b bytes.Buffer

	b.Write(obj.AddressVersion.Serialize())
	b.Write(obj.Stream.Serialize())
	binary.Write(&b, binary.BigEndian, obj.Behaviour)
	b.Write(obj.PubSigningKey[:])
	b.Write(obj.PubEncryptionKey[:])
	b.Write(obj.DestinationRipe[:])
	b.Write(types.Varint(obj.Encoding).Serialize())
	b.Write(types.Varint(len(obj.Message)).Serialize())
	b.Write(obj.Message)
	b.Write(types.Varint(len(obj.AckData)).Serialize())
	b.Write(obj.AckData)

	return b.Bytes()
}

func (obj *MsgUnencryptedV2) Serialize() []byte {
	var b bytes.Buffer

	b.Write(obj.SignatureSerialize())
	b.Write(types.Varint(len(obj.Signature)).Serialize())
	b.Write(obj.Signature)

	return b.Bytes()
}

func (obj *MsgUnencryptedV2) DeserializeReader(b io.Reader) error {
	err := obj.AddressVersion.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("AddressVersion")
	}
	err = obj.Stream.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("Stream")
	}
	err = binary.Read(b, binary.BigEndian, &obj.Behaviour)
	if err != nil {
		return types.DeserializeFailedError("Behaviour")
	}
	err = binary.Read(b, binary.BigEndian, &obj.PubSigningKey)
	if err != nil {
		return types.DeserializeFailedError("PubSigningKey")
	}
	err = binary.Read(b, binary.BigEndian, &obj.PubEncryptionKey)
	if err != nil {
		return types.DeserializeFailedError("PubEncryptionKey")
	}
	err = binary.Read(b, binary.BigEndian, &obj.DestinationRipe)
	if err != nil {
		return types.DeserializeFailedError("DestinationRipe")
	}

	var encoding types.Varint
	err = encoding.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("Encoding")
	}
	obj.Encoding = EncodingType(encoding)

	var msgLen, ackLen, sigLen types.Varint

	err = msgLen.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("message length")
	}
	obj.Message = make([]byte, msgLen)
	err = binary.Read(b, binary.BigEndian, obj.Message)
	if err != nil {
		return types.DeserializeFailedError("Message")
	}

	err = ackLen.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("ackdata length")
	}
	obj.AckData = make([]byte, ackLen)
	err = binary.Read(b, binary.BigEndian, obj.AckData)
	if err != nil {
		return types.DeserializeFailedError("Ackdata")
	}

	err = sigLen.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("signature length")
	}
	obj.Signature = make([]byte, sigLen)
	err = binary.Read(b, binary.BigEndian, obj.Signature)
	if err != nil {
		return types.DeserializeFailedError("Signature")
	}

	return nil
}

func (obj *MsgUnencryptedV2) SetSignature(sig []byte) {
	obj.Signature = sig
}

func (obj *MsgUnencryptedV2) SetSigningAndEncryptionKeys(sk, ek []byte) {
	copy(obj.PubSigningKey[:], sk)
	copy(obj.PubEncryptionKey[:], ek)
}

func (obj *MsgUnencryptedV2) Encrypt(key *elliptic.PublicKey) (types.Serializer,
	error) {
	return encryptMessage(obj.Serialize(), key)
}

func encryptMessage(payload []byte, key *elliptic.PublicKey) (types.Serializer,
	error) {
	encData, err := elliptic.RandomPrivateKeyEncrypt(payload, key)
	if err != nil {
		return nil, err
	}
	encMsg := new(MsgEncrypted)
	encMsg.EncryptedData = encData
	return encMsg, nil
}

// Used for person-to-person messages when the sender's address version >= 3.
type MsgUnencryptedV3 struct {
	// Sender's address version number. This is needed in order to calculate the
	// sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	AddressVersion types.Varint
	// The sender's stream number
	Stream types.Varint
	// A bitfield of optional behaviors and features that can be expected from
	// the node with this pubkey included in this message (the sender's pubkey).
	Behaviour uint32
	// The ECC public key used for signing (uncompressed format; normally
	// prepended with \x04 )
	PubSigningKey [64]byte
	// The ECC public key used for encryption (uncompressed format; normally
	// prepended with \x04 )
	PubEncryptionKey [64]byte
	// Used to calculate the difficulty target of messages accepted by this
	// node. The higher this value, the more difficult the Proof of Work must be
	// before this individual will accept the message. This number is the
	// average number of nonce trials a node will have to perform to meet the
	// Proof of Work requirement. 1000 is the network minimum so any lower
	// values will be automatically raised to 1000. This field is new and is
	// only included when the address_version >= 3.
	NonceTrialsPerByte types.Varint
	// Used to calculate the difficulty target of messages accepted by this
	// node. The higher this value, the more difficult the Proof of Work must be
	// before this individual will accept the message. This number is added to
	// the data length to make sending small messages more difficult. 1000 is
	// the network minimum so any lower values will be automatically raised to
	// 1000. This field is new and is only included when the AddressVersion >= 3.
	ExtraBytes types.Varint
	// The ripe hash of the public key of the receiver of the message.
	DestinationRipe [20]byte
	// Message Encoding type
	Encoding EncodingType
	// The message
	Message []byte
	// The acknowledgement data to be transmitted. This takes the form of a
	// Bitmessage protocol message, like another msg message. The POW therein
	// must already be completed.
	AckData []byte
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	Signature []byte
}

func (obj *MsgUnencryptedV3) SignatureSerialize() []byte {
	var b bytes.Buffer

	b.Write(obj.AddressVersion.Serialize())
	b.Write(obj.Stream.Serialize())
	binary.Write(&b, binary.BigEndian, obj.Behaviour)
	b.Write(obj.PubSigningKey[:])
	b.Write(obj.PubEncryptionKey[:])
	b.Write(obj.NonceTrialsPerByte.Serialize())
	b.Write(obj.ExtraBytes.Serialize())
	b.Write(obj.DestinationRipe[:])
	b.Write(types.Varint(obj.Encoding).Serialize())
	b.Write(types.Varint(len(obj.Message)).Serialize())
	b.Write(obj.Message)
	b.Write(types.Varint(len(obj.AckData)).Serialize())
	b.Write(obj.AckData)

	return b.Bytes()
}

func (obj *MsgUnencryptedV3) Serialize() []byte {
	var b bytes.Buffer

	b.Write(obj.SignatureSerialize())
	b.Write(types.Varint(len(obj.Signature)).Serialize())
	b.Write(obj.Signature)

	return b.Bytes()
}

func (obj *MsgUnencryptedV3) DeserializeReader(b io.Reader) error {
	err := obj.AddressVersion.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("AddressVersion")
	}
	err = obj.Stream.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("Stream")
	}
	err = binary.Read(b, binary.BigEndian, &obj.Behaviour)
	if err != nil {
		return types.DeserializeFailedError("Behaviour")
	}
	err = binary.Read(b, binary.BigEndian, &obj.PubSigningKey)
	if err != nil {
		return types.DeserializeFailedError("PubSigningKey")
	}
	err = binary.Read(b, binary.BigEndian, &obj.PubEncryptionKey)
	if err != nil {
		return types.DeserializeFailedError("PubEncryptionKey")
	}
	err = obj.NonceTrialsPerByte.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("NonceTrialsPerByte")
	}
	err = obj.ExtraBytes.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("ExtraBytes")
	}
	err = binary.Read(b, binary.BigEndian, &obj.DestinationRipe)
	if err != nil {
		return types.DeserializeFailedError("DestinationRipe")
	}

	var encoding types.Varint
	err = encoding.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("Encoding")
	}
	obj.Encoding = EncodingType(encoding)

	var msgLen, ackLen, sigLen types.Varint

	err = msgLen.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("message length")
	}
	obj.Message = make([]byte, msgLen)
	err = binary.Read(b, binary.BigEndian, obj.Message)
	if err != nil {
		return types.DeserializeFailedError("Message")
	}

	err = ackLen.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("ackdata length")
	}
	obj.AckData = make([]byte, ackLen)
	err = binary.Read(b, binary.BigEndian, obj.AckData)
	if err != nil {
		return types.DeserializeFailedError("Ackdata")
	}

	err = sigLen.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("signature length")
	}
	obj.Signature = make([]byte, sigLen)
	err = binary.Read(b, binary.BigEndian, obj.Signature)
	if err != nil {
		return types.DeserializeFailedError("Signature")
	}

	return nil
}

func (obj *MsgUnencryptedV3) SetSignature(sig []byte) {
	obj.Signature = sig
}

func (obj *MsgUnencryptedV3) SetSigningAndEncryptionKeys(sk, ek []byte) {
	copy(obj.PubSigningKey[:], sk)
	copy(obj.PubEncryptionKey[:], ek)
}

func (obj *MsgUnencryptedV3) Encrypt(key *elliptic.PublicKey) (types.Serializer,
	error) {
	return encryptMessage(obj.Serialize(), key)
}
