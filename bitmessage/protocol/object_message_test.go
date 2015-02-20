package protocol

import (
	"bytes"
	"testing"
	"time"

	"github.com/ishbir/bmgo/bitmessage/constants"
	"github.com/ishbir/bmgo/bitmessage/identity"
	"github.com/ishbir/bmgo/bitmessage/pow"
	"github.com/ishbir/bmgo/bitmessage/protocol/objects"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

var ownId1 *identity.Own
var ownId2 *identity.Own

func init() {
	var err error
	ownId1, err = identity.NewRandom(1)
	if err != nil {
		panic("failed to generate identity 1")
	}
	ownId2, err = identity.NewRandom(1)
	if err != nil {
		panic("failed to generate identity 2")
	}
	ownId1.CreateAddress(4, 1)
	ownId2.CreateAddress(4, 1)
}

func TestObjectMessage(t *testing.T) {
	msg := ObjectMessage{
		TTL:        time.Hour,
		ObjectType: ObjectType(6), // undefined
		Version:    types.Varint(8),
		Stream:     types.Varint(1),
		Payload:    &bytesPayload{bytes: []byte{0x54, 0xA4, 0x4E, 0x9F}},
	}
	err := msg.Preserialize(nil, ownId1.ToForeign())
	if err != nil {
		t.Fatal("preserialize error:", err.Error())
	}

	raw := msg.Serialize()

	msg1 := new(ObjectMessage)
	DeserializeTo(msg1, raw[MessageHeaderSize():])

	if msg1.Nonce != msg.Nonce {
		t.Error("for Nonce got", msg1.Nonce, "expected", msg.Nonce)
	}
	if msg1.expiresTime != msg.expiresTime {
		t.Error("for expiresTime got", msg1.expiresTime, "expected",
			msg.expiresTime)
	}
	if msg1.ObjectType != msg.ObjectType {
		t.Error("for ObjectType got", msg1.ObjectType, "expected",
			msg.ObjectType)
	}
	if msg1.Version != msg.Version {
		t.Error("for Version got", msg1.Version, "expected", msg.Version)
	}
	if msg1.Stream != msg.Stream {
		t.Error("for Stream got", msg1.Stream, "expected", msg.Stream)
	}
	if _, ok := msg1.Payload.(*objects.Unrecognized); !ok {
		t.Error("for Payload, did not get Unrecognized object type")
	}
	if !bytes.Equal(msg1.Payload.Serialize(), msg.Payload.Serialize()) {
		t.Error("for Payload got", msg1.Payload.Serialize(), "expected",
			msg.Payload.Serialize())
	}
	if !pow.Check(raw[MessageHeaderSize():], int(ownId1.ExtraBytes),
		int(ownId1.NonceTrialsPerByte)) {
		t.Error("nonce check failed")
	}
}

func TestGetpubkeyV4Object(t *testing.T) {
	msg := ObjectMessage{
		TTL:        time.Hour,
		ObjectType: GetpubkeyObject,
		Version:    4,
		Stream:     1,
		Payload: &objects.GetpubkeyV4{
			Tag: ownId2.Address.Tag(),
		},
	}
	err := msg.Preserialize(nil, nil)
	if err != nil {
		t.Fatal("preserialize error:", err.Error())
	}

	raw := msg.Serialize()

	msg1 := new(ObjectMessage)
	DeserializeTo(msg1, raw[MessageHeaderSize():])

	if msg1.ObjectType != GetpubkeyObject {
		t.Error("for ObjectType got", msg1.ObjectType, "expected GetpubkeyObject")
	}
	if _, ok := msg1.Payload.(*objects.GetpubkeyV4); !ok {
		t.Error("for Payload, did not get GetpubkeyV4 object type")
	}
	if !bytes.Equal(msg1.Payload.Serialize(), msg.Payload.Serialize()) {
		t.Error("for Payload got", msg1.Payload.Serialize(), "expected",
			msg.Payload.Serialize())
	}
	if !pow.Check(raw[MessageHeaderSize():], constants.POWDefaultExtraBytes,
		constants.POWDefaultNonceTrialsPerByte) {
		t.Error("nonce check failed")
	}
	if tag := ownId2.Address.Tag(); !bytes.Equal(tag[:],
		msg1.Payload.(*objects.GetpubkeyV4).Tag[:]) {
		t.Error("tags didn't match")
	}
}

func TestGetpubkeyV3Object(t *testing.T) {
	msg := ObjectMessage{
		TTL:        time.Hour,
		ObjectType: GetpubkeyObject,
		Version:    3,
		Stream:     1,
		Payload: &objects.GetpubkeyV3{
			Ripe: ownId2.Address.Ripe,
		},
	}
	err := msg.Preserialize(nil, nil)
	if err != nil {
		t.Fatal("preserialize error:", err.Error())
	}

	raw := msg.Serialize()

	msg1 := new(ObjectMessage)
	DeserializeTo(msg1, raw[MessageHeaderSize():])

	if msg1.ObjectType != GetpubkeyObject {
		t.Error("for ObjectType got", msg1.ObjectType, "expected GetpubkeyObject")
	}
	if _, ok := msg1.Payload.(*objects.GetpubkeyV3); !ok {
		t.Error("for Payload, did not get GetpubkeyV3 object type")
	}
	if !bytes.Equal(msg1.Payload.Serialize(), msg.Payload.Serialize()) {
		t.Error("for Payload got", msg1.Payload.Serialize(), "expected",
			msg.Payload.Serialize())
	}
	if !pow.Check(raw[MessageHeaderSize():], constants.POWDefaultExtraBytes,
		constants.POWDefaultNonceTrialsPerByte) {
		t.Error("nonce check failed")
	}
	if !bytes.Equal(ownId2.Address.Ripe[:],
		msg1.Payload.(*objects.GetpubkeyV3).Ripe[:]) {
		t.Error("ripe didn't match")
	}
}

func TestPubkeyV2Object(t *testing.T) {
	msg := ObjectMessage{
		TTL:        time.Hour,
		ObjectType: PubkeyObject,
		Version:    2,
		Stream:     1,
		Payload: &objects.PubkeyV2{
			Behaviour: (0x01 << 31), // we need ack
		},
	}
	ownId1.CreateAddress(2, 1)
	err := msg.Preserialize(ownId1, nil) // set our keys
	if err != nil {
		t.Fatal("preserialize error:", err.Error())
	}

	raw := msg.Serialize()
	msg1 := new(ObjectMessage)
	DeserializeTo(msg1, raw[MessageHeaderSize():])

	if msg1.ObjectType != PubkeyObject {
		t.Error("for ObjectType got", msg1.ObjectType, "expected PubkeyObject")
	}
	if _, ok := msg1.Payload.(*objects.PubkeyV2); !ok {
		t.Error("for Payload, did not get GetpubkeyV2 object type")
	}
	if !bytes.Equal(msg1.Payload.Serialize(), msg.Payload.Serialize()) {
		t.Error("for Payload got", msg1.Payload.Serialize(), "expected",
			msg.Payload.Serialize())
	}
	if !pow.Check(raw[MessageHeaderSize():], constants.POWDefaultExtraBytes,
		constants.POWDefaultNonceTrialsPerByte) {
		t.Error("nonce check failed")
	}

	// generate foreign identity from public key and check if it's same
	genID, _ := msg1.GenerateForeignIdentity()

	ownAddr, _ := ownId1.Address.Encode()
	genAddr, _ := genID.Address.Encode()

	if ownAddr != genAddr {
		t.Error("for generated addresses expected", ownAddr, "got", genAddr)
	}
}

func TestPubkeyV3Object(t *testing.T) {
	msg := ObjectMessage{
		TTL:        time.Hour,
		ObjectType: PubkeyObject,
		Version:    3,
		Stream:     1,
		Payload: &objects.PubkeyV3{
			Behaviour: (0x01 << 31), // we need ack
		},
	}
	ownId1.CreateAddress(3, 1)
	err := msg.Preserialize(ownId1, nil) // set our keys
	if err != nil {
		t.Fatal("preserialize error:", err.Error())
	}

	p1 := msg.Payload.(*objects.PubkeyV3)

	// check if public encryption key was set
	if bytes.Equal(p1.PubEncryptionKey[:],
		bytes.Repeat([]byte{0x00}, 64)) {
		t.Error("public encryption key is empty")
	}
	// check if signing key was set
	if bytes.Equal(p1.PubSigningKey[:],
		bytes.Repeat([]byte{0x00}, 64)) {
		t.Error("public signing key is empty")
	}

	raw := msg.Serialize()
	msg1 := new(ObjectMessage)
	DeserializeTo(msg1, raw[MessageHeaderSize():])

	if msg1.ObjectType != PubkeyObject {
		t.Error("for ObjectType got", msg1.ObjectType, "expected PubkeyObject")
	}
	if _, ok := msg1.Payload.(*objects.PubkeyV3); !ok {
		t.Error("for Payload, did not get GetpubkeyV3 object type")
	}
	if !bytes.Equal(msg1.Payload.Serialize(), msg.Payload.Serialize()) {
		t.Error("for Payload got", msg1.Payload.Serialize(), "expected",
			msg.Payload.Serialize())
	}
	if !pow.Check(raw[MessageHeaderSize():], constants.POWDefaultExtraBytes,
		constants.POWDefaultNonceTrialsPerByte) {
		t.Error("nonce check failed")
	}

	payload := msg1.Payload.(*objects.PubkeyV3)

	// generate foreign identity from public key and check if it's same
	genID, _ := msg1.GenerateForeignIdentity()

	ownAddr, _ := ownId1.Address.Encode()
	genAddr, _ := genID.Address.Encode()

	if ownAddr != genAddr {
		t.Error("for generated addresses expected", ownAddr, "got", genAddr)
	}

	// check if the signature is valid
	sigMatch, err := genID.SigningKey.VerifySignature(payload.Signature,
		append(msg1.HeaderSerialize(), payload.SignatureSerialize()...))
	if err != nil {
		t.Error("signature verification failed:", err)
	}
	if !sigMatch {
		t.Error("invalid signature")
	}
}

func TestPubkeyV4Object(t *testing.T) {
	msg := ObjectMessage{
		TTL:        time.Hour,
		ObjectType: PubkeyObject,
		Version:    4,
		Stream:     1,
		Payload: &objects.PubkeyUnencryptedV4{
			objects.PubkeyV3{
				Behaviour: (0x01 << 31), // we need ack
			},
		},
	}

	if _, ok := msg.Payload.(EncryptablePayload); !ok {
		t.Fatal("payload not encrypted")
	}

	err := msg.Preserialize(ownId1, nil) // set our keys
	if err != nil {
		t.Fatal("preserialize error:", err.Error())
	}

	// check if Preserialize encrypted successfully
	if _, ok := msg.Payload.(*objects.PubkeyEncryptedV4); !ok {
		t.Error("for Payload, did not get PubkeyEncryptedV4 object type")
	}

	raw := msg.Serialize()
	msg1 := new(ObjectMessage)
	DeserializeTo(msg1, raw[MessageHeaderSize():])

	if msg1.ObjectType != PubkeyObject {
		t.Error("for ObjectType got", msg1.ObjectType, "expected PubkeyObject")
	}
	if _, ok := msg1.Payload.(*objects.PubkeyEncryptedV4); !ok {
		t.Error("for Payload, did not get PubkeyEncryptedV4 object type")
	}
	if !bytes.Equal(msg1.Payload.Serialize(), msg.Payload.Serialize()) {
		t.Error("for Payload got", msg1.Payload.Serialize(), "expected",
			msg.Payload.Serialize())
	}
	if !pow.Check(raw[MessageHeaderSize():], constants.POWDefaultExtraBytes,
		constants.POWDefaultNonceTrialsPerByte) {
		t.Error("nonce check failed")
	}
	// TODO try decrypting Pubkey and check if it corresponds to unencrypted
	// key

	// test if decryption fails with wrong address
	// test if decryption succeeds with right address

	// TODO check if the signature of unencrypted message is valid
	// TODO generate foreign identity from public key and check if it's same

}

func TestMsgObject(t *testing.T) {

}

func TestBroadcastObject(t *testing.T) {

}
