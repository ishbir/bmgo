package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"time"

	"github.com/ishbir/elliptic"

	"github.com/ishbir/bmgo/bitmessage/constants"
	"github.com/ishbir/bmgo/bitmessage/identity"
	"github.com/ishbir/bmgo/bitmessage/pow"
	"github.com/ishbir/bmgo/bitmessage/protocol/objects"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// HeaderSerialize is responsible for serializing the object message header
// (excluding the nonce) for use in signing of the payload.
func (msg *ObjectMessage) HeaderSerialize() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, msg.expiresTime)
	binary.Write(&b, binary.BigEndian, uint32(msg.ObjectType))
	b.Write(msg.Version.Serialize())
	b.Write(msg.Stream.Serialize())
	return b.Bytes()
}

func (msg *ObjectMessage) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, msg.Nonce)
	b.Write(msg.HeaderSerialize())
	b.Write(msg.Payload.Serialize())

	return CreateMessage("object", b.Bytes())
}

func (msg *ObjectMessage) DeserializeReader(b io.Reader) error {
	err := binary.Read(b, binary.BigEndian, &msg.Nonce)
	if err != nil {
		return types.DeserializeFailedError("nonce: " + err.Error())
	}
	err = binary.Read(b, binary.BigEndian, &msg.expiresTime)
	if err != nil {
		return types.DeserializeFailedError("expiresTime: " + err.Error())
	}
	var objType uint32
	err = binary.Read(b, binary.BigEndian, &objType)
	if err != nil {
		return types.DeserializeFailedError("objectType: " + err.Error())
	}
	msg.ObjectType = ObjectType(objType)
	err = msg.Version.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("version: " + err.Error())
	}
	err = msg.Stream.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("stream: " + err.Error())
	}
	msg.setPayloadType() // set the Payload field
	err = msg.Payload.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("payload" + err.Error())
	}
	return nil
}

// random generates a random int between the given range
func random(min, max int) int {
	return rand.Intn(max-min) + min
}

// Preserialize is responsible for embedding the public signing and encryption
// keys, setting the POW parameters like nonce trials per byte and extra bytes,
// signing the unencrypted message, encrypting the object, setting the tags,
// calculating and setting the expiration time and then doing POW. The function
// is meant to be used only when the object is created from scratch, not when
// it is being propogated.
func (msg *ObjectMessage) Preserialize(id *identity.Own,
	target *identity.Foreign) error {
	// calculate TTL of the object message based on the defined constant values
	msg.TTL += time.Second * time.Duration(random(
		-int(time.Duration(constants.ObjectTTLRandRange).Seconds()),
		int(time.Duration(constants.ObjectTTLRandRange).Seconds())))
	ttl := int(msg.TTL.Seconds())
	// set the expiration time based on TTL
	msg.expiresTime = uint64(time.Now().Add(msg.TTL).Unix())

	// Setting signing and encryption public keys
	if keysetter, ok := msg.Payload.(PublicKeysAddablePayload); ok {
		keysetter.SetSigningAndEncryptionKeys(
			id.SigningKey.PublicKey.SerializeUncompressed()[1:], // exclude 0x04
			id.EncryptionKey.PublicKey.SerializeUncompressed()[1:],
		)
	}

	// Message signing
	if signer, ok := msg.Payload.(SignablePayload); ok {
		var b bytes.Buffer
		b.Write(msg.HeaderSerialize())
		b.Write(signer.SignatureSerialize())
		signature, err := id.SigningKey.Sign(b.Bytes())
		if err != nil {
			return errors.New("signing failed: " + err.Error())
		}
		signer.SetSignature(signature)
	}

	// tag, if it needs to be added
	var tag []byte

	switch msg.Payload.(type) {
	// set the encryption key and tag for v4 pubkeys and v5 broadcasts
	case *objects.PubkeyUnencryptedV4, *objects.BroadcastUnencryptedV5:
		hash := id.Address.CalcDoubleHash()
		privKey, err := elliptic.PrivateKeyFromRawBytes(constants.Curve,
			hash[:32])
		if err != nil {
			return errors.New("failed to create private key from address: " +
				err.Error())
		}
		target = new(identity.Foreign)
		target.EncryptionKey = &privKey.PublicKey
		tag = hash[32:] // set the tag

	// set encryption key for v4 broadcasts
	case *objects.BroadcastUnencryptedV4AddressV2,
		*objects.BroadcastUnencryptedV4AddressV3:
		sha := sha512.New()
		sha.Write(id.Address.Version.Serialize())
		sha.Write(id.Address.Stream.Serialize())
		sha.Write(id.Address.Ripe[:])
		hash := sha.Sum(nil)

		privKey, err := elliptic.PrivateKeyFromRawBytes(constants.Curve,
			hash[:32])
		if err != nil {
			return errors.New("failed to create private key from address: " +
				err.Error())
		}
		target = new(identity.Foreign)
		target.EncryptionKey = &privKey.PublicKey

	// set network default POW parameters for objects that are meant to not be
	// destination client specific
	case *objects.PubkeyV2, *objects.PubkeyV3,
		*objects.GetpubkeyV3, *objects.GetpubkeyV4:
		target = new(identity.Foreign)

	}
	// Enforce minimum POW requirements. This also sets POW parameters for
	// foreign identities generated previously.
	if target.NonceTrialsPerByte < constants.POWDefaultNonceTrialsPerByte {
		target.NonceTrialsPerByte = constants.POWDefaultNonceTrialsPerByte
	}
	if target.ExtraBytes < constants.POWDefaultNonceTrialsPerByte {
		target.ExtraBytes = constants.POWDefaultNonceTrialsPerByte
	}

	// encrypt the payload if it needs to be encrypted
	if unenc, ok := msg.Payload.(EncryptablePayload); ok {
		enc, err := unenc.Encrypt(target.EncryptionKey)
		if err != nil {
			return errors.New("payload encryption failed: " + err.Error())
		}
		msg.Payload = enc // set payload to encrypted object
	}

	// add a tag to the payload if it needs to be added
	if taggable, ok := msg.Payload.(TaggableEncryptedPayload); ok {
		taggable.SetTag(tag)
	}
	// Our payload is ready. Do POW.
	payload := msg.Payload.Serialize()
	objHeader := msg.HeaderSerialize()
	payloadLength := len(payload) + len(objHeader) + 8 // nonce length also

	powTarget := pow.CalculateTarget(payloadLength, ttl,
		int(target.NonceTrialsPerByte), int(target.ExtraBytes))

	hash := sha512.New()
	hash.Write(msg.HeaderSerialize())
	hash.Write(payload)
	// TODO add logic for choosing which POW implementation to use
	msg.Nonce = pow.DoSequential(powTarget, hash.Sum(nil))
	return nil
}

// setPayloadType sets the Payload field of the ObjectMessage struct according
// to the value of Version and ObjectType.
func (msg *ObjectMessage) setPayloadType() {
	// default value
	msg.Payload = &objects.Unrecognized{}
	// used when the msg version is unknown
	corrupt := &objects.Corrupt{}

	switch msg.ObjectType {
	case GetpubkeyObject:
		switch msg.Version {
		case 2:
			fallthrough
		case 3:
			msg.Payload = &objects.GetpubkeyV3{}
		case 4:
			msg.Payload = &objects.GetpubkeyV4{}
		default:
			msg.Payload = corrupt
		}

	case PubkeyObject:
		switch msg.Version {
		case 2:
			msg.Payload = &objects.PubkeyV2{}
		case 3:
			msg.Payload = &objects.PubkeyV3{}
		case 4:
			msg.Payload = &objects.PubkeyEncryptedV4{}
		default:
			msg.Payload = corrupt
		}

	case MsgObject:
		if int(msg.Version) == 1 { // this has been fixed at 1
			msg.Payload = &objects.MsgEncrypted{}
		} else {
			msg.Payload = corrupt
		}

	case BroadcastObject:
		switch msg.Version {
		case 4:
			msg.Payload = &objects.BroadcastEncryptedV4{}
		case 5:
			msg.Payload = &objects.BroadcastEncryptedV5{}
		default:
			msg.Payload = corrupt
		}
	}
}

var InvalidPayloadOperationError = errors.New("intended operation not defined" +
	" for this payload")

// GenerateForeignIdentity generates an identity.Foreign object based on the
// type of public key that we have (if it is a public key).
func (msg *ObjectMessage) GenerateForeignIdentity() (*identity.Foreign, error) {
	id := new(identity.Foreign)

	switch payload := msg.Payload.(type) {
	case *objects.PubkeyV2:
		// errors here can be safely ignored (refer to elliptic.go for reason)
		id.EncryptionKey, _ = elliptic.PublicKeyFromUncompressedBytes(
			constants.Curve, append([]byte{0x04}, payload.PubEncryptionKey[:]...))
		id.SigningKey, _ = elliptic.PublicKeyFromUncompressedBytes(
			constants.Curve, append([]byte{0x04}, payload.PubSigningKey[:]...))
		id.CreateAddress(2, msg.Stream)
		id.SetDefaultPOWParams()
		return id, nil

	case *objects.PubkeyV3:
		// errors here can be safely ignored
		id.EncryptionKey, _ = elliptic.PublicKeyFromUncompressedBytes(
			constants.Curve, append([]byte{0x04}, payload.PubEncryptionKey[:]...))
		id.SigningKey, _ = elliptic.PublicKeyFromUncompressedBytes(
			constants.Curve, append([]byte{0x04}, payload.PubSigningKey[:]...))
		id.CreateAddress(3, msg.Stream)
		id.NonceTrialsPerByte = payload.NonceTrialsPerByte
		id.ExtraBytes = payload.ExtraBytes
		return id, nil

	case *objects.PubkeyUnencryptedV4:
		// errors here can be safely ignored
		id.EncryptionKey, _ = elliptic.PublicKeyFromUncompressedBytes(
			constants.Curve, append([]byte{0x04}, payload.PubEncryptionKey[:]...))
		id.SigningKey, _ = elliptic.PublicKeyFromUncompressedBytes(
			constants.Curve, append([]byte{0x04}, payload.PubSigningKey[:]...))
		id.CreateAddress(4, msg.Stream)
		id.NonceTrialsPerByte = payload.NonceTrialsPerByte
		id.ExtraBytes = payload.ExtraBytes
		return id, nil
	}

	return nil, InvalidPayloadOperationError
}

// TryDecrypt tries to decrypt the payload, which could be a message, broadcast,
// or v4 pubkey, and returns whether it was successful or not, along with any
// error. It changes the payload to its unencrypted form in the process. Error
// is only returned if decryption didn't fail due to invalid key.
func (msg *ObjectMessage) TryDecrypt(ownId *identity.Own,
	address *identity.Address) (bool, error) {
	encPayload, ok := msg.Payload.(DecryptablePayload)
	if !ok { // make sure that payload is decryptable
		return false, InvalidPayloadOperationError
	}
	var privKey *elliptic.PrivateKey
	var err error
	// generate decryption key if payload is pubkey (first 32 bytes of double
	// hash of address)
	if _, ok := msg.Payload.(*objects.PubkeyEncryptedV4); ok {
		if address == nil {
			// can't happen unless there's a bug
			return false, errors.New("address not specified")
		}

		hash := address.CalcDoubleHash()
		privKey, err = elliptic.PrivateKeyFromRawBytes(constants.Curve,
			hash[:32])
		if err != nil {
			return false, errors.New("failed to create private key from address: " +
				err.Error())
		}
	} else if ownId == nil {
		// can't happen unless there's a bug
		return false, errors.New("own ID not specified")
	} else { // we can safely set encryption key
		privKey = ownId.EncryptionKey
	}

	dencPayload, err := encPayload.Decrypt(privKey)

	// invalid private key/corrupted data
	if err == elliptic.InvalidMACError {
		return false, nil
	} else if err != nil {
		return false, err
	}
	msg.Payload = dencPayload
	return true, nil
}
