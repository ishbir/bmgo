package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/ishbir/elliptic"

	"github.com/ishbir/bmgo/bitmessage/constants"
	"github.com/ishbir/bmgo/bitmessage/identity"
	"github.com/ishbir/bmgo/bitmessage/pow"
	"github.com/ishbir/bmgo/bitmessage/protocol/helpers"
	"github.com/ishbir/bmgo/bitmessage/protocol/objects"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

func init() {
	// seed the random number generator
	rand.Seed(time.Now().UnixNano())
}

// Return the size of the message header
func MessageHeaderSize() int {
	return 24 // unsafe.Sizeof is not reliable, because of alignment, padding etc.
}

// Create a message in the format required by the protocol specification.
// https://bitmessage.org/wiki/Protocol_specification#Message_structure
func CreateMessage(command string, payload []byte) []byte {
	if len(command) > 12 {
		panic("programming error: length of command cannot be greater than 12")
	}
	var b bytes.Buffer
	// checksum is first 4 bytes of sha512 of payload
	var checksum [4]byte
	t := sha512.Sum512(payload)
	copy(checksum[:], t[:4])

	// convert to bytes an pad at same time
	var byteCommand [12]byte
	copy(byteCommand[:], command)

	// Write the header
	binary.Write(&b, binary.BigEndian,
		&messageHeader{constants.MessageMagic, byteCommand,
			uint32(len(payload)), checksum})

	// Write the payload
	b.Write(payload)

	return b.Bytes()
}

// Unpack the header of the received message.
func UnpackMessageHeader(raw []byte) (command string, payloadLength uint32,
	checksum [4]byte, err error) {
	b := bytes.NewReader(raw)
	var header messageHeader

	// Unpack struct
	err = binary.Read(b, binary.BigEndian, &header)
	if err != nil {
		err = errors.New("error unpacking the header: " + err.Error())
		return
	}

	if header.Magic != constants.MessageMagic {
		err = errors.New("invalid message magic: " + fmt.Sprint(header.Magic))
	}

	command = string(bytes.TrimRight(header.Command[:], "\x00")) // trim padding
	payloadLength = header.PayloadLength
	checksum = header.Checksum
	return
}

// Verify the checksum on the payload of a message to see if it has been
// correctly received.
func VerifyMessageChecksum(payload []byte, checksum [4]byte) bool {
	t := sha512.Sum512(payload)
	return bytes.Equal(checksum[:], t[:4]) // check for equality
}

func (addr *NetworkAddressShort) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, addr.Services)
	binary.Write(&b, binary.BigEndian, addr.IP.To16())
	binary.Write(&b, binary.BigEndian, addr.Port)

	return b.Bytes()
}

func (addr *NetworkAddressShort) DeserializeReader(b io.Reader) error {
	ip := make([]byte, net.IPv6len)

	err := binary.Read(b, binary.BigEndian, &addr.Services)
	if err != nil {
		return types.DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, ip)
	if err != nil {
		return types.DeserializeFailedError("IP address")
	}
	addr.IP = net.IP(ip)
	err = binary.Read(b, binary.BigEndian, &addr.Port)
	if err != nil {
		return types.DeserializeFailedError("port")
	}

	return nil
}

func (addr *NetworkAddress) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, addr.Time)
	binary.Write(&b, binary.BigEndian, addr.Stream)
	binary.Write(&b, binary.BigEndian, addr.Services)
	binary.Write(&b, binary.BigEndian, addr.IP.To16())
	binary.Write(&b, binary.BigEndian, addr.Port)

	return b.Bytes()
}

func (addr *NetworkAddress) DeserializeReader(b io.Reader) error {
	ip := make([]byte, net.IPv6len)

	err := binary.Read(b, binary.BigEndian, &addr.Time)
	if err != nil {
		return types.DeserializeFailedError("time")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Stream)
	if err != nil {
		return types.DeserializeFailedError("stream")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Services)
	if err != nil {
		return types.DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, ip)
	if err != nil {
		return types.DeserializeFailedError("IP address")
	}
	addr.IP = net.IP(ip)
	err = binary.Read(b, binary.BigEndian, &addr.Port)
	if err != nil {
		return types.DeserializeFailedError("port")
	}

	return nil
}

func (msg *VersionMessage) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, msg.Version)
	binary.Write(&b, binary.BigEndian, msg.Services)
	binary.Write(&b, binary.BigEndian, msg.Timestamp)
	b.Write(msg.AddrRecv.Serialize())
	b.Write(msg.AddrFrom.Serialize())
	binary.Write(&b, binary.BigEndian, msg.Nonce)
	b.Write(msg.UserAgent.Serialize())
	b.Write(msg.Streams.Serialize())

	return CreateMessage("version", b.Bytes())
}

func (msg *VersionMessage) DeserializeReader(b io.Reader) error {
	err := binary.Read(b, binary.BigEndian, &msg.Version)
	if err != nil {
		return types.DeserializeFailedError("version")
	}
	err = binary.Read(b, binary.BigEndian, &msg.Services)
	if err != nil {
		return types.DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, &msg.Timestamp)
	if err != nil {
		return types.DeserializeFailedError("timestamp")
	}
	err = msg.AddrRecv.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("addrrecv: " + err.Error())
	}
	err = msg.AddrFrom.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("addrfrom: " + err.Error())
	}
	err = binary.Read(b, binary.BigEndian, &msg.Nonce)
	if err != nil {
		return types.DeserializeFailedError("nonce")
	}
	err = msg.UserAgent.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("useragent: " + err.Error())
	}
	err = msg.Streams.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("streams: " + err.Error())
	}

	return nil
}

// Create a response to the version message (verack)
func CreateVerackMessage() []byte {
	return CreateMessage("verack", nil)
}

func (msg *AddrMessage) Serialize() []byte {
	var b bytes.Buffer
	b.Write(types.Varint(len(msg.Addresses)).Serialize()) // first item is count

	for _, addr := range msg.Addresses { // write them all!
		b.Write(addr.Serialize())
	}

	return CreateMessage("addr", b.Bytes())
}

func (msg *AddrMessage) DeserializeReader(b io.Reader) error {
	var count types.Varint

	err := count.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("number of addresses: " + err.Error())
	}

	msg.Addresses = make([]NetworkAddress, uint64(count)) // init output

	var i uint64
	for i = 0; i < uint64(count); i++ { // set them up
		err = msg.Addresses[i].DeserializeReader(b)
		if err != nil {
			return types.DeserializeFailedError("addr at pos " +
				fmt.Sprint(i) + ": " + err.Error())
		}
	}

	return nil
}

func serializeInvVector(items []InvVector) []byte {
	var b bytes.Buffer
	b.Write(types.Varint(len(items)).Serialize()) // first item is the count

	for _, item := range items { // write them all!
		b.Write(item[:])
	}
	return b.Bytes()
}

func deserializeInvVector(b io.Reader) ([]InvVector, error) {
	var count types.Varint

	err := count.DeserializeReader(b)
	if err != nil {
		return nil, types.DeserializeFailedError("number of inv items: " + err.Error())
	}

	items := make([]InvVector, uint64(count)) // init output

	var i uint64
	for i = 0; i < uint64(count); i++ { // set them up
		err = binary.Read(b, binary.BigEndian, &items[i])
		if err != nil {
			return nil, types.DeserializeFailedError("inv item at pos " +
				fmt.Sprint(i) + ": " + err.Error())
		}
	}

	return items, nil
}

func (msg *InvMessage) Serialize() []byte {
	return CreateMessage("inv", serializeInvVector(msg.Items))
}

func (msg *InvMessage) DeserializeReader(b io.Reader) error {
	var err error
	msg.Items, err = deserializeInvVector(b)
	return err
}

func (msg *GetdataMessage) Serialize() []byte {
	return CreateMessage("getdata", serializeInvVector(msg.Items))
}

func (msg *GetdataMessage) DeserializeReader(b io.Reader) error {
	var err error
	msg.Items, err = deserializeInvVector(b)
	return err
}

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
		privKey, err := elliptic.PrivateKeyFromRawBytes(elliptic.Secp256k1,
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

		privKey, err := elliptic.PrivateKeyFromRawBytes(elliptic.Secp256k1,
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

// CalculateInvVector returns an InvVector for the corresponding message.
func CalculateInvVector(message []byte) InvVector {
	hash := helpers.CalculateDoubleSHA512Hash(message)
	var invVector InvVector
	copy(invVector[:], hash[:32])
	return invVector
}
