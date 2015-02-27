package protocol

import (
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
	"github.com/ishbir/elliptic"
	"net"
	"time"
)

// The main packet/data structure used for P2P communication
type messageHeader struct {
	Magic         uint32   // 0xE9BEB4D9
	Command       [12]byte // string
	PayloadLength uint32
	Checksum      [4]byte
}

// When a network address is needed somewhere, this structure is used.
type NetworkAddress struct {
	Time     int64 // 8 byte UNIX time
	Stream   uint32
	Services uint64
	IP       net.IP
	Port     uint16
}

// Network address structure used for VersionMessage. Addresses are not prefixed
// with a timestamp or stream in the version message.
type NetworkAddressShort struct {
	Services uint64
	IP       net.IP
	Port     uint16
}

// When a node creates an outgoing connection, it will immediately advertise its
// version. The remote node will respond with its version. No futher
// communication is possible until both peers have exchanged their version.
type VersionMessage struct {
	Version   uint32
	Services  int64
	Timestamp int64 // UNIX time
	AddrRecv  NetworkAddressShort
	AddrFrom  NetworkAddressShort
	Nonce     uint64 // Random nonce
	UserAgent types.Varstring
	Streams   types.VarintList
}

// Provide information on known nodes of the network. Non-advertised nodes
// should be forgotten after typically 3 hours. (max 1000 items)
type AddrMessage struct {
	Addresses []NetworkAddress
}

// Inventory vectors are used for notifying other nodes about objects they have
// or data which is being requested. Two rounds of SHA-512 are used, resulting
// in a 64 byte hash. Only the first 32 bytes are used; the later 32 bytes are
// ignored.
type InvVector [32]byte

// Allows a node to advertise its knowledge of one or more objects.
// (maximum 50000 items)
type InvMessage struct {
	Items []InvVector
}

// getdata is used in response to an inv message to retrieve the content of a
// specific object after filtering known elements. (maximum 50000 items)
type GetdataMessage struct {
	Items []InvVector
}

// ObjectType tells the type of payload that the object message contains.
type ObjectType uint32

const (
	GetpubkeyObject = ObjectType(iota)
	PubkeyObject
	MsgObject
	BroadcastObject
)

// An object is a message which is shared throughout a stream. It is the only
// message which propagates; all others are only between two nodes. Objects have
// a type, like 'msg', or 'broadcast'. To be a valid object, the Proof Of Work
// must be done (which is stored in Nonce).
type ObjectMessage struct {
	Nonce uint64
	// TTL tells how long the object message should be valid from the time of
	// PoW. It is not serialized but is used, along with a random interval of
	// time defined in constants (ObjectTTLRandRange), to calculate expiresTime.
	// Has to be greater than the duration specified in ObjectTTLRandRange or
	// the result might turn out to be negative.
	TTL         time.Duration
	expiresTime uint64 // not meant to be assigned, calculated in Preserialize
	ObjectType  ObjectType
	Version     types.Varint
	Stream      types.Varint
	Payload     types.Serializer
}

// SignablePayload represents payload which can have a signature added to it.
type SignablePayload interface {
	// SignatureSerialize gets the part of the payload that has to be appended
	// to object message header for signing.
	SignatureSerialize() []byte
	// SetSignature sets the value of the Signature field of the payload.
	SetSignature([]byte)
}

// PublicKeysAddablePayload represents payload that requires addition of signing
// and encryption public keys to it.
type PublicKeysAddablePayload interface {
	// SetSigningAndEncryptionKeys sets the PubSigningKey and PubEncryptionKey
	// fields of the payload.
	SetSigningAndEncryptionKeys([]byte, []byte)
}

// EncryptablePayload represents payloads that need to be encrypted before being
// sent on the network.
type EncryptablePayload interface {
	// Encrypt makes the payload encrypt itself for the target public key and
	// return a transformed payload (the encrypted form of itself).
	Encrypt(*elliptic.PublicKey) (types.Serializer, error)
}

// DecryptablePayload represents payloads that was originally in the encrypted
// form while being transfered on network.
type DecryptablePayload interface {
	// Decrypt reverses the operation performed by Encrypt and transforms the
	// payload back to its unencrypted form.
	Decrypt(*elliptic.PrivateKey) (types.Serializer, error)
}

// TaggableEncryptedPayload represents encrypted payloads that have a tag.
type TaggableEncryptedPayload interface {
	// SetTag is used to set the tag of the encrypted payload.
	SetTag([]byte)
}
