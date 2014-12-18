package protocol

import (
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
	"net"
)

// Included in every message
const MessageMagic uint32 = 0xE9BEB4D9

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

// An object is a message which is shared throughout a stream. It is the only
// message which propagates; all others are only between two nodes. Objects have
// a type, like 'msg', or 'broadcast'. To be a valid object, the Proof Of Work
// must be done (which is stored in Nonce).
type ObjectMessage struct {
	Nonce       uint64
	ExpiresTime uint64
	ObjectType  uint32
	Version     types.Varint
	Stream      types.Varint
	Payload     Serializer
}

// Represents the payload of an ObjectMessage. Contains the fields of different
// objects.
type Object interface {
	Serializer
	// Useful for adding signatures, calculating POW etc. before the object is
	// serialized.
	preserialize(*ObjectMessage)
}
