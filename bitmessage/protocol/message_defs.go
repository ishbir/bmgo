package protocol

import "net"

// Interface defined for each and every message, making serializing/deserializing easier
type MessageInterface interface {
	// Serialize the message into a proper packet, ready for sending on network.
	Serialize() []byte
	// Deserialize the payload part of the message into the struct.
	Deserialize([]byte) error
}

// Included in every message
const MessageMagic uint32 = 0xE9BEB4D9

// The main packet/data structure used for P2P communication
type messageHeader struct {
	Magic         uint32   // 0xE9BEB4D9
	Command       [12]byte // string
	PayloadLength uint32
	Checksum      [4]byte
}

// Network address structure used for addr
type NetworkAddress struct {
	Time   uint64 // 8 byte UNIX time
	Stream uint32
	NetworkAddressShort
}

// Network address structure used for version message
type NetworkAddressShort struct {
	Services uint64
	IP       net.IP
	Port     uint16
}

type VersionMessage struct {
	versionMessageFixed
	UserAgent string
	Streams   []uint64
}

type versionMessageFixed struct {
	Version   uint32
	Services  uint64
	Timestamp int64 // UNIX time
	AddrRecv  NetworkAddressShort
	AddrFrom  NetworkAddressShort
	Nonce     uint64 // Random nonce
}

type AddrMessage struct {
	Addresses []NetworkAddress
}
