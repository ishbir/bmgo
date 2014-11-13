package protocol

import "net"

// Included in every message
const MessageMagic uint32 = 0xE9BEB4D9

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
	networkAddressShort
}

// Network address structure used for version message
type networkAddressShort struct {
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
	AddrRecv  networkAddressShort
	AddrFrom  networkAddressShort
	Nonce     uint64 // Random nonce
}
