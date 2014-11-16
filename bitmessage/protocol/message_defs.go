package protocol

import "net"

// Included in every message
const MessageMagic uint32 = 0xE9BEB4D9

// The main packet/data structure used for P2P communication
type messageHeader struct {
	Magic         uint32   // 0xE9BEB4D9
	Command       [12]byte // string
	PayloadLength uint32
	Checksum      [4]byte
}

// Network address structure used for VersionMessage.
type NetworkAddressShort struct {
	Services uint64
	IP       net.IP
	Port     uint16
}

// Network address structure used for AddrMessage.
type NetworkAddress struct {
	Time     int64 // 8 byte UNIX time
	Stream   uint32
	Services uint64
	IP       net.IP
	Port     uint16
}

// Message sent by clients on connecting to each other.
type VersionMessage struct {
	Version   uint32
	Services  int64
	Timestamp int64 // UNIX time
	AddrRecv  NetworkAddressShort
	AddrFrom  NetworkAddressShort
	Nonce     uint64 // Random nonce
	UserAgent Varstring
	Streams   VarintList
}

// Message containing the list of known nodes.
type AddrMessage struct {
	Addresses []NetworkAddress
}
