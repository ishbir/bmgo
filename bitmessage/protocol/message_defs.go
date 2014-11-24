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
	UserAgent Varstring
	Streams   VarintList
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
// must be done.
type ObjectMessage struct {
	Nonce       uint64
	ExpiresTime uint64
	ObjectType  uint32
	Version     Varint
	Stream      Varint
	Payload     []byte
}

// Used for data that has been encrypted.
type EncryptedPayload struct {
	// Initialization Vector used for AES-256-CBC
	IV [16]byte
	// Elliptic Curve type 0x02CA (714)
	CurveType uint16
	// Length of X component of public key R
	XLength uint16
	// X component of public key R
	X []byte
	// Length of X component of public key R
	YLength uint16
	// Y component of public key R
	Y []byte
	// Cipher text
	Data []byte
	// HMACSHA256 Message Authentication Code
	MAC [32]byte
}

// When a node has the hash of a public key (from a version <= 3 address) but
// not the public key itself, it must send out a request for the public key.
type GetpubkeyV3Object struct {
	// The ripemd hash of the public key. This field is only included when the
	// address version is <= 3.
	Ripe [20]byte
}

// When a node has the hash of a public key (from a version >= 4 address) but
// not the public key itself, it must send out a request for the public key.
type GetpubkeyV4Object struct {
	// The tag derived from the address version, stream number, and ripe. This
	// field is only included when the address version is >= 4.
	Tag [32]byte
}

// Version 2, 3 and 4 public keys
type PubkeyObject struct {
}

// Define how the message is to be encoded.
type EncodingType Varint

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
type MsgEncryptedObject struct {
	Data EncryptedPayload
}

// Used for person-to-person messages when the sender's address version >= 3.
type MsgUnencryptedV3Object struct {
	// Sender's address version number. This is needed in order to calculate the
	// sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	AddressVersion Varint
	// The sender's stream number
	StreamNumber Varint
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
	NonceTrialsPerByte Varint
	// Used to calculate the difficulty target of messages accepted by this
	// node. The higher this value, the more difficult the Proof of Work must be
	// before this individual will accept the message. This number is added to
	// the data length to make sending small messages more difficult. 1000 is
	// the network minimum so any lower values will be automatically raised to
	// 1000. This field is new and is only included when the AddressVersion >= 3.
	ExtraBytes Varint
	// The ripe hash of the public key of the receiver of the message.
	DestinationRipe [20]byte
	// Message Encoding type
	Encoding EncodingType
	// Message Length
	MessageLength Varint
	// The message
	Message []byte
	// Length of the acknowledgement data
	AckLength Varint
	// The acknowledgement data to be transmitted. This takes the form of a
	// Bitmessage protocol message, like another msg message. The POW therein
	// must already be completed.
	AckData []byte
	// Length of the signature
	SigLength Varint
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	Signature []byte
}

// Used for person-to-person messages when the sender's address version <= 2.
type MsgUnencryptedV2Object struct {
	// Sender's address version number. This is needed in order to calculate the
	// sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	AddressVersion Varint
	// The sender's stream number
	StreamNumber Varint
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
	// Message Length
	MessageLength Varint
	// The message
	Message []byte
	// Length of the acknowledgement data
	AckLength Varint
	// The acknowledgement data to be transmitted. This takes the form of a
	// Bitmessage protocol message, like another msg message. The POW therein
	// must already be completed.
	AckData []byte
	// Length of the signature
	SigLength Varint
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	Signature []byte
}

// Having a broadcast version of 5 indicates that a tag is used which, in turn,
// is used when the sender's address version is >=4.
type BroadcastEncryptedV5Object struct {
	// The tag. This field is new and only included when the broadcast version
	// is >= 5.
	Tag [32]byte
	// Encrypted broadcast data.
	Data EncryptedPayload
}

// Broadcast originating from an address version <= 3.
type BroadcastEncryptedV4Object struct {
	// Encrypted broadcast data.
	Data EncryptedPayload
}

// Broadcast version == 4 and address version == 3.
type BroadcastUnencryptedV4AddressV3Object struct {
	Message MsgUnencryptedV3Object
}

// Broadcast version == 4 and address version == 2.
type BroadcastUnencryptedV4AddressV2Object struct {
	Message MsgUnencryptedV2Object
}

// Broadcast version == 5 and address version == 4.
type BroadcastUnencryptedV5Object struct {
	Message MsgUnencryptedV3Object
}
