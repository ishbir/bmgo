package objects

import "github.com/ishbir/bmgo/bitmessage/protocol/types"

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

// Used for person-to-person messages.
type MsgEncrypted struct {
	Data EncryptedPayload
}

// Version 2 and 3 messages
type MsgUnencrypted interface {
	// What version of the msg is it?
	Version() int
}

// Used for person-to-person messages when the sender's address version >= 3.
type MsgUnencryptedV3 struct {
	// Sender's address version number. This is needed in order to calculate the
	// sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	AddressVersion types.Varint
	// The sender's stream number
	StreamNumber types.Varint
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
	// Message Length
	MessageLength types.Varint
	// The message
	Message []byte
	// Length of the acknowledgement data
	AckLength types.Varint
	// The acknowledgement data to be transmitted. This takes the form of a
	// Bitmessage protocol message, like another msg message. The POW therein
	// must already be completed.
	AckData []byte
	// Length of the signature
	SigLength types.Varint
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	Signature []byte
}

// Used for person-to-person messages when the sender's address version <= 2.
type MsgUnencryptedV2 struct {
	// Sender's address version number. This is needed in order to calculate the
	// sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	AddressVersion types.Varint
	// The sender's stream number
	StreamNumber types.Varint
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
	MessageLength types.Varint
	// The message
	Message []byte
	// Length of the acknowledgement data
	AckLength types.Varint
	// The acknowledgement data to be transmitted. This takes the form of a
	// Bitmessage protocol message, like another msg message. The POW therein
	// must already be completed.
	AckData []byte
	// Length of the signature
	SigLength types.Varint
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	Signature []byte
}