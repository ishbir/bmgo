// Constants package contains constants vital to the Bitmessage protocol and its
// functioning.
package constants

import "time"

const (
	// The first 4 byte value of every message exchanged wiht a Bitmessage node.
	MessageMagic uint32 = 0xE9BEB4D9
	// POW Constants:
	//
	// If changed, these values will cause particularly unexpected behavior: You
	// won't be able to either send or receive messages because the proof of
	// work you do (or demand) won't match that done or demanded by others.
	// Don't change them!
	//
	// The amount of work that should be performed (and demanded) per byte of
	// the payload.
	POWDefaultNonceTrialsPerByte = 1000
	// To make sending short messages a little more difficult, this value is
	// added to the payload length for use in calculating the proof of work
	// target.
	POWDefaultExtraBytes = 1000
	// ObjectTTLBase contains the amount of time that an object should roughly
	// be valid for.
	ObjectTTLBase = 24 * time.Hour * 28
	// ObjectTTLRandRange contains the amount of time that should be randomly
	// added to or subtracted from TTLBase to get the exact duration that the
	// object is valid for.
	ObjectTTLRandRange = 5 * time.Minute
)
