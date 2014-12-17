// pow package is responsible for proof of work calculation/verification for an
// object transmitted over the network.
package pow

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"time"

	"github.com/ishbir/bmgo/bitmessage/protocol"
)

// CalculateTarget calculates the target POW value.
// https://bitmessage.org/wiki/Proof_of_work
func CalculateTarget(PayloadLength, PayloadLengthExtraBytes, TTL,
	NonceTrialsPerByte int) int64 {
	payloadLength := float64(PayloadLength)
	payloadLengthExtraBytes := float64(PayloadLengthExtraBytes)
	ttl := float64(TTL)
	nonceTrialsPerByte := float64(NonceTrialsPerByte)

	return int64(float64(2^64) / (nonceTrialsPerByte * (payloadLength +
		payloadLengthExtraBytes + ((ttl * (payloadLength + payloadLengthExtraBytes)) /
		float64(2^16)))))
}

// Check if the POW is sufficient for an object.
func CheckPOW(objMessage *protocol.ObjectMessage, PayloadLengthExtraBytes,
	NonceTrialsPerByte int) bool {
	ttl := int(objMessage.ExpiresTime - uint64(time.Now().Unix()))
	data := objMessage.Serialize()
	dataToCheck := data[8:] // exclude the nonce value in the beginning
	payloadLength := len(dataToCheck)

	hash := sha512.New()
	hash.Write(dataToCheck)
	initialHash := hash.Sum(nil)

	hash.Reset()
	hash.Write(data[0:8]) // nonce
	hash.Write(initialHash)
	tempHash := hash.Sum(nil)
	hash.Reset()
	hash.Write(tempHash)
	resultHash := hash.Sum(nil)

	b := bytes.NewReader(resultHash[0:8])
	var powValue int64
	binary.Read(b, binary.BigEndian, &powValue)

	target := CalculateTarget(payloadLength, PayloadLengthExtraBytes, ttl,
		NonceTrialsPerByte)

	if powValue <= target {
		return true
	} else {
		return false
	}
}

// Do the POW using multiple go-routines
func Do() {

}
