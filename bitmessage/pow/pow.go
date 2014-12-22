// pow package is responsible for proof of work calculation/verification for an
// object transmitted over the network.
package pow

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"math"
	"time"
)

// CalculateTarget calculates the target POW value.
// https://bitmessage.org/wiki/Proof_of_work
func CalculateTarget(PayloadLength, TTL, NonceTrialsPerByte,
	PayloadLengthExtraBytes int) uint64 {
	payloadLength := float64(PayloadLength)
	payloadLengthExtraBytes := float64(PayloadLengthExtraBytes)
	ttl := float64(TTL)
	nonceTrialsPerByte := float64(NonceTrialsPerByte)

	return uint64(float64(2^64) / (nonceTrialsPerByte * (payloadLength +
		payloadLengthExtraBytes + ((ttl * (payloadLength + payloadLengthExtraBytes)) /
		float64(2^16)))))
}

// Check checks if the POW that was done for an object is sufficient.
func Check(objectData []byte, PayloadLengthExtraBytes, NonceTrialsPerByte int) bool {
	// calculate ttl from bytes 8-16 that contain ExpiresTime
	ttl := int(binary.BigEndian.Uint64(objectData[8:16]) -
		uint64(time.Now().Unix()))
	dataToCheck := objectData[8:] // exclude the nonce value in the beginning
	payloadLength := len(dataToCheck)

	hash := sha512.New()
	hash.Write(dataToCheck)
	initialHash := hash.Sum(nil)

	hash.Reset()
	hash.Write(objectData[:8]) // nonce
	hash.Write(initialHash)
	tempHash := hash.Sum(nil)
	hash.Reset()
	hash.Write(tempHash)
	resultHash := hash.Sum(nil)

	b := bytes.NewReader(resultHash[0:8])
	var powValue uint64
	binary.Read(b, binary.BigEndian, &powValue)

	target := CalculateTarget(payloadLength, PayloadLengthExtraBytes, ttl,
		NonceTrialsPerByte)

	if powValue <= target {
		return true
	} else {
		return false
	}
}

// DoSequential does the POW sequentially and returns the nonce value.
func DoSequential(target uint64, initialHash []byte) uint64 {
	var nonce uint64 = 0
	nonceBytes := make([]byte, 8)
	var trialValue uint64 = math.MaxUint64
	sha1 := sha512.New() // inner
	sha2 := sha512.New() // outer
	for trialValue > target {
		nonce += 1
		binary.BigEndian.PutUint64(nonceBytes, nonce)
		sha1.Write(nonceBytes)
		sha1.Write(initialHash)
		sha2.Write(sha1.Sum(nil))
		finalSum := sha2.Sum(nil)
		trialValue = binary.BigEndian.Uint64(finalSum[:8])
		sha1.Reset()
		sha2.Reset()
	}
	return nonce
}

// DoParallel does the POW using CPU_COUNT number of goroutines and returns the
// nonce value.
func DoParallel(target uint64, initialHash []byte) uint64 {
	panic("not implemented")
	return 0
}

// DoGPU does the POW on an OpenCL supported device and returns the nonce value.
func DoOpenCL(target uint64, initialHash []byte) uint64 {
	panic("not implemented")
	return 0
}
