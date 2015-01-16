// pow package is responsible for proof of work calculation/verification for an
// object transmitted over the network.
package pow

import (
	"crypto/sha512"
	"encoding/binary"
	"math"
	"time"
)

// CalculateTarget calculates the target POW value. PayloadLength includes the
// full length of the payload (inluding the width of the initial nonce field).
// TTL is the time to live (in seconds). Information about NonceTrialsPerByte
// and PayloadLengthExtraBytes can be found at:
// https://bitmessage.org/wiki/Proof_of_work
func CalculateTarget(PayloadLength, TTL, NonceTrialsPerByte,
	PayloadLengthExtraBytes int) uint64 {
	// All these type conversions are needed for interoperability with Python
	// which casts types back to int after performing division. Clearly
	// something that Atheros did not think about.
	return math.MaxUint64 / uint64(
		uint64(NonceTrialsPerByte)*(uint64(PayloadLength)+uint64(PayloadLengthExtraBytes)+
			uint64(
				float64(TTL)*(float64(PayloadLength)+float64(PayloadLengthExtraBytes))/
					math.Pow(2, 16))))
}

// Check checks if the POW that was done for an object is sufficient.
func Check(objectData []byte, PayloadLengthExtraBytes, NonceTrialsPerByte int) bool {
	// calculate ttl from bytes 8-16 that contain ExpiresTime
	ttl := int(binary.BigEndian.Uint64(objectData[8:16]) -
		uint64(time.Now().Unix()))
	dataToCheck := objectData[8:] // exclude the nonce value in the beginning
	payloadLength := len(objectData)

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

	powValue := binary.BigEndian.Uint64(resultHash[0:8])

	target := CalculateTarget(payloadLength, ttl, PayloadLengthExtraBytes,
		NonceTrialsPerByte)

	return powValue <= target
}

// Do is the signature of a POW implementation that returns a nonce value.
type Do func(target uint64, initialHash []byte) uint64

// DoSequential does the POW sequentially and returns the nonce value.
func DoSequential(target uint64, initialHash []byte) uint64 {
	var nonce uint64 = 0
	nonceBytes := make([]byte, 8)
	var trialValue uint64 = math.MaxUint64
	sha1 := sha512.New() // inner
	sha2 := sha512.New() // outer
	var finalSum []byte
	for trialValue > target {
		nonce += 1
		binary.BigEndian.PutUint64(nonceBytes, nonce)
		sha1.Write(nonceBytes)
		sha1.Write(initialHash)
		sha2.Write(sha1.Sum(nil))
		finalSum = sha2.Sum(nil)
		trialValue = binary.BigEndian.Uint64(finalSum[:8])
		sha1.Reset()
		sha2.Reset()
	}
	return nonce
}

// DoParallel does the POW using cpuCount number of goroutines and returns the
// nonce value. TODO: Optimize parallel and make it stable. Performance is very
// volatile at the moment.
func DoParallel(target uint64, initialHash []byte, parallelCount int) uint64 {
	done := make(chan bool)
	nonceValue := make(chan uint64, 1)

	for i := 0; i < parallelCount; i++ {
		go func() {
			var nonce uint64 = uint64(i)
			nonceBytes := make([]byte, 8)
			var trialValue uint64 = math.MaxUint64
			sha1 := sha512.New() // inner
			sha2 := sha512.New() // outer
			for trialValue > target {
				select {
				case <-done: // some other goroutine already finished
					return
				default:
					nonce += uint64(parallelCount) // increment by parallelCount
					binary.BigEndian.PutUint64(nonceBytes, nonce)
					sha1.Write(nonceBytes)
					sha1.Write(initialHash)
					sha2.Write(sha1.Sum(nil))
					finalSum := sha2.Sum(nil)
					trialValue = binary.BigEndian.Uint64(finalSum[:8])
					sha1.Reset()
					sha2.Reset()
				}
			}
			nonceValue <- nonce
			for j := 0; j < parallelCount; j++ {
				done <- true
			}
		}()
	}
	return <-nonceValue
}

// DoGPU does the POW on an OpenCL supported device and returns the nonce value.
func DoOpenCL(target uint64, initialHash []byte) uint64 {
	panic("not implemented")
	return 0
}
