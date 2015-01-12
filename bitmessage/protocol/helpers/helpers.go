package helpers

import "crypto/sha512"

// CalculateDoubleSHA512Hash returns the SHA512 hash of the SHA512 hash of the
// input data.
func CalculateDoubleSHA512Hash(in []byte) []byte {
	sha := sha512.New()
	sha.Write(in)
	temp := sha.Sum(nil)
	sha.Reset()
	sha.Write(temp)
	return sha.Sum(nil)
}
